use std::{collections::BTreeMap, ops::ControlFlow};

use boa_ast::{
    function::{
        AsyncArrowFunction, AsyncFunctionDeclaration, AsyncFunctionExpression,
        AsyncGeneratorDeclaration, AsyncGeneratorExpression,
    },
    scope::Scope,
    visitor::{VisitWith, Visitor},
};
use boa_engine::{Context, Source, object::builtins::JsPromise};
use boa_interner::Interner;
use boa_parser::Parser;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    Error, Result,
    bru::{Block, Document},
    engine::{Assertion, Response},
    variables::Variables,
};

const MAX_SCRIPT_BYTES: usize = 64 * 1024;

pub(crate) struct ScriptResult {
    pub variables: Variables,
    pub assertions: Vec<Assertion>,
    pub request: Document,
}

pub(crate) fn validate(document: &Document) -> Result<()> {
    for block in &document.blocks {
        if !matches!(
            block.name.as_str(),
            "script:pre-request" | "script:post-response" | "tests"
        ) {
            continue;
        }
        if block.content.len() > MAX_SCRIPT_BYTES {
            return Err(Error::invalid("script exceeds the 64 KiB limit"));
        }
        let mut interner = Interner::default();
        let syntax = Parser::new(Source::from_bytes(&block.content))
            .parse_script(&Scope::new_global(), &mut interner)
            .map_err(script_error)?;
        if syntax.visit_with(&mut SynchronousOnly).is_break() {
            return Err(Error::Unsupported {
                feature: "asynchronous JavaScript functions".into(),
            });
        }
    }
    Ok(())
}

pub(crate) fn run(
    documents: &[&Document],
    stages: &[&str],
    request: &Document,
    method_block: &str,
    variables: &Variables,
    response: Option<&Response>,
) -> Result<ScriptResult> {
    let scripts: Vec<_> = stages
        .iter()
        .flat_map(|stage| documents.iter().filter_map(move |doc| doc.block(stage)))
        .filter(|block| !block.content.trim().is_empty())
        .collect();
    if scripts
        .iter()
        .any(|block| block.content.len() > MAX_SCRIPT_BYTES)
    {
        return Err(Error::invalid("script exceeds the 64 KiB limit"));
    }
    let mut result = ScriptResult {
        variables: Variables::new(),
        assertions: Vec::new(),
        request: request.clone(),
    };
    if scripts.is_empty() {
        return Ok(result);
    }
    let body_type = request
        .value(method_block, "body")?
        .unwrap_or_else(|| "none".into());
    let body = request.block(&format!("body:{body_type}")).map(|block| {
        serde_json::from_str::<Value>(&block.content)
            .unwrap_or(Value::String(block.content.clone()))
    });
    let mut headers = BTreeMap::new();
    for document in documents {
        for pair in document.pairs("headers")? {
            let key = pair.key.to_lowercase();
            if pair.enabled {
                headers.insert(key, pair.value);
            } else {
                headers.remove(&key);
            }
        }
    }
    let data = json!({
        "vars": variables,
        "url": request.value(method_block, "url")?,
        "method": if method_block == "http" {request.value("http", "method")?.unwrap_or_default()} else {method_block.to_uppercase()},
        "headers": headers,
        "body": body,
        "bodyType": body_type,
        "response": response.map(|res| json!({
            "status":res.status,"headers":res.headers,
            "body":serde_json::from_str::<Value>(&res.body).unwrap_or(Value::String(res.body.clone())),
            "responseTime":res.elapsed_ms
        }))
    });
    let mut context = Context::builder()
        .instructions_remaining(1_000_000)
        .build()
        .map_err(script_error)?;
    let limits = context.runtime_limits_mut();
    limits.set_loop_iteration_limit(100_000);
    limits.set_recursion_limit(128);
    limits.set_stack_size_limit(16_384);
    let setup = format!("const __quinn = {data};\n{BOOTSTRAP}");
    context
        .eval(Source::from_bytes(&setup))
        .map_err(script_error)?;
    for block in scripts {
        let source = format!("{{\n{}\n}}", block.content);
        let value = match context.eval(Source::from_bytes(&source)) {
            Ok(value) => value,
            Err(error) if response.is_some() => {
                result.assertions.push(Assertion {
                    expression: block.name.clone(),
                    expected: "script completes".into(),
                    actual: error.to_string(),
                    passed: false,
                });
                break;
            }
            Err(error) => return Err(Error::invalid(format!("{}: {error}", block.name))),
        };
        if value
            .as_object()
            .is_some_and(|object| JsPromise::from_object(object).is_ok())
        {
            return Err(Error::Unsupported {
                feature: "asynchronous JavaScript scripts".into(),
            });
        }
    }
    let output = context.eval(Source::from_bytes(
        "JSON.stringify({variables:__quinn.changed, tests:__quinn.tests, mutations:__quinn.mutations})"
    )).map_err(script_error)?.to_string(&mut context).map_err(script_error)?.to_std_string_escaped();
    if output.len() > 1024 * 1024 {
        return Err(Error::invalid("script output exceeds the 1 MiB limit"));
    }
    let output: Output = serde_json::from_str(&output)
        .map_err(|error| Error::invalid(format!("invalid script output: {error}")))?;
    result.variables = output.variables;
    result.assertions.extend(
        output
            .tests
            .into_iter()
            .map(|test| Assertion {
                expression: format!("test: {}", test.name),
                expected: "pass".into(),
                actual: test.error.unwrap_or_else(|| "pass".into()),
                passed: test.passed,
            })
            .collect::<Vec<_>>(),
    );
    apply_mutations(&mut result.request, method_block, output.mutations)?;
    Ok(result)
}

fn script_error(error: impl std::fmt::Display) -> Error {
    Error::invalid(format!("cannot execute JavaScript: {error}"))
}

struct SynchronousOnly;

macro_rules! reject_async {
    ($method:ident, $type:ty) => {
        fn $method(&mut self, _: &'ast $type) -> ControlFlow<Self::BreakTy> {
            ControlFlow::Break(())
        }
    };
}

impl<'ast> Visitor<'ast> for SynchronousOnly {
    type BreakTy = ();
    reject_async!(visit_async_function_expression, AsyncFunctionExpression);
    reject_async!(visit_async_function_declaration, AsyncFunctionDeclaration);
    reject_async!(visit_async_arrow_function, AsyncArrowFunction);
    reject_async!(visit_async_generator_expression, AsyncGeneratorExpression);
    reject_async!(visit_async_generator_declaration, AsyncGeneratorDeclaration);
}

fn apply_mutations(
    document: &mut Document,
    method_block: &str,
    mutations: Mutations,
) -> Result<()> {
    for (key, value) in [("url", mutations.url), ("method", mutations.method)] {
        if let Some(value) = value {
            if key == "method" && method_block != "http" {
                let block = document
                    .blocks
                    .iter_mut()
                    .find(|block| block.name == method_block)
                    .ok_or_else(|| Error::invalid("missing request method"))?;
                let original = method_block.to_uppercase();
                block.name = "http".into();
                block.content.push_str(&format!("\nmethod: {original}"));
            }
            let name = if key == "method" {
                "http"
            } else {
                method_block
            };
            let name = if document.block(name).is_none() {
                "http"
            } else {
                name
            };
            set_pair(document, name, key, &value)?;
        }
    }
    for (key, value) in mutations.headers {
        set_pair(document, "headers", &key, &value)?;
    }
    if mutations.body_set {
        let body = mutations.body.unwrap_or(Value::Null);
        let name = if document.block(method_block).is_some() {
            method_block
        } else {
            "http"
        };
        let body_type = document
            .value(name, "body")?
            .unwrap_or_else(|| "none".into());
        let content = if body_type == "json" {
            serde_json::to_string(&body).map_err(script_error)?
        } else {
            body.as_str()
                .ok_or_else(|| Error::invalid("text script body must be a string"))?
                .into()
        };
        let block_name = format!("body:{body_type}");
        let block = document
            .blocks
            .iter_mut()
            .find(|block| block.name == block_name)
            .ok_or_else(|| Error::invalid("missing request body block"))?;
        block.content = content;
    }
    Ok(())
}

fn set_pair(document: &mut Document, name: &str, key: &str, value: &str) -> Result<()> {
    if key.contains(['\n', '\r', ':']) || value.contains(['\n', '\r']) {
        return Err(Error::invalid(
            "script request fields must be single-line values",
        ));
    }
    let mut pairs = document.pairs(name)?;
    pairs.retain(|pair| !pair.key.eq_ignore_ascii_case(key));
    let mut content = pairs
        .into_iter()
        .map(|pair| {
            format!(
                "{}{}: {}",
                if pair.enabled { "" } else { "~" },
                pair.key,
                pair.value
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    content.push_str(&format!("\n{key}: {value}"));
    if let Some(block) = document.blocks.iter_mut().find(|block| block.name == name) {
        block.content = content;
    } else {
        document.blocks.push(Block {
            name: name.into(),
            content,
            line: 0,
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct Output {
    variables: Variables,
    tests: Vec<Test>,
    mutations: Mutations,
}

#[derive(Deserialize)]
struct Test {
    name: String,
    passed: bool,
    error: Option<String>,
}

#[derive(Default, Deserialize)]
struct Mutations {
    url: Option<String>,
    method: Option<String>,
    headers: BTreeMap<String, String>,
    body: Option<Value>,
    #[serde(default, rename = "bodySet")]
    body_set: bool,
}

const BOOTSTRAP: &str = r#"
globalThis.Promise = new Proxy(function() {}, {
  construct: () => unsupported('Promise'),
  get: () => () => unsupported('Promise')
});
__quinn.changed = {};
__quinn.tests = [];
__quinn.mutations = {headers:{}};
function unsupported(name) { throw Error(name + ' is not supported in Quinn'); }
function stringify(value) {
  if (value === undefined) throw Error('variable value cannot be undefined');
  return typeof value === 'string' ? value : JSON.stringify(value);
}
const bru = new Proxy({
  getVar: name => __quinn.vars[name],
  hasVar: name => Object.hasOwn(__quinn.vars, name),
  setVar: (name, value) => {
    if (typeof name !== 'string' || !name) throw Error('variable name must be a nonempty string');
    value = stringify(value);
    if (value.length > 1048576) throw Error('variable exceeds the 1 MiB limit');
    __quinn.changed[name] = value; __quinn.vars[name] = value;
  },
  interpolate: value => String(value).replace(/\{\{([^}]+)\}\}/g, (_, name) => {
    if (!Object.hasOwn(__quinn.vars, name)) throw Error('missing variable ' + name);
    return __quinn.vars[name];
  })
}, {get:(target,key) => key in target ? target[key] : () => unsupported('bru.' + String(key))});
const req = new Proxy({
  getUrl: () => __quinn.url,
  getMethod: () => __quinn.method,
  getHeader: name => __quinn.headers[String(name).toLowerCase()],
  getHeaders: () => ({...__quinn.headers}),
  getBody: () => __quinn.body,
  setUrl: value => {__quinn.url = __quinn.mutations.url = String(value);},
  setMethod: value => {__quinn.method = __quinn.mutations.method = String(value);},
  setHeader: (name,value) => {
    name = String(name).toLowerCase();
    __quinn.headers[name] = __quinn.mutations.headers[name] = String(value);
  },
  setBody: value => {
    if (!['json','text','xml','sparql'].includes(__quinn.bodyType)) unsupported('req.setBody for this body type');
    if (value === undefined) throw Error('request body cannot be undefined');
    __quinn.mutations.bodySet = true;
    __quinn.body = __quinn.mutations.body = value;
  }
}, {get:(target,key) => key in target ? target[key] : () => unsupported('req.' + String(key))});
const res = __quinn.response && new Proxy({
  ...__quinn.response,
  getStatus: () => __quinn.response.status,
  getBody: () => __quinn.response.body,
  getHeaders: () => ({...__quinn.response.headers}),
  getHeader: name => __quinn.response.headers[String(name).toLowerCase()],
  getResponseTime: () => __quinn.response.responseTime
}, {get:(target,key) => key in target ? target[key] : () => unsupported('res.' + String(key))});
function test(name, fn) {
  try {
    const result = fn();
    if (result && typeof result.then === 'function') throw Error('asynchronous tests are not supported');
    __quinn.tests.push({name:String(name), passed:true, error:null});
  } catch (error) {
    __quinn.tests.push({name:String(name), passed:false, error:String(error)});
  }
}
function deepEqual(actual, expected, seen=[]) {
  if (Object.is(actual, expected)) return true;
  if (actual === null || expected === null || typeof actual !== 'object' || typeof expected !== 'object') return false;
  for (const value of [actual,expected]) {
    const prototype = Object.getPrototypeOf(value);
    if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null)
      unsupported('deep equality for non-JSON objects');
  }
  if (Array.isArray(actual) !== Array.isArray(expected)) return false;
  if (Array.isArray(actual) && actual.length !== expected.length) return false;
  if (seen.some(pair => pair[0] === actual && pair[1] === expected)) return true;
  seen.push([actual,expected]);
  const keys = value => Reflect.ownKeys(value).filter(key => Object.prototype.propertyIsEnumerable.call(value,key));
  const left = keys(actual), right = keys(expected);
  return left.length === right.length && left.every(key => right.includes(key) && deepEqual(actual[key],expected[key],seen));
}
function expect(actual) {
  function chain(negate=false, deep=false, own=false) {
    const check = (passed, message) => {
      if (negate ? passed : !passed) throw Error(message);
      return chain(negate,deep,own);
    };
    const equal = (left,right) => deep ? deepEqual(left,right) : left === right;
    const has = key => actual != null && (own ? Object.hasOwn(actual,key) : key in Object(actual));
    const numeric = (...values) => {
      if (values.some(value => typeof value !== 'number' || Number.isNaN(value))) throw Error('expected numeric arguments');
    };
    const matches = (text,pattern) => {
      const index = pattern.lastIndex;
      try { return pattern.test(text); } finally { pattern.lastIndex = index; }
    };
    const api = {
      equal: expected => check(equal(actual,expected), 'expected equality'),
      eql: expected => check(deepEqual(actual,expected), 'expected deep equality'),
      include: expected => {
        let included;
        if (typeof actual === 'string') {
          if (typeof expected !== 'string') throw Error('expected a string for inclusion');
          included = actual.includes(expected);
        } else if (Array.isArray(actual)) included = actual.some(value => equal(value,expected));
        else if (Object.prototype.toString.call(actual) === '[object Object]') {
          if (Object.prototype.toString.call(expected) !== '[object Object]') throw Error('expected an object for inclusion');
          included = Object.keys(expected).every(key => has(key) && equal(actual[key],expected[key]));
        } else unsupported('inclusion for this value type');
        return check(included,'expected inclusion');
      },
      above: expected => {numeric(actual,expected); return check(actual > expected, 'expected greater value');},
      least: expected => {numeric(actual,expected); return check(actual >= expected, 'expected minimum value');},
      below: expected => {numeric(actual,expected); return check(actual < expected, 'expected smaller value');},
      most: expected => {numeric(actual,expected); return check(actual <= expected, 'expected maximum value');},
      within: (min,max) => {numeric(actual,min,max); return check(actual >= min && actual <= max, 'expected value within range');},
      lengthOf: expected => {
        if (actual == null || typeof actual.length !== 'number') throw Error('expected a value with a length');
        numeric(expected); return check(actual.length === expected,'expected length');
      },
      match: pattern => {
        if (typeof actual !== 'string' || !(pattern instanceof RegExp)) throw Error('expected a string and a RegExp');
        return check(matches(actual,pattern),'expected regular expression match');
      },
      a: type => {
        if (typeof type !== 'string') throw Error('expected a type name');
        const kind = actual === null ? 'null' : Object.prototype.toString.call(actual).slice(8,-1).toLowerCase();
        return check(kind === type.toLowerCase(),'expected type ' + type);
      },
      property: function(key,value) {
        if (!['string','number','symbol'].includes(typeof key)) throw Error('expected a property name');
        const exists = has(key);
        check(exists && (arguments.length < 2 || equal(actual[key],value)), 'expected property ' + String(key));
        return exists ? expect(actual[key]) : chain(negate,deep,own);
      },
      throw: (errorType,message) => {
        if (typeof actual !== 'function') throw Error('expected a function');
        if (typeof errorType === 'string' || errorType instanceof RegExp) {message = errorType; errorType = undefined;}
        if (errorType !== undefined && typeof errorType !== 'function' && !(errorType instanceof Error)) throw Error('expected an error constructor or instance');
        if (message !== undefined && typeof message !== 'string' && !(message instanceof RegExp)) throw Error('expected an error message or RegExp');
        let caught, threw = false;
        try { actual(); } catch (error) {caught = error; threw = true;}
        const text = caught != null && caught.message !== undefined ? String(caught.message) : String(caught);
        const correctType = errorType === undefined || (threw && (typeof errorType === 'function' ? caught instanceof errorType : caught === errorType));
        const correctMessage = message === undefined || (typeof message === 'string' ? text.includes(message) : matches(text,message));
        check(threw && correctType && correctMessage,'expected function to throw matching error');
        return expect(caught);
      }
    };
    api.equals = api.eq = api.equal; api.contain = api.includes = api.include; api.an = api.a;
    api.greaterThan = api.gt = api.above; api.lessThan = api.lt = api.below;
    api.greaterThanOrEqual = api.gte = api.least; api.lessThanOrEqual = api.lte = api.most;
    api.length = api.lengthOf; api.matches = api.match; api.throws = api.Throw = api.throw;
    return new Proxy(api,{get:(target,key) => {
      // Assertion chains are synchronous, not thenables.
      if (key === 'then') return undefined;
      if (['to','be','been','have','has','with','and','is','that','which','at','of','same','but','does','still','also'].includes(key)) return chain(negate,deep,own);
      if (key === 'not') return chain(!negate,deep,own);
      if (key === 'deep') return chain(negate,true,own);
      if (key === 'own') return chain(negate,deep,true);
      if (key === 'empty') {
        let empty;
        if (typeof actual === 'string' || Array.isArray(actual)) empty = actual.length === 0;
        else if (actual !== null && typeof actual === 'object' &&
          (Object.getPrototypeOf(actual) === Object.prototype || Object.getPrototypeOf(actual) === null)) empty = Object.keys(actual).length === 0;
        else unsupported('empty assertion for this value type');
        return check(empty,'expected empty value');
      }
      const predicates = {ok:!!actual,true:actual === true,false:actual === false,null:actual === null,
        undefined:actual === undefined,NaN:Number.isNaN(actual),exist:actual != null};
      if (Object.hasOwn(predicates,key)) return check(predicates[key], 'expected ' + key);
      if (Object.hasOwn(target,key)) return target[key];
      throw Error('expect.' + String(key) + ' is not supported in Quinn');
    }});
  }
  return chain();
}
const assert = Object.assign((value,message) => {if (!value) throw Error(message || 'assertion failed');}, {
  equal:(a,b) => expect(a).to.equal(b), deepEqual:(a,b) => expect(a).to.deep.equal(b),
  isTrue:value => expect(value).to.be.true, isFalse:value => expect(value).to.be.false
});
Object.defineProperty(Function.prototype, 'constructor', {value:() => unsupported('Function')});
globalThis.Function = () => unsupported('Function');
globalThis.eval = () => unsupported('eval');
"#;
