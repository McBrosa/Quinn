use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use crate::{Error, Result, bru::Document, opencollection, variables::Variables};

#[derive(Clone, Debug)]
pub struct Entry {
    pub path: PathBuf,
    pub name: String,
    pub sequence: i64,
}

/// Discover request files in a collection without following symbolic links.
pub fn discover(path: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    if fs::symlink_metadata(path)
        .map_err(|source| Error::io(path, source))?
        .file_type()
        .is_symlink()
    {
        return Ok(entries);
    }
    if path.is_file() {
        let root = root(path)?;
        if (is_yaml(&root) && path.extension().is_some_and(|extension| extension == "bru"))
            || (!is_yaml(&root)
                && root.join("bruno.json").is_file()
                && path.extension().is_some_and(|extension| extension == "yml"))
        {
            return Err(Error::invalid(
                "request format does not match the collection",
            ));
        }
        add_entry(path, &mut entries)?;
    } else {
        walk(path, is_yaml(&root(path)?), &mut entries)?;
    }
    Ok(entries)
}

/// Parse a request without changing its original source format.
pub fn parse(path: &Path, source: &str) -> Result<Document> {
    if path.extension().is_some_and(|extension| extension == "yml") {
        opencollection::parse(
            source,
            path.file_name()
                .is_some_and(|name| name == "opencollection.yml"),
            path.file_name().is_some_and(|name| name == "folder.yml"),
        )
    } else {
        Document::parse(source)
    }
}

pub fn load(path: &Path) -> Result<Document> {
    if fs::symlink_metadata(path)
        .map_err(|source| Error::io(path, source))?
        .file_type()
        .is_symlink()
    {
        return Err(Error::invalid(
            "cannot load symbolic-link metadata or requests",
        ));
    }
    parse(path, &read(path)?)
}

pub fn is_yaml(root: &Path) -> bool {
    root.join("opencollection.yml").is_file()
}

pub fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| Error::io(path, source))
}

/// Replace a request atomically if its contents still match the opened version.
pub fn save(path: &Path, original: &str, source: &str) -> Result<()> {
    if fs::symlink_metadata(path)
        .map_err(|source| Error::io(path, source))?
        .file_type()
        .is_symlink()
    {
        return Err(Error::invalid("cannot save symbolic-link request"));
    }
    if path.extension().is_some_and(|extension| extension == "yml") {
        opencollection::validate_syntax(source)?;
    } else {
        Document::parse(source)?;
    }
    if read(path)? != original {
        return Err(Error::invalid(
            "file changed on disk; reopen it before saving",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::invalid("request has no parent directory"))?;
    let permissions = fs::metadata(path)
        .map_err(|source| Error::io(path, source))?
        .permissions();
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| Error::io(path, source))?;
    temporary
        .as_file()
        .set_permissions(permissions)
        .map_err(|source| Error::io(path, source))?;
    temporary
        .write_all(source.as_bytes())
        .map_err(|source| Error::io(path, source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| Error::io(path, source))?;
    if read(path)? != original {
        return Err(Error::invalid(
            "file changed on disk; reopen it before saving",
        ));
    }
    temporary
        .persist(path)
        .map_err(|error| Error::io(path, error.error))?;
    Ok(())
}

/// Locate the collection root, or use the request's parent for standalone files.
pub fn root(path: &Path) -> Result<PathBuf> {
    let absolute = fs::canonicalize(path).map_err(|source| Error::io(path, source))?;
    let directory = if absolute.is_dir() {
        absolute
    } else {
        absolute
            .parent()
            .ok_or_else(|| Error::invalid("request has no parent directory"))?
            .to_owned()
    };
    for parent in directory.ancestors() {
        let mut collection = false;
        for marker in ["opencollection.yml", "bruno.json"] {
            let marker = parent.join(marker);
            match fs::symlink_metadata(&marker) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(Error::invalid(
                            "cannot load symbolic-link collection metadata",
                        ));
                    }
                    collection |= metadata.is_file();
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(Error::io(&marker, source)),
            }
        }
        if collection {
            return Ok(parent.to_owned());
        }
    }
    Ok(directory)
}

/// Load collection and folder defaults from the outermost directory inward.
pub fn defaults(root: &Path, request: &Path) -> Result<Vec<Document>> {
    let root = fs::canonicalize(root).map_err(|source| Error::io(root, source))?;
    let request = fs::canonicalize(request).map_err(|source| Error::io(request, source))?;
    let parent = request
        .parent()
        .ok_or_else(|| Error::invalid("request has no parent directory"))?;
    let relative = parent
        .strip_prefix(&root)
        .map_err(|_| Error::invalid("request is outside the collection"))?;
    let mut documents = Vec::new();
    let yaml = is_yaml(&root);
    let collection = root.join(if yaml {
        "opencollection.yml"
    } else {
        "collection.bru"
    });
    if collection.is_file() {
        documents.push(load(&collection)?);
    }
    let mut directory = root;
    for component in relative.components() {
        directory.push(component);
        let folder = directory.join(if yaml { "folder.yml" } else { "folder.bru" });
        if folder.is_file() {
            documents.push(load(&folder)?);
        }
    }
    Ok(documents)
}

pub fn environment(root: &Path, name: &str) -> Result<Variables> {
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(Error::invalid(
            "environment must be a name, without path separators",
        ));
    }
    if is_yaml(root) {
        let embedded =
            opencollection::embedded_environments(&read(&root.join("opencollection.yml"))?)?;
        let mut chain = Vec::new();
        let mut current = name.to_owned();
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if current.contains(['/', '\\'])
                || current == "."
                || current == ".."
                || !seen.insert(current.clone())
                || seen.len() > 64
            {
                return Err(Error::invalid("invalid or cyclic environment inheritance"));
            }
            let path = root.join("environments").join(format!("{current}.yml"));
            let source = if path.is_file() {
                if embedded.iter().any(|(name, _)| name == &current) {
                    return Err(Error::invalid(
                        "environment exists both in collection and on disk",
                    ));
                }
                if fs::symlink_metadata(&path)
                    .map_err(|source| Error::io(&path, source))?
                    .file_type()
                    .is_symlink()
                {
                    return Err(Error::invalid("cannot load symbolic-link environment"));
                }
                read(&path)?
            } else {
                embedded
                    .iter()
                    .find(|(name, _)| name == &current)
                    .map(|(_, source)| source.clone())
                    .ok_or_else(|| Error::invalid(format!("cannot find environment '{current}'")))?
            };
            let (variables, parent) = opencollection::environment(&source)?;
            chain.push(variables);
            match parent {
                Some(parent) => current = parent,
                None => break,
            }
        }
        let mut variables = Variables::new();
        for inherited in chain.into_iter().rev() {
            variables.extend(inherited);
        }
        return Ok(variables);
    }
    let path = root.join("environments").join(format!("{name}.bru"));
    if fs::symlink_metadata(&path)
        .map_err(|source| Error::io(&path, source))?
        .file_type()
        .is_symlink()
    {
        return Err(Error::invalid("cannot load symbolic-link environment"));
    }
    let document = Document::parse(&read(&path)?)?;
    for block in &document.blocks {
        if !matches!(block.name.as_str(), "vars" | "vars:secret" | "docs") {
            return Err(Error::Unsupported {
                feature: format!("environment block '{}'", block.name),
            });
        }
        if block.name == "vars:secret" && !block.content.trim().is_empty() {
            return Err(Error::Unsupported {
                feature:
                    "Bruno secret storage; supply secrets with --var or the desktop variables field"
                        .into(),
            });
        }
    }
    let pairs = document.pairs("vars")?;
    Ok(pairs
        .into_iter()
        .filter(|pair| pair.enabled)
        .map(|pair| (pair.key, pair.value))
        .collect())
}

pub fn environment_names(root: &Path) -> Result<Vec<String>> {
    let directory = root.join("environments");
    let mut names = if is_yaml(root) {
        opencollection::embedded_environments(&read(&root.join("opencollection.yml"))?)?
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    } else {
        Vec::new()
    };
    if !directory.exists() {
        names.sort();
        return Ok(names);
    }
    for entry in fs::read_dir(&directory).map_err(|source| Error::io(&directory, source))? {
        let entry = entry.map_err(|source| Error::io(&directory, source))?;
        let path = entry.path();
        if entry
            .file_type()
            .map_err(|source| Error::io(&path, source))?
            .is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == if is_yaml(root) { "yml" } else { "bru" })
            && let Some(name) = path.file_stem().and_then(|name| name.to_str())
        {
            if names.iter().any(|existing| existing == name) {
                return Err(Error::invalid(
                    "environment exists both in collection and on disk",
                ));
            }
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn walk(directory: &Path, yaml: bool, entries: &mut Vec<Entry>) -> Result<()> {
    let mut folders = Vec::new();
    let mut requests = Vec::new();
    for entry in fs::read_dir(directory).map_err(|source| Error::io(directory, source))? {
        let entry = entry.map_err(|source| Error::io(directory, source))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|source| Error::io(&path, source))?;
        if kind.is_dir() {
            if !matches!(
                entry.file_name().to_str(),
                Some("environments" | "node_modules" | ".git" | ".quinn")
            ) {
                let metadata = path.join(if yaml { "folder.yml" } else { "folder.bru" });
                let sequence = if metadata.is_file() {
                    sequence(&metadata_document(&metadata)?, &metadata)?
                } else {
                    0
                };
                folders.push((path, sequence));
            }
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == if yaml { "yml" } else { "bru" })
        {
            add_entry(&path, &mut requests)?;
        }
    }
    folders.sort_by(|left, right| left.0.file_name().cmp(&right.0.file_name()));
    let mut sorted: Vec<Vec<(PathBuf, i64)>> = folders
        .iter()
        .filter(|(_, sequence)| *sequence <= 0)
        .cloned()
        .map(|folder| vec![folder])
        .collect();
    folders.retain(|(_, sequence)| *sequence > 0);
    folders.sort_by_key(|(_, sequence)| *sequence);
    for folder in folders {
        let position = usize::try_from(folder.1 - 1)
            .unwrap_or(usize::MAX)
            .min(sorted.len());
        if sorted
            .get(position)
            .is_some_and(|group| group.first().is_some_and(|existing| existing.1 == folder.1))
        {
            sorted[position].push(folder);
        } else {
            sorted.insert(position, vec![folder]);
        }
    }
    for (path, _) in sorted.into_iter().flatten() {
        walk(&path, yaml, entries)?;
    }
    requests.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then(left.path.cmp(&right.path))
    });
    entries.extend(requests);
    Ok(())
}

fn add_entry(path: &Path, entries: &mut Vec<Entry>) -> Result<()> {
    if path
        .extension()
        .is_none_or(|extension| extension != "bru" && extension != "yml")
        || matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("collection.bru" | "folder.bru" | "opencollection.yml" | "folder.yml")
        )
    {
        return Ok(());
    }
    let document = if path.extension().is_some_and(|extension| extension == "yml") {
        let Some(document) = opencollection::request_metadata(&read(path)?)? else {
            return Ok(());
        };
        document
    } else {
        load(path)?
    };
    let name = document.value("meta", "name")?.unwrap_or_else(|| {
        path.file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    });
    let sequence = sequence(&document, path)?;
    entries.push(Entry {
        path: path.to_owned(),
        name,
        sequence,
    });
    Ok(())
}

fn sequence(document: &Document, path: &Path) -> Result<i64> {
    document
        .value("meta", "seq")?
        .map_or(Ok(0), |value| value.parse::<i64>())
        .map_err(|_| Error::invalid(format!("invalid sequence in {}", path.display())))
}

fn metadata_document(path: &Path) -> Result<Document> {
    if fs::symlink_metadata(path)
        .map_err(|source| Error::io(path, source))?
        .file_type()
        .is_symlink()
    {
        return Err(Error::invalid("cannot load symbolic-link metadata"));
    }
    if path.extension().is_some_and(|extension| extension == "yml") {
        opencollection::metadata(&read(path)?)
    } else {
        load(path)
    }
}
