use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use crate::{Error, Result, bru::Document, variables::Variables};

#[derive(Clone, Debug)]
pub struct Entry {
    pub path: PathBuf,
    pub name: String,
    pub sequence: i64,
}

/// Discover request files in a collection without following symbolic links.
pub fn discover(path: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    if path.is_file() {
        add_entry(path, &mut entries)?;
    } else {
        walk(path, &mut entries)?;
    }
    entries.sort_by(|left, right| {
        left.path
            .parent()
            .cmp(&right.path.parent())
            .then(left.sequence.cmp(&right.sequence))
            .then(left.path.cmp(&right.path))
    });
    Ok(entries)
}

pub fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| Error::io(path, source))
}

/// Replace a request atomically if its contents still match the opened version.
pub fn save(path: &Path, original: &str, source: &str) -> Result<()> {
    Document::parse(source)?;
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
    Ok(directory
        .ancestors()
        .find(|parent| parent.join("bruno.json").is_file())
        .unwrap_or(&directory)
        .to_owned())
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
    let collection = root.join("collection.bru");
    if collection.is_file() {
        documents.push(Document::parse(&read(&collection)?)?);
    }
    let mut directory = root;
    for component in relative.components() {
        directory.push(component);
        let folder = directory.join("folder.bru");
        if folder.is_file() {
            documents.push(Document::parse(&read(&folder)?)?);
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
    let path = root.join("environments").join(format!("{name}.bru"));
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
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|source| Error::io(&directory, source))? {
        let entry = entry.map_err(|source| Error::io(&directory, source))?;
        let path = entry.path();
        if entry
            .file_type()
            .map_err(|source| Error::io(&path, source))?
            .is_file()
            && path.extension().is_some_and(|extension| extension == "bru")
            && let Some(name) = path.file_stem().and_then(|name| name.to_str())
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn walk(directory: &Path, entries: &mut Vec<Entry>) -> Result<()> {
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
                walk(&path, entries)?;
            }
        } else if kind.is_file() {
            add_entry(&path, entries)?;
        }
    }
    Ok(())
}

fn add_entry(path: &Path, entries: &mut Vec<Entry>) -> Result<()> {
    if path.extension().is_none_or(|extension| extension != "bru")
        || matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("collection.bru" | "folder.bru")
        )
    {
        return Ok(());
    }
    let document = Document::parse(&read(path)?)?;
    let name = document.value("meta", "name")?.unwrap_or_else(|| {
        path.file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    });
    let sequence = document
        .value("meta", "seq")?
        .map_or(Ok(0), |value| value.parse::<i64>())
        .map_err(|_| Error::invalid(format!("invalid request sequence in {}", path.display())))?;
    entries.push(Entry {
        path: path.to_owned(),
        name,
        sequence,
    });
    Ok(())
}
