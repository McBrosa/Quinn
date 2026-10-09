use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use reqwest::blocking::{
    Body,
    multipart::{Form, Part},
};

use crate::{
    Error, Result,
    bru::Pair,
    variables::{Variables, interpolate},
};

/// Interpret Bruno's inline file and content-type annotations.
pub(crate) fn multipart(pairs: Vec<Pair>, root: &Path, variables: &Variables) -> Result<Form> {
    let mut form = Form::new();
    for pair in pairs.into_iter().filter(|pair| pair.enabled) {
        let key = interpolate(&pair.key, variables)?;
        if pair.is_list {
            for value in pair.value.lines() {
                form = form.part(key.clone(), Part::text(interpolate(value, variables)?));
            }
            continue;
        }
        let value = interpolate(&pair.value, variables)?;
        let (value, content_type) = annotations(&value)?;
        if let Some(paths) = file_paths(value)? {
            for path in paths {
                let path = root.join(path);
                let (file, length) = open_file(&path)?;
                let filename = path
                    .file_name()
                    .ok_or_else(|| Error::invalid("upload has no filename"))?
                    .to_string_lossy()
                    .into_owned();
                let part = Part::reader_with_length(file, length).file_name(filename);
                form = form.part(key.clone(), mime(part, content_type)?);
            }
        } else {
            form = form.part(key, mime(Part::text(value.to_owned()), content_type)?);
        }
    }
    Ok(form)
}

pub(crate) fn binary(
    pairs: Vec<Pair>,
    root: &Path,
    variables: &Variables,
) -> Result<(Body, String)> {
    let mut enabled = pairs.into_iter().filter(|pair| pair.enabled);
    let pair = enabled
        .next()
        .ok_or_else(|| Error::invalid("binary body requires one enabled file"))?;
    if pair.key != "file" || pair.is_list || enabled.next().is_some() {
        return Err(Error::invalid(
            "binary body requires exactly one enabled 'file' entry",
        ));
    }
    let value = interpolate(&pair.value, variables)?;
    let (value, content_type) = annotations(&value)?;
    let paths =
        file_paths(value)?.ok_or_else(|| Error::invalid("binary body requires @file(PATH)"))?;
    if paths.len() != 1 {
        return Err(Error::invalid("binary body requires exactly one file path"));
    }
    let path = root.join(paths[0]);
    let (file, length) = open_file(&path)?;
    // Validate the MIME type before reading or sending the upload.
    let content_type = content_type.unwrap_or("application/octet-stream");
    mime(Part::text(String::new()), Some(content_type))?;
    Ok((Body::sized(file, length), content_type.to_owned()))
}

fn annotations(value: &str) -> Result<(&str, Option<&str>)> {
    let Some((content, annotation)) = value.rsplit_once(" @contentType(") else {
        return Ok((value, None));
    };
    let content_type = annotation
        .strip_suffix(')')
        .ok_or_else(|| Error::invalid("unclosed @contentType annotation"))?;
    if content_type.is_empty() || content_type.contains(['\r', '\n']) {
        return Err(Error::invalid("invalid upload content type"));
    }
    Ok((content, Some(content_type)))
}

fn file_paths(value: &str) -> Result<Option<Vec<&str>>> {
    let Some(value) = value.strip_prefix("@file(") else {
        return Ok(None);
    };
    let value = value
        .strip_suffix(')')
        .ok_or_else(|| Error::invalid("unclosed @file annotation"))?;
    let paths: Vec<_> = value.split('|').map(str::trim).collect();
    if paths.iter().any(|path| path.is_empty()) {
        return Err(Error::invalid("upload file path is empty"));
    }
    Ok(Some(paths))
}

fn open_file(path: &Path) -> Result<(File, u64)> {
    let metadata = fs::metadata(path).map_err(|source| Error::Io {
        path: PathBuf::from(path),
        source,
    })?;
    if !metadata.is_file() {
        return Err(Error::invalid("upload path must name a regular file"));
    }
    let file = File::open(path).map_err(|source| Error::Io {
        path: PathBuf::from(path),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| Error::Io {
        path: PathBuf::from(path),
        source,
    })?;
    if !metadata.is_file() {
        return Err(Error::invalid("upload path must name a regular file"));
    }
    Ok((file, metadata.len()))
}

fn mime(part: Part, content_type: Option<&str>) -> Result<Part> {
    match content_type {
        Some(content_type) => part
            .mime_str(content_type)
            .map_err(|_| Error::invalid("invalid upload content type")),
        None => Ok(part),
    }
}
