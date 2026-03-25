use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathKeyMode {
    #[cfg(test)]
    Exact,
    AsciiCaseInsensitive,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathPolicy {
    key_mode: PathKeyMode,
}

#[cfg(any(target_os = "windows", test))]
impl PathPolicy {
    pub(crate) const fn new(key_mode: PathKeyMode) -> Self {
        Self { key_mode }
    }

    #[cfg(test)]
    pub(crate) const fn exact() -> Self {
        Self::new(PathKeyMode::Exact)
    }

    pub(crate) const fn ascii_case_insensitive() -> Self {
        Self::new(PathKeyMode::AsciiCaseInsensitive)
    }

    #[cfg(test)]
    pub(crate) fn normalize_paths(self, paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
        dedupe_canonical_paths(paths, self.key_mode)
    }

    pub(crate) fn validate_and_dedupe<E>(
        self,
        paths: impl IntoIterator<Item = PathBuf>,
        mut validate: impl FnMut(&Path) -> Result<PathBuf, E>,
    ) -> Result<Vec<PathBuf>, E> {
        let mut validated = Vec::new();
        for path in paths {
            validated.push(validate(&path)?);
        }
        Ok(dedupe_paths(validated, self.key_mode))
    }
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn canonicalize_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = absolute_path(path)?;
    canonicalize_absolute(&absolute)
}

#[cfg(test)]
pub(crate) fn canonicalize_or_original(path: &Path) -> PathBuf {
    canonicalize_path(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
pub(crate) fn dedupe_canonical_paths(
    paths: impl IntoIterator<Item = PathBuf>,
    mode: PathKeyMode,
) -> Vec<PathBuf> {
    let canonicalized = paths
        .into_iter()
        .map(|path| canonicalize_or_original(&path))
        .collect::<Vec<_>>();
    dedupe_paths(canonicalized, mode)
}

#[cfg(any(target_os = "windows", test))]
fn dedupe_paths(paths: impl IntoIterator<Item = PathBuf>, mode: PathKeyMode) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        let key = path_key(&path, mode);
        if seen.insert(key) {
            out.push(path);
        }
    }
    out
}

pub(crate) fn path_exists(path: &Path) -> bool {
    let Ok(absolute) = absolute_path(path) else {
        return false;
    };

    if let Some((parent, leaf)) = parent_and_leaf(&absolute) {
        let Ok(dir) = Dir::open_ambient_dir(parent, ambient_authority()) else {
            return false;
        };

        return dir.try_exists(leaf).unwrap_or(false);
    }

    Dir::open_ambient_dir(&absolute, ambient_authority()).is_ok()
}

pub(crate) fn is_dir(path: &Path) -> bool {
    let Ok(absolute) = absolute_path(path) else {
        return false;
    };

    if let Some((parent, leaf)) = parent_and_leaf(&absolute) {
        let Ok(dir) = Dir::open_ambient_dir(parent, ambient_authority()) else {
            return false;
        };

        return dir
            .metadata(leaf)
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false);
    }

    Dir::open_ambient_dir(&absolute, ambient_authority()).is_ok()
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn is_file(path: &Path) -> bool {
    let Ok(absolute) = absolute_path(path) else {
        return false;
    };

    let Some((parent, leaf)) = parent_and_leaf(&absolute) else {
        return false;
    };

    let Ok(dir) = Dir::open_ambient_dir(parent, ambient_authority()) else {
        return false;
    };

    dir.metadata(leaf)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

#[cfg(test)]
pub(crate) fn is_symlink(path: &Path) -> io::Result<bool> {
    let absolute = absolute_path(path)?;

    let Some((parent, leaf)) = parent_and_leaf(&absolute) else {
        return Ok(false);
    };

    let dir = Dir::open_ambient_dir(parent, ambient_authority())?;
    let metadata = dir.symlink_metadata(leaf)?;
    Ok(metadata.file_type().is_symlink())
}

#[cfg(test)]
pub(crate) fn child_directories(path: &Path, limit: usize) -> io::Result<Vec<PathBuf>> {
    let absolute = absolute_path(path)?;
    let dir = Dir::open_ambient_dir(&absolute, ambient_authority())?;

    let mut out = Vec::new();
    for entry in dir.entries()?.take(limit) {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        out.push(absolute.join(entry.file_name()));
    }

    Ok(out)
}

#[cfg(any(target_os = "windows", test))]
fn canonicalize_absolute(absolute: &Path) -> io::Result<PathBuf> {
    if let Some((parent, leaf)) = parent_and_leaf(absolute) {
        let dir = Dir::open_ambient_dir(parent, ambient_authority())?;
        let relative = dir.canonicalize(leaf)?;
        Ok(parent.join(relative))
    } else {
        absolute.canonicalize()
    }
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn parent_and_leaf(path: &Path) -> Option<(&Path, &OsStr)> {
    Some((path.parent()?, path.file_name()?))
}

#[cfg(any(target_os = "windows", test))]
fn path_key(path: &Path, mode: PathKeyMode) -> String {
    match mode {
        #[cfg(test)]
        PathKeyMode::Exact => path.to_string_lossy().to_string(),
        PathKeyMode::AsciiCaseInsensitive => path.to_string_lossy().to_ascii_lowercase(),
    }
}

#[cfg(test)]
#[path = "../tests/unit/cap_fs_tests.rs"]
mod tests;
