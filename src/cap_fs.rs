use std::ffi::OsStr;
use std::io;
#[cfg(target_os = "windows")]
use std::path::{Component, Prefix};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathKeyMode {
    AsciiCaseInsensitive,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathPolicy {
    key_mode: PathKeyMode,
}

#[cfg(target_os = "windows")]
impl PathPolicy {
    pub(crate) const fn ascii_case_insensitive() -> Self {
        Self {
            key_mode: PathKeyMode::AsciiCaseInsensitive,
        }
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

pub(crate) fn canonicalize_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = absolute_path(path)?;
    let canonical = absolute.canonicalize()?;

    #[cfg(target_os = "windows")]
    {
        Ok(strip_windows_verbatim_prefix(&canonical))
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(canonical)
    }
}

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
fn path_key(path: &Path, mode: PathKeyMode) -> String {
    match mode {
        PathKeyMode::AsciiCaseInsensitive => path.to_string_lossy().to_ascii_lowercase(),
    }
}

#[cfg(target_os = "windows")]
fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    let mut components = path.components();
    let Some(Component::Prefix(prefix_component)) = components.next() else {
        return path.to_path_buf();
    };

    let mut normalized = match prefix_component.kind() {
        Prefix::VerbatimDisk(letter) => PathBuf::from(format!("{}:", letter as char)),
        Prefix::VerbatimUNC(server, share) => {
            let mut prefix = PathBuf::from(r"\\");
            prefix.push(server);
            prefix.push(share);
            prefix
        }
        _ => return path.to_path_buf(),
    };

    for component in components {
        normalized.push(component.as_os_str());
    }

    normalized
}
