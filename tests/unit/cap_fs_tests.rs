use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    PathKeyMode, PathPolicy, canonicalize_path, child_directories, dedupe_canonical_paths, is_dir,
    is_file, is_symlink, path_exists,
};

#[test]
fn canonicalize_path_matches_std_for_directory() {
    let temp = unique_temp_path("cap-fs-canonicalize");
    fs::create_dir_all(&temp).expect("temp directory should be created");

    let expected = temp.canonicalize().expect("std canonicalize should work");
    let actual = canonicalize_path(&temp).expect("cap canonicalize should work");

    assert_eq!(
        actual
            .canonicalize()
            .expect("cap-derived path should canonicalize"),
        expected
    );

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn path_exists_and_is_dir_reflect_directory_presence() {
    let temp = unique_temp_path("cap-fs-exists");
    fs::create_dir_all(&temp).expect("temp directory should be created");

    assert!(path_exists(&temp));
    assert!(is_dir(&temp));

    let _ = fs::remove_dir_all(&temp);
    assert!(!path_exists(&temp));
    assert!(!is_dir(&temp));
}

#[test]
fn is_symlink_false_for_regular_file() {
    let temp = unique_temp_path("cap-fs-symlink");
    fs::create_dir_all(&temp).expect("temp directory should be created");
    let file = temp.join("plain.txt");
    fs::write(&file, "ok").expect("temp file should be created");

    let value = is_symlink(&file).expect("symlink query should succeed");
    assert!(!value);

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn is_file_true_for_regular_file() {
    let temp = unique_temp_path("cap-fs-file");
    fs::create_dir_all(&temp).expect("temp directory should be created");
    let file = temp.join("plain.txt");
    fs::write(&file, "ok").expect("temp file should be created");

    assert!(is_file(&file));
    assert!(!is_file(&temp));

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn child_directories_returns_only_directories() {
    let temp = unique_temp_path("cap-fs-children");
    fs::create_dir_all(&temp).expect("temp directory should be created");
    fs::create_dir_all(temp.join("a")).expect("dir a should be created");
    fs::create_dir_all(temp.join("b")).expect("dir b should be created");
    fs::write(temp.join("file.txt"), "x").expect("file should be created");

    let children = child_directories(&temp, 10).expect("children query should succeed");
    let mut names = children
        .iter()
        .filter_map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    names.sort();

    assert_eq!(names, vec!["a".to_string(), "b".to_string()]);

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn dedupe_canonical_paths_respects_key_mode() {
    let temp = unique_temp_path("cap-fs-dedupe");
    fs::create_dir_all(&temp).expect("temp directory should be created");

    let sample = temp.join("MiXeD-Case-Entry");
    let upper = std::path::PathBuf::from(sample.to_string_lossy().to_string().to_uppercase());
    let lower = std::path::PathBuf::from(sample.to_string_lossy().to_string().to_lowercase());

    let exact = dedupe_canonical_paths(vec![upper.clone(), lower.clone()], PathKeyMode::Exact);
    assert_eq!(exact.len(), 2);

    let insensitive = dedupe_canonical_paths(vec![upper, lower], PathKeyMode::AsciiCaseInsensitive);
    assert_eq!(insensitive.len(), 1);

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn path_policy_validate_and_dedupe_uses_mode() {
    let policy = PathPolicy::ascii_case_insensitive();
    let paths = vec![
        std::path::PathBuf::from(r"C:\\Temp\\Value"),
        std::path::PathBuf::from(r"c:\\temp\\value"),
    ];

    let deduped = policy
        .validate_and_dedupe(paths, |path| Ok::<_, ()>(path.to_path_buf()))
        .expect("validation should succeed");
    assert_eq!(deduped.len(), 1);
}

#[test]
fn path_policy_exact_keeps_case_distinct_inputs() {
    let policy = PathPolicy::exact();
    let normalized = policy.normalize_paths(vec![
        std::path::PathBuf::from("CaseSensitive"),
        std::path::PathBuf::from("casesensitive"),
    ]);

    assert_eq!(normalized.len(), 2);
}

fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!("agena-{prefix}-{nonce}"))
}
