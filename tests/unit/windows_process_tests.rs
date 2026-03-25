use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{quote_windows_arg, resolve_executable};

#[test]
fn resolve_executable_honors_custom_path_and_pathext() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("agena-resolve-exec-test-{nonce}"));
    fs::create_dir_all(&temp_dir).expect("temp directory should be created");

    let tool_path = temp_dir.join("demo.cmd");
    fs::write(&tool_path, "@echo off\r\nexit /b 0\r\n").expect("stub command should be written");

    let mut env = HashMap::new();
    env.insert("PATH".to_string(), temp_dir.to_string_lossy().to_string());
    env.insert("PATHEXT".to_string(), ".CMD;.EXE".to_string());

    let resolved = resolve_executable("demo", &temp_dir, &env)
        .expect("executable should resolve via PATH/PATHEXT");

    assert_eq!(
        resolved
            .canonicalize()
            .expect("resolved path should canonicalize"),
        tool_path
            .canonicalize()
            .expect("tool path should canonicalize"),
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn resolve_executable_does_not_fallback_to_path_for_relative_binary() {
    let cwd = std::env::temp_dir();
    let env = HashMap::new();

    let resolved = resolve_executable(r".\missing-command", &cwd, &env);
    assert!(resolved.is_none());
}

#[test]
fn quote_windows_arg_handles_spaces_quotes_and_trailing_backslashes() {
    assert_eq!(quote_windows_arg("plain"), "plain");
    assert_eq!(quote_windows_arg("two words"), r#""two words""#);
    assert_eq!(
        quote_windows_arg(r#"a\"b"#),
        r#""a\\\"b""#,
        "embedded quote should be escaped with preceding backslashes"
    );
    assert_eq!(
        quote_windows_arg(r"path with tail\\"),
        r#""path with tail\\\\""#,
        "trailing backslashes must be doubled inside quoted arg"
    );
}
