use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_userns-guard"))
}

#[test]
fn detect_runs_on_dev_host() {
    let out = bin().args(["detect", "--json"]).output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json.get("recommended_backend").is_some());
}

#[test]
fn preset_is_valid_toml() {
    let out = bin().arg("preset").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("name = \"oci-runtimes\""));
    assert!(stdout.contains("/opt/google/chrome/chrome"));
}

#[test]
fn preset_allows_registered_runtime_path() {
    let out = bin()
        .args(["check", "--exe", "/usr/bin/runc", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "check should allow runc");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["decision"]["verdict"], "allow");
    assert_eq!(json["decision"]["enforced"], "allow");
}

#[test]
fn unknown_binary_is_denied_by_default_in_enforce_policy() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        r#"
version = 1
mode = "enforce"
default_action = "deny"

[[allow]]
name = "runc"
paths = ["/usr/bin/runc"]
"#,
    )
    .unwrap();

    let out = bin()
        .args([
            "check",
            "--policy",
            policy.to_str().unwrap(),
            "--exe",
            "/tmp/not-registered-exploit",
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["decision"]["verdict"], "deny");
    assert_eq!(json["decision"]["enforced"], "deny");
}

#[test]
fn audit_mode_would_deny_but_does_not_enforce() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        r#"
version = 1
mode = "audit"

[[allow]]
name = "runc"
paths = ["/usr/bin/runc"]
"#,
    )
    .unwrap();

    let out = bin()
        .args([
            "check",
            "--policy",
            policy.to_str().unwrap(),
            "--exe",
            "/tmp/unknown",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("verdict:   Deny"));
    assert!(stdout.contains("enforced:  Allow"));
}

#[test]
fn ancestor_constraint_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        r#"
version = 1
mode = "enforce"

[[allow]]
name = "chrome-child"
paths = ["/usr/lib/chromium/chromium"]
ancestor_paths = ["/usr/bin/chromium"]
"#,
    )
    .unwrap();

    let ok = bin()
        .args([
            "check",
            "--policy",
            policy.to_str().unwrap(),
            "--exe",
            "/usr/lib/chromium/chromium",
            "--ancestor",
            "/usr/bin/chromium",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(ok.status.success());

    let bad = bin()
        .args([
            "check",
            "--policy",
            policy.to_str().unwrap(),
            "--exe",
            "/usr/lib/chromium/chromium",
            "--ancestor",
            "/tmp/malicious-launcher",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(3));
}

#[test]
fn renders_apparmor_to_directory() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("rendered");
    let out = bin()
        .args(["render", "apparmor", "--out-dir", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let profile = std::fs::read_to_string(out_dir.join("apparmor.d/userns-guard")).unwrap();
    assert!(profile.contains("profile \"userns-guard.usr.bin.runc\" \"/usr/bin/runc\""));
    let sysctl = std::fs::read_to_string(out_dir.join("sysctl.d/99-userns-guard.conf")).unwrap();
    assert!(sysctl.contains("apparmor_restrict_unprivileged_userns = 1"));
}
