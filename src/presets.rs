use crate::policy::{Policy, Rule};
use std::path::PathBuf;

/// Conservative path candidates for common runtimes and browser sandboxes.
///
/// These are not unconditional recommendations to trust every path. Operators
/// should validate package ownership/hashes and remove entries that do not exist
/// in the target image before switching from audit to enforce.
pub fn preset_policy() -> Policy {
    Policy {
        allow: vec![
            Rule {
                name: "oci-runtimes".to_string(),
                categories: vec!["container-runtime".to_string()],
                paths: paths(&[
                    "/usr/bin/runc",
                    "/usr/sbin/runc",
                    "/usr/local/sbin/runc",
                    "/usr/bin/crun",
                    "/usr/bin/youki",
                ]),
                reason: Some("OCI runtimes configure namespaces before container exec".to_string()),
                ..Rule::default()
            },
            Rule {
                name: "containerd-shim".to_string(),
                categories: vec!["container-runtime".to_string()],
                paths: paths(&[
                    "/usr/bin/containerd-shim-runc-v2",
                    "/usr/local/bin/containerd-shim-runc-v2",
                ]),
                ..Rule::default()
            },
            Rule {
                name: "rootless-container-stack".to_string(),
                categories: vec!["container-runtime".to_string()],
                paths: paths(&[
                    "/usr/bin/podman",
                    "/usr/bin/rootlesskit",
                    "/usr/bin/slirp4netns",
                    "/usr/bin/pasta",
                    "/usr/bin/lxc-start",
                    "/usr/bin/lxc-user-nic",
                ]),
                reason: Some(
                    "Rootless podman/lxc stacks call unshare before calling the OCI runtime"
                        .to_string(),
                ),
                ..Rule::default()
            },
            Rule {
                name: "bubblewrap-flatpak".to_string(),
                categories: vec!["desktop-sandbox".to_string()],
                paths: paths(&["/usr/bin/bwrap", "/usr/bin/flatpak"]),
                reason: Some(
                    "bwrap is generic; constrain it by ancestor/cgroup where possible".to_string(),
                ),
                ..Rule::default()
            },
            Rule {
                name: "google-chrome".to_string(),
                categories: vec!["browser-sandbox".to_string()],
                paths: paths(&[
                    "/opt/google/chrome/chrome",
                    "/opt/google/chrome/chrome-sandbox",
                ]),
                ..Rule::default()
            },
            Rule {
                name: "chromium".to_string(),
                categories: vec!["browser-sandbox".to_string()],
                paths: paths(&[
                    "/usr/bin/chromium",
                    "/usr/bin/chromium-browser",
                    "/usr/lib/chromium/chromium",
                    "/usr/lib/chromium/chrome-sandbox",
                    "/usr/lib/chromium-browser/chromium-browser",
                ]),
                ..Rule::default()
            },
            Rule {
                name: "firefox".to_string(),
                categories: vec!["browser-sandbox".to_string()],
                paths: paths(&[
                    "/usr/bin/firefox",
                    "/usr/lib/firefox/firefox",
                    "/usr/lib/firefox/firefox-bin",
                    "/usr/lib/firefox-esr/firefox-esr",
                ]),
                ..Rule::default()
            },
            Rule {
                name: "microsoft-edge".to_string(),
                categories: vec!["browser-sandbox".to_string()],
                paths: paths(&[
                    "/opt/microsoft/msedge/msedge",
                    "/opt/microsoft/msedge/msedge-sandbox",
                ]),
                ..Rule::default()
            },
            Rule {
                name: "brave".to_string(),
                categories: vec!["browser-sandbox".to_string()],
                paths: paths(&[
                    "/opt/brave.com/brave/brave",
                    "/opt/brave.com/brave/chrome-sandbox",
                ]),
                ..Rule::default()
            },
        ],
        ..Policy::default()
    }
}

fn paths(xs: &[&str]) -> Vec<PathBuf> {
    xs.iter().map(PathBuf::from).collect()
}

#[cfg(test)]
mod tests {
    use super::preset_policy;

    #[test]
    fn presets_validate() {
        let p = preset_policy();
        p.validate().unwrap();
        assert!(p.allow.len() >= 8);
    }
}
