use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    pub target_os: String,
    pub linux: bool,
    pub kernel_release: Option<String>,
    pub kernel_version: Option<(u32, u32, u32)>,
    pub active_lsms: Vec<String>,
    pub bpf_lsm_enabled: bool,
    pub btf_available: bool,
    pub apparmor_securityfs: bool,
    pub apparmor_restrict_userns: Option<i64>,
    pub apparmor_restrict_unconfined: Option<i64>,
    pub selinux_securityfs: bool,
    pub unprivileged_userns_clone: Option<i64>,
    pub max_user_namespaces: Option<i64>,
    pub recommended_backend: String,
    pub global_enforcement_available: bool,
    pub caveats: Vec<String>,
}

pub fn detect() -> CapabilityReport {
    let linux = cfg!(target_os = "linux");
    let kernel_release = if linux {
        read_trim("/proc/sys/kernel/osrelease")
    } else {
        None
    };
    let kernel_version = kernel_release.as_deref().and_then(parse_kernel_version);
    let lsm_raw = if linux {
        read_trim("/sys/kernel/security/lsm").unwrap_or_default()
    } else {
        String::new()
    };
    let active_lsms: Vec<String> = lsm_raw
        .split([',', '\n'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let bpf_lsm_enabled = active_lsms.iter().any(|x| x == "bpf");
    let btf_available = linux && Path::new("/sys/kernel/btf/vmlinux").exists();
    let apparmor_securityfs = linux && Path::new("/sys/kernel/security/apparmor").exists();
    let selinux_securityfs = linux && Path::new("/sys/fs/selinux").exists();
    let apparmor_restrict_userns =
        read_i64("/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    let apparmor_restrict_unconfined =
        read_i64("/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined");
    let unprivileged_userns_clone = read_i64("/proc/sys/kernel/unprivileged_userns_clone");
    let max_user_namespaces = read_i64("/proc/sys/user/max_user_namespaces");

    let mut caveats = Vec::new();
    let (recommended_backend, global_enforcement_available) = if !linux {
        (
            "unsupported-host: build and run this component on Linux".to_string(),
            false,
        )
    } else if bpf_lsm_enabled
        && btf_available
        && kernel_version.map(|v| v >= (6, 1, 0)).unwrap_or(false)
    {
        (
            "bpf-lsm: attach to userns_create and key allowlist by executable inode".to_string(),
            true,
        )
    } else if apparmor_restrict_userns.is_some() {
        caveats.push(
            "Use flags=(default_allow) AppArmor profiles for registered binaries and enable both apparmor_restrict sysctls."
                .to_string(),
        );
        (
            "apparmor: per-path default_allow profiles + restricted unprivileged userns"
                .to_string(),
            true,
        )
    } else if selinux_securityfs && kernel_version.map(|v| v >= (6, 1, 0)).unwrap_or(false) {
        caveats.push(
            "SELinux exposes the user_namespace:create hook on new enough kernels; ship a CIL policy and label entry programs."
                .to_string(),
        );
        (
            "selinux: user_namespace create policy module".to_string(),
            true,
        )
    } else {
        caveats.push(
            "No stable upstream global per-executable deny hook was detected. Prefer upgrading to >=6.1 with CONFIG_BPF_LSM=y and bpf in the LSM list."
                .to_string(),
        );
        caveats.push(
            "On older kernels, distribution AppArmor/SELinux backports may still work; otherwise use audit/tracepoint observation plus PAM/systemd/seccomp-unotify scoped coverage."
                .to_string(),
        );
        caveats.push(
            "Do not treat LD_PRELOAD or ptrace as a global boundary: raw syscalls, static binaries and early processes bypass them."
                .to_string(),
        );
        (
            "upgrade-or-distribution-mac; trace-only fallback".to_string(),
            false,
        )
    };

    if linux && kernel_version.map(|v| v < (6, 1, 0)).unwrap_or(true) {
        caveats.push(
            "Kernel <6.1 lacks the canonical userns_create LSM hook merged for v6.1; distribution backports may expose an equivalent."
                .to_string(),
        );
    }
    if bpf_lsm_enabled && !btf_available {
        caveats.push(
            "BPF LSM is listed but /sys/kernel/btf/vmlinux is missing; CO-RE loading will fail."
                .to_string(),
        );
    }
    if unprivileged_userns_clone == Some(0) {
        caveats.push(
            "kernel.unprivileged_userns_clone=0 is coarse: it cannot allow individual browser/container binaries."
                .to_string(),
        );
    }
    if max_user_namespaces == Some(0) {
        caveats.push(
            "/proc/sys/user/max_user_namespaces=0 is also coarse and may block registered rootless sandboxes."
                .to_string(),
        );
    }

    CapabilityReport {
        target_os: std::env::consts::OS.to_string(),
        linux,
        kernel_release,
        kernel_version,
        active_lsms,
        bpf_lsm_enabled,
        btf_available,
        apparmor_securityfs,
        apparmor_restrict_userns,
        apparmor_restrict_unconfined,
        selinux_securityfs,
        unprivileged_userns_clone,
        max_user_namespaces,
        recommended_backend,
        global_enforcement_available,
        caveats,
    }
}

pub fn parse_kernel_version(release: &str) -> Option<(u32, u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_i64(path: &str) -> Option<i64> {
    read_trim(path).and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::parse_kernel_version;

    #[test]
    fn parses_distribution_kernel_releases() {
        assert_eq!(parse_kernel_version("6.8.0-48-generic"), Some((6, 8, 0)));
        assert_eq!(parse_kernel_version("5.15.0-122-el9"), Some((5, 15, 0)));
        assert_eq!(parse_kernel_version("6.1"), Some((6, 1, 0)));
    }
}
