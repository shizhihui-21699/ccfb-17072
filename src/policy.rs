use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Disabled,
    /// Record what would be denied, but do not return EPERM.
    #[default]
    Audit,
    /// Deny policy violations at the selected enforcement point.
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FailureMode {
    /// If the in-kernel policy cannot be read, allow. Availability-first.
    Open,
    /// If the in-kernel policy cannot be read, deny. Security-first after canary.
    #[default]
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub failure_mode: FailureMode,
    #[serde(default = "default_default_action")]
    pub default_action: Action,
    #[serde(default)]
    pub allow: Vec<Rule>,
    #[serde(default)]
    pub deny: Vec<Rule>,
}

fn default_default_action() -> Action {
    Action::Deny
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            mode: Mode::Audit,
            failure_mode: FailureMode::Closed,
            default_action: Action::Deny,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl Policy {
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn to_toml_string(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(self.version));
        }

        let mut names = BTreeSet::new();
        for rule in self.allow.iter().chain(self.deny.iter()) {
            if rule.name.trim().is_empty() {
                return Err(PolicyError::EmptyRuleName);
            }
            if !names.insert(rule.name.clone()) {
                return Err(PolicyError::DuplicateRuleName(rule.name.clone()));
            }
            rule.validate()?;
        }
        Ok(())
    }

    pub fn decide(&self, req: &DecisionRequest) -> Decision {
        if self.mode == Mode::Disabled {
            return Decision {
                verdict: Verdict::Allow,
                enforced: Action::Allow,
                rule: None,
                reasons: vec!["guard disabled".to_string()],
            };
        }

        let mut reasons = Vec::new();

        for rule in &self.deny {
            if rule.enabled_or_default() {
                let mut why = Vec::new();
                if rule.matches(req, &mut why) {
                    return self.finish(Verdict::Deny, Some(rule.name.clone()), why);
                }
                reasons.extend(why.into_iter().map(|w| format!("deny:{}: {w}", rule.name)));
            }
        }

        for rule in &self.allow {
            if rule.enabled_or_default() {
                let mut why = Vec::new();
                if rule.matches(req, &mut why) {
                    return self.finish(Verdict::Allow, Some(rule.name.clone()), why);
                }
                reasons.extend(why.into_iter().map(|w| format!("allow:{}: {w}", rule.name)));
            }
        }

        let verdict = match self.default_action {
            Action::Allow => Verdict::Allow,
            Action::Deny => Verdict::Deny,
        };
        let mut why = vec![format!(
            "no rule matched; default {:?}",
            self.default_action
        )];
        why.extend(reasons);
        self.finish(verdict, None, why)
    }

    fn finish(&self, verdict: Verdict, rule: Option<String>, reasons: Vec<String>) -> Decision {
        // Audit mode never turns a denial into EPERM. It is still important to
        // retain the policy verdict so logs can distinguish would-deny events.
        let enforced = match (self.mode, verdict) {
            (Mode::Enforce, Verdict::Deny) => Action::Deny,
            _ => Action::Allow,
        };
        Decision {
            verdict,
            enforced,
            rule,
            reasons,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IdentityStrength {
    /// Exact executable path only. Useful during audit; weak against replacement.
    Path,
    /// Path plus dev/inode/generation. Stable across rename, detects replacement.
    Inode,
    /// Explicit SHA-256/fs-verity/IMA measurement.
    #[default]
    Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Free-form labels such as "container-runtime" or "browser-sandbox".
    #[serde(default)]
    pub categories: Vec<String>,
    /// Exact executable paths. Globs are intentionally unsupported.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Optional SHA-256 allowlist. When non-empty, the request must present one.
    #[serde(default)]
    pub sha256: Vec<String>,
    /// Optional dev/inode pin. Most deployments populate this from the daemon,
    /// rather than writing it by hand.
    #[serde(default)]
    pub dev: Option<u64>,
    #[serde(default)]
    pub ino: Option<u64>,
    /// inode generation, when available.
    #[serde(default)]
    pub generation: Option<u64>,
    /// Prefixes such as `/system.slice/docker.service/` or `/user.slice/...`.
    #[serde(default)]
    pub cgroup_prefixes: Vec<String>,
    /// At least one ancestor executable must exactly match one of these paths.
    #[serde(default)]
    pub ancestor_paths: Vec<PathBuf>,
    /// AppArmor profile / SELinux context labels accepted by this rule.
    #[serde(default)]
    pub lsm_profiles: Vec<String>,
    /// Require the subject to have CAP_SYS_ADMIN in the relevant namespace.
    #[serde(default)]
    pub require_capable: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            categories: Vec::new(),
            paths: Vec::new(),
            sha256: Vec::new(),
            dev: None,
            ino: None,
            generation: None,
            cgroup_prefixes: Vec::new(),
            ancestor_paths: Vec::new(),
            lsm_profiles: Vec::new(),
            require_capable: false,
            reason: None,
        }
    }
}

impl Rule {
    pub fn enabled_or_default(&self) -> bool {
        // `enabled` defaults to true through serde for parsed files. This helper
        // also keeps manually constructed rules working if Default is derived.
        self.enabled
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.paths.is_empty()
            && self.cgroup_prefixes.is_empty()
            && self.lsm_profiles.is_empty()
            && self.ino.is_none()
        {
            return Err(PolicyError::RuleWithoutSelector(self.name.clone()));
        }

        for digest in &self.sha256 {
            let d = digest.trim();
            if d.len() != 64 || !d.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(PolicyError::InvalidSha256 {
                    rule: self.name.clone(),
                    value: digest.clone(),
                });
            }
        }

        if self.ino.is_some() && self.dev.is_none() {
            return Err(PolicyError::InodeRequiresDev(self.name.clone()));
        }

        Ok(())
    }

    fn matches(&self, req: &DecisionRequest, why: &mut Vec<String>) -> bool {
        let mut selector_matched = false;

        if !self.paths.is_empty() {
            if let Some(exe) = req.exe_path.as_deref() {
                let exe = normalize_path(exe);
                if self.paths.iter().any(|p| normalize_path(p) == exe) {
                    selector_matched = true;
                    why.push("executable path matched".to_string());
                } else {
                    why.push(format!("path {exe} not in rule"));
                    return false;
                }
            } else {
                why.push("request has no executable path".to_string());
                return false;
            }
        }

        if let Some(want_ino) = self.ino {
            match (req.exe_dev, req.exe_ino) {
                (Some(dev), Some(ino)) if self.dev == Some(dev) && want_ino == ino => {
                    selector_matched = true;
                    why.push("dev:inode matched".to_string());
                }
                _ => {
                    why.push("dev:inode missing or mismatch".to_string());
                    return false;
                }
            }
        }

        if !self.sha256.is_empty() {
            match req.exe_sha256.as_deref() {
                Some(h) if self.sha256.iter().any(|x| x.eq_ignore_ascii_case(h)) => {
                    why.push("sha256 matched".to_string());
                }
                Some(h) => {
                    why.push(format!("sha256 {h} is not pinned"));
                    return false;
                }
                None => {
                    why.push("sha256 required but unavailable".to_string());
                    return false;
                }
            }
        }

        if let Some(want_gen) = self.generation {
            if req.exe_generation != Some(want_gen) {
                why.push("inode generation mismatch".to_string());
                return false;
            }
        }

        if !self.cgroup_prefixes.is_empty() {
            let Some(cg) = req.cgroup.as_deref() else {
                why.push("cgroup required but unavailable".to_string());
                return false;
            };
            if !self
                .cgroup_prefixes
                .iter()
                .any(|prefix| cg.starts_with(prefix))
            {
                why.push(format!("cgroup {cg} does not match prefix"));
                return false;
            }
            why.push("cgroup prefix matched".to_string());
        }

        if !self.ancestor_paths.is_empty() {
            let ok = req.ancestor_paths.iter().any(|ancestor| {
                let a = normalize_path(ancestor);
                self.ancestor_paths
                    .iter()
                    .any(|wanted| normalize_path(wanted) == a)
            });
            if !ok {
                why.push("no required ancestor executable found".to_string());
                return false;
            }
            why.push("ancestor constraint matched".to_string());
        }

        if !self.lsm_profiles.is_empty() {
            let Some(label) = req.lsm_profile.as_deref() else {
                why.push("LSM profile required but unavailable".to_string());
                return false;
            };
            if !self
                .lsm_profiles
                .iter()
                .any(|wanted| wanted == label || label.starts_with(&format!("{wanted} ")))
            {
                why.push(format!("LSM profile {label} does not match"));
                return false;
            }
            why.push("LSM profile matched".to_string());
        }

        if self.require_capable && !req.capable {
            why.push("CAP_SYS_ADMIN was required".to_string());
            return false;
        }

        // A rule containing only constraints is not an allow selector. This
        // guards against an empty/over-broad TOML table becoming allow-all.
        if !selector_matched && !self.paths.is_empty() {
            // Path branch sets selector_matched on success.
            selector_matched = true;
        }
        if !selector_matched && self.paths.is_empty() && self.ino.is_none() {
            selector_matched = !self.cgroup_prefixes.is_empty() || !self.lsm_profiles.is_empty();
        }

        selector_matched
    }
}

fn normalize_path<P: AsRef<Path>>(p: P) -> String {
    // Policy and /proc paths are absolute. Do not canonicalize here: the file
    // may not exist on the machine evaluating a rendered policy. Only normalize
    // repeated separators and trailing slash-like differences.
    let s = p.as_ref().to_string_lossy();
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for c in s.chars() {
        if c == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            out.push(c);
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub exe_path: Option<String>,
    pub exe_sha256: Option<String>,
    pub exe_dev: Option<u64>,
    pub exe_ino: Option<u64>,
    pub exe_generation: Option<u64>,
    pub cgroup: Option<String>,
    pub lsm_profile: Option<String>,
    #[serde(default)]
    pub ancestor_paths: Vec<String>,
    pub uid: Option<u32>,
    #[serde(default)]
    pub capable: bool,
    pub syscall: Option<String>,
    pub flags: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub enforced: Action,
    pub rule: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("unsupported policy version {0}; expected {POLICY_VERSION}")]
    UnsupportedVersion(u32),
    #[error("rule name must not be empty")]
    EmptyRuleName,
    #[error("duplicate rule name: {0}")]
    DuplicateRuleName(String),
    #[error("rule {0} needs at least one selector (paths, inode, cgroup or LSM profile)")]
    RuleWithoutSelector(String),
    #[error("rule {rule} has invalid SHA-256 value {value:?}")]
    InvalidSha256 { rule: String, value: String },
    #[error("rule {0} pins ino without dev")]
    InodeRequiresDev(String),
}
