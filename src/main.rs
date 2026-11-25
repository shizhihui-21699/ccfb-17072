use clap::{Parser, Subcommand};
use std::path::PathBuf;
use userns_guard::audit::AuditEvent;
use userns_guard::detect;
use userns_guard::identity::identify;
use userns_guard::policy::{DecisionRequest, Policy};
use userns_guard::presets::preset_policy;
use userns_guard::procfs::{call_chain, snapshot, ProcessNode};
use userns_guard::render::render_apparmor;

#[derive(Parser, Debug)]
#[command(
    name = "userns-guard",
    version,
    about = "Program-scoped user namespace creation control"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Detect kernel/LSM capabilities and recommended interception backend.
    Detect {
        #[arg(long)]
        json: bool,
    },
    /// Print built-in container-runtime and browser-sandbox path candidates.
    Preset {
        #[arg(long)]
        json: bool,
    },
    /// Validate a TOML policy.
    Validate {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Evaluate an executable or live PID against policy.
    Check(CheckArgs),
    /// Print a live process and its ancestor call chain.
    Snapshot {
        pid: u32,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 32)]
        max_depth: usize,
    },
    /// Evaluate a live PID and emit one userns-guard/event/v1 JSONL record.
    AuditPid(AuditPidArgs),
    /// Resolve policy paths to stable dev:inode/hash identities.
    Reconcile(ReconcileArgs),
    /// Render distribution MAC configuration.
    Render {
        #[command(subcommand)]
        format: RenderFormat,
    },
}

#[derive(clap::Args, Debug)]
struct CheckArgs {
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long, conflicts_with = "pid")]
    exe: Option<PathBuf>,
    #[arg(long)]
    pid: Option<u32>,
    /// Compute SHA-256 of an existing executable before evaluating.
    #[arg(long)]
    hash: bool,
    #[arg(long)]
    cgroup: Option<String>,
    #[arg(long)]
    lsm_profile: Option<String>,
    #[arg(long = "ancestor")]
    ancestors: Vec<String>,
    #[arg(long)]
    capable: bool,
    #[arg(long)]
    json: bool,
    /// Exit 3 for policy verdict Deny even when mode=audit would allow it.
    #[arg(long)]
    audit_strict: bool,
}

#[derive(clap::Args, Debug)]
struct AuditPidArgs {
    pid: u32,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long, default_value = "unshare")]
    syscall: String,
    /// Hex or decimal CLONE_* flags value, for example 0x10000000.
    #[arg(long)]
    flags: Option<String>,
}

#[derive(clap::Args, Debug)]
struct ReconcileArgs {
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    json: bool,
    /// Also hash every path. May read large browser binaries.
    #[arg(long)]
    hash: bool,
}

#[derive(Subcommand, Debug)]
enum RenderFormat {
    /// Render AppArmor default_allow profiles and sysctl drop-in.
    Apparmor {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Detect { json } => {
            let report = detect::detect();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("userns-guard capability report");
                println!("  os:                 {}", report.target_os);
                if let Some(r) = &report.kernel_release {
                    println!("  kernel:             {r}");
                }
                println!("  active LSMs:        {}", report.active_lsms.join(","));
                println!("  BPF LSM:            {}", report.bpf_lsm_enabled);
                println!("  BTF:                {}", report.btf_available);
                println!("  AppArmor:           {}", report.apparmor_securityfs);
                println!("  SELinux:            {}", report.selinux_securityfs);
                println!("  recommended:        {}", report.recommended_backend);
                println!(
                    "  global enforce:     {}",
                    report.global_enforcement_available
                );
                for c in &report.caveats {
                    println!("  caveat: {c}");
                }
            }
        }
        Command::Preset { json } => {
            let policy = preset_policy();
            if json {
                println!("{}", serde_json::to_string_pretty(&policy)?);
            } else {
                print!("{}", policy.to_toml_string()?);
            }
        }
        Command::Validate { policy, json } => {
            let p = load_policy(Some(&policy))?;
            p.validate()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "rules": p.allow.len() + p.deny.len()})
                );
            } else {
                println!(
                    "policy {} is valid ({} allow, {} deny rules; mode={:?})",
                    policy.display(),
                    p.allow.len(),
                    p.deny.len(),
                    p.mode
                );
            }
        }
        Command::Check(args) => return run_check(args),
        Command::Snapshot {
            pid,
            json,
            max_depth,
        } => {
            let chain = call_chain(pid, max_depth)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&chain)?);
            } else {
                for (i, node) in chain.iter().enumerate() {
                    let indent = "  ".repeat(i);
                    let exe = node.exe.as_deref().unwrap_or("<unknown>");
                    let comm = node.name.as_deref().unwrap_or("?");
                    println!("{indent}{} {} [{}]", node.pid, exe, comm);
                }
            }
        }
        Command::AuditPid(args) => return run_audit_pid(args),
        Command::Reconcile(args) => run_reconcile(args)?,
        Command::Render { format } => match format {
            RenderFormat::Apparmor {
                policy,
                out_dir,
                json,
            } => {
                let p = load_policy(policy.as_deref())?;
                p.validate()?;
                let files = render_apparmor(&p)?;
                if let Some(dir) = out_dir {
                    let mut written = Vec::new();
                    for f in &files {
                        let path = dir.join(&f.relative_path);
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(&path, &f.contents)?;
                        written.push(path);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&written)?);
                    } else {
                        for path in written {
                            println!("wrote {}", path.display());
                        }
                    }
                } else if json {
                    println!("{}", serde_json::to_string_pretty(&files)?);
                } else {
                    for f in &files {
                        println!("# --- {} ---", f.relative_path.display());
                        print!("{}", f.contents);
                    }
                }
            }
        },
    }
    Ok(())
}

fn live_decision_input(
    pid: u32,
) -> Result<(DecisionRequest, ProcessNode, Vec<ProcessNode>), Box<dyn std::error::Error>> {
    let subject = snapshot(pid)?;
    let chain = call_chain(pid, 32).unwrap_or_else(|_| vec![subject.clone()]);
    let req = DecisionRequest {
        exe_path: subject.exe.clone(),
        uid: subject.uid,
        cgroup: subject.cgroup.clone(),
        lsm_profile: subject.lsm_profile.clone(),
        ancestor_paths: chain
            .iter()
            .skip(1)
            .filter_map(|node| node.exe.clone())
            .collect(),
        ..DecisionRequest::default()
    };
    Ok((req, subject, chain))
}

fn parse_flags(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex flags {value:?}: {e}").into())
    } else {
        value
            .parse::<u64>()
            .map_err(|e| format!("invalid decimal flags {value:?}: {e}").into())
    }
}

fn run_audit_pid(args: AuditPidArgs) -> Result<(), Box<dyn std::error::Error>> {
    let policy = load_policy(args.policy.as_deref())?;
    policy.validate()?;

    let (mut req, subject, chain) = live_decision_input(args.pid)?;
    if let Some(exe) = req.exe_path.clone() {
        let should_hash = policy_has_digest_pins(&policy);
        let id = identify(&exe, should_hash)?;
        if id.exists {
            req.exe_dev = id.dev;
            req.exe_ino = id.ino;
            req.exe_generation = id.generation;
            req.exe_sha256 = id.sha256;
        }
    }

    let flags = args.flags.as_deref().map(parse_flags).transpose()?;
    let decision = policy.decide(&req);
    let event = AuditEvent::from_decision(&decision, subject, chain, Some(args.syscall), flags);
    let mut stdout = std::io::stdout().lock();
    event.write_jsonl(&mut stdout)?;

    if decision.enforced == userns_guard::Action::Deny {
        std::process::exit(3);
    }
    Ok(())
}

fn run_check(args: CheckArgs) -> Result<(), Box<dyn std::error::Error>> {
    let policy = load_policy(args.policy.as_deref())?;
    policy.validate()?;

    let mut req = DecisionRequest {
        cgroup: args.cgroup,
        lsm_profile: args.lsm_profile,
        ancestor_paths: args.ancestors,
        capable: args.capable,
        ..DecisionRequest::default()
    };

    let mut chain = Vec::new();
    if let Some(pid) = args.pid {
        let (live, _, live_chain) = live_decision_input(pid)?;
        chain = live_chain;
        req.exe_path = live.exe_path;
        req.uid = live.uid;
        if req.cgroup.is_none() {
            req.cgroup = live.cgroup;
        }
        if req.lsm_profile.is_none() {
            req.lsm_profile = live.lsm_profile;
        }
        if req.ancestor_paths.is_empty() {
            req.ancestor_paths = live.ancestor_paths;
        }
    }

    if let Some(exe) = args.exe {
        req.exe_path = Some(exe.to_string_lossy().to_string());
    }

    if let Some(exe) = req.exe_path.clone() {
        let should_hash = args.hash || policy_has_digest_pins(&policy);
        let id = identify(&exe, should_hash)?;
        if id.exists {
            req.exe_dev = id.dev;
            req.exe_ino = id.ino;
            req.exe_generation = id.generation;
            req.exe_sha256 = id.sha256;
        }
    }

    let decision = policy.decide(&req);
    if args.json {
        let out = serde_json::json!({
            "request": req,
            "decision": decision,
            "chain": chain,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("verdict:   {:?}", decision.verdict);
        println!("enforced:  {:?}", decision.enforced);
        if let Some(rule) = &decision.rule {
            println!("rule:      {rule}");
        }
        for reason in &decision.reasons {
            println!("reason:    {reason}");
        }
        if !chain.is_empty() {
            println!("call-chain:");
            for (i, node) in chain.iter().enumerate() {
                let indent = "  ".repeat(i + 1);
                println!(
                    "{indent}{} {}",
                    node.pid,
                    node.exe.as_deref().unwrap_or("<unknown>")
                );
            }
        }
    }

    if decision.enforced == userns_guard::Action::Deny
        || (args.audit_strict && decision.verdict == userns_guard::Verdict::Deny)
    {
        std::process::exit(3);
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ReconciledEntry {
    rule: String,
    path: PathBuf,
    exists: bool,
    dev: Option<u64>,
    ino: Option<u64>,
    generation: Option<u64>,
    sha256: Option<String>,
    ready_for_bpf_map: bool,
    warnings: Vec<String>,
}

fn run_reconcile(args: ReconcileArgs) -> Result<(), Box<dyn std::error::Error>> {
    let policy = load_policy(args.policy.as_deref())?;
    policy.validate()?;
    let mut entries = Vec::new();

    for rule in policy.allow.iter().filter(|r| r.enabled) {
        for path in &rule.paths {
            let hash = args.hash || !rule.sha256.is_empty();
            let id = identify(path, hash)?;
            let mut warnings = Vec::new();
            let mut ready = id.exists && id.dev.is_some() && id.ino.is_some();
            if !id.exists {
                warnings.push("path does not exist on this host".to_string());
                ready = false;
            }
            if !rule.sha256.is_empty() {
                match &id.sha256 {
                    Some(h) if rule.sha256.iter().any(|x| x.eq_ignore_ascii_case(h)) => {}
                    Some(h) => {
                        warnings.push(format!("sha256 mismatch: {h}"));
                        ready = false;
                    }
                    None => {
                        warnings.push("sha256 was not computed".to_string());
                        ready = false;
                    }
                }
            }
            entries.push(ReconciledEntry {
                rule: rule.name.clone(),
                path: path.clone(),
                exists: id.exists,
                dev: id.dev,
                ino: id.ino,
                generation: id.generation,
                sha256: id.sha256,
                ready_for_bpf_map: ready,
                warnings,
            });
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for e in &entries {
            let key = match (e.dev, e.ino) {
                (Some(d), Some(i)) => format!("{d}:{i}"),
                _ => "-".to_string(),
            };
            println!(
                "{:<24} {:<10} {} {}",
                e.rule,
                key,
                if e.ready_for_bpf_map {
                    "ready"
                } else {
                    "not-ready"
                },
                e.path.display()
            );
            for w in &e.warnings {
                println!("    warning: {w}");
            }
        }
    }
    Ok(())
}

fn load_policy(path: Option<&std::path::Path>) -> Result<Policy, Box<dyn std::error::Error>> {
    match path {
        Some(p) => {
            let text = std::fs::read_to_string(p)?;
            let policy = Policy::from_toml_str(&text)?;
            Ok(policy)
        }
        None => Ok(preset_policy()),
    }
}

fn policy_has_digest_pins(policy: &Policy) -> bool {
    policy
        .allow
        .iter()
        .chain(policy.deny.iter())
        .any(|r| !r.sha256.is_empty())
}
