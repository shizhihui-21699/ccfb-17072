use serde::Serialize;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: Option<String>,
    pub exe: Option<String>,
    pub exe_deleted: bool,
    pub cmdline: Vec<String>,
    pub uid: Option<u32>,
    pub cgroup: Option<String>,
    pub lsm_profile: Option<String>,
    /// starttime field from /proc/<pid>/stat, used with pid to defeat PID reuse.
    pub starttime_ticks: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcError {
    #[error("procfs inspection is only available on Linux")]
    Unsupported,
    #[error("process {pid} not found")]
    NotFound { pid: u32 },
    #[error("failed to read {path}: {source}")]
    Read {
        pid: u32,
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {reason}")]
    Parse {
        pid: u32,
        path: String,
        reason: String,
    },
}

#[cfg(target_os = "linux")]
pub fn snapshot(pid: u32) -> Result<ProcessNode, ProcError> {
    let root = PathBuf::from("/proc").join(pid.to_string());
    if !root.exists() {
        return Err(ProcError::NotFound { pid });
    }

    let status = std::fs::read_to_string(root.join("status")).map_err(|e| ProcError::Read {
        pid,
        path: format!("/proc/{pid}/status"),
        source: e,
    })?;
    let (ppid, uid) = parse_status(&status);

    let stat = std::fs::read_to_string(root.join("stat")).map_err(|e| ProcError::Read {
        pid,
        path: format!("/proc/{pid}/stat"),
        source: e,
    })?;
    let name = parse_comm(&stat);
    let starttime_ticks = parse_starttime(&stat);

    let cmdline_bytes = std::fs::read(root.join("cmdline")).unwrap_or_default();
    let cmdline = parse_cmdline(&cmdline_bytes);

    let (exe, exe_deleted) = match std::fs::read_link(root.join("exe")) {
        Ok(p) => {
            let mut s = p.to_string_lossy().to_string();
            let deleted = s.ends_with(" (deleted)");
            if deleted {
                s.truncate(s.len() - " (deleted)".len());
            }
            (Some(s), deleted)
        }
        Err(_) => (None, false),
    };

    let cgroup = std::fs::read_to_string(root.join("cgroup"))
        .ok()
        .and_then(|s| primary_cgroup_path(&s));

    let lsm_profile = std::fs::read_to_string(root.join("attr/current"))
        .ok()
        .map(|s| s.trim_matches(char::from(0)).trim().to_string())
        .filter(|s| !s.is_empty());

    Ok(ProcessNode {
        pid,
        ppid,
        name,
        exe,
        exe_deleted,
        cmdline,
        uid,
        cgroup,
        lsm_profile,
        starttime_ticks,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn snapshot(_pid: u32) -> Result<ProcessNode, ProcError> {
    Err(ProcError::Unsupported)
}

/// Return subject first, then parent, grandparent, ... up to `max_depth`.
#[cfg(target_os = "linux")]
pub fn call_chain(pid: u32, max_depth: usize) -> Result<Vec<ProcessNode>, ProcError> {
    let mut chain = Vec::new();
    let mut current = pid;
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..max_depth.max(1) {
        if !seen.insert(current) {
            break;
        }
        let node = snapshot(current)?;
        let Some(ppid) = node.ppid else {
            chain.push(node);
            break;
        };
        let stop = ppid == 0 || ppid == current;
        chain.push(node);
        if stop || ppid == 1 {
            if ppid == 1 {
                if let Ok(init) = snapshot(1) {
                    if chain.last().map(|n| n.pid) != Some(1) {
                        chain.push(init);
                    }
                }
            }
            break;
        }
        current = ppid;
    }
    Ok(chain)
}

#[cfg(not(target_os = "linux"))]
pub fn call_chain(_pid: u32, _max_depth: usize) -> Result<Vec<ProcessNode>, ProcError> {
    Err(ProcError::Unsupported)
}

pub fn parse_status(content: &str) -> (Option<u32>, Option<u32>) {
    let mut ppid = None;
    let mut uid = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|x| x.parse().ok());
        }
    }
    (ppid, uid)
}

pub fn parse_comm(stat: &str) -> Option<String> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open + 1 {
        return None;
    }
    Some(stat[open + 1..close].to_string())
}

pub fn parse_starttime(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 1..)?;
    // After comm, fields are state(3), ppid(4), ..., starttime(22).
    // Therefore starttime is zero-based token 19 in `rest`.
    rest.split_whitespace().nth(19)?.parse().ok()
}

pub fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

pub fn primary_cgroup_path(content: &str) -> Option<String> {
    let mut v1_fallback = None;
    for line in content.lines() {
        let mut parts = line.splitn(3, ':');
        let id = parts.next().unwrap_or_default();
        let controllers = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();
        if id == "0" && controllers.is_empty() && !path.is_empty() {
            return Some(path.to_string());
        }
        if v1_fallback.is_none() && !path.is_empty() {
            v1_fallback = Some(path.to_string());
        }
    }
    v1_fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let status = "Name:\trunc\nUmask:\t0022\nUid:\t0\t0\t0\t0\nPPid:\t1234\n";
        assert_eq!(parse_status(status), (Some(1234), Some(0)));
    }

    #[test]
    fn parses_comm_with_spaces_and_starttime() {
        let stat = "42 (chrome --type zygote) S 41 1 1 0 -1 4194304 1 0 0 0 10 20 0 0 20 0 1 0 1234567 200 0 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        assert_eq!(parse_comm(stat).as_deref(), Some("chrome --type zygote"));
        assert_eq!(parse_starttime(stat), Some(1234567));
    }

    #[test]
    fn parses_nul_cmdline() {
        assert_eq!(
            parse_cmdline(b"/usr/bin/runc\0run\0--root\0/x\0\0"),
            vec!["/usr/bin/runc", "run", "--root", "/x"]
        );
    }
}
