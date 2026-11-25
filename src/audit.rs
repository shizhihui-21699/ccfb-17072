use crate::policy::{Action, Decision, Verdict};
use crate::procfs::ProcessNode;
use serde::Serialize;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub schema: &'static str,
    pub time_unix_secs: u64,
    pub event: &'static str,
    pub syscall: Option<String>,
    pub flags: Option<u64>,
    pub verdict: Verdict,
    /// Actual enforcement after policy mode is considered.
    pub enforced: Action,
    /// errno returned to the syscall when enforced=deny. EPERM is 1 on Linux.
    pub returned_errno: Option<i32>,
    pub rule: Option<String>,
    pub reasons: Vec<String>,
    pub subject: ProcessNode,
    pub call_chain: Vec<ProcessNode>,
}

impl AuditEvent {
    pub fn from_decision(
        decision: &Decision,
        subject: ProcessNode,
        call_chain: Vec<ProcessNode>,
        syscall: Option<String>,
        flags: Option<u64>,
    ) -> Self {
        let returned_errno = if decision.enforced == Action::Deny {
            Some(1)
        } else {
            None
        };
        Self {
            schema: "userns-guard/event/v1",
            time_unix_secs: now_unix_secs(),
            event: "user_namespace_create",
            syscall,
            flags,
            verdict: decision.verdict,
            enforced: decision.enforced,
            returned_errno,
            rule: decision.rule.clone(),
            reasons: decision.reasons.clone(),
            subject,
            call_chain,
        }
    }

    pub fn write_jsonl<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let line = serde_json::to_string(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")
    }
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
