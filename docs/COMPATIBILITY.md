# Interception-point compatibility

No single interception point covers every kernel. The safe design is a backend
trait with capability detection, not one hard-coded syscall hook.

| Environment | Preferred point | Granularity | Enforcement | Call chain | Notes |
|---|---|---:|---:|---:|---|
| Upstream Linux >= 6.1 with BPF LSM + BTF | `userns_create` LSM hook via BPF | executable inode, cgroup, LSM label, cred | yes, return `-EPERM` | ring event + `/proc` ancestry + stack id | Catches `unshare`, `clone`, and `clone3` after argument handling |
| Ubuntu 23.10 / 24.04 and HWE kernels with AppArmor userns mediation | AppArmor profile + `apparmor_restrict_unprivileged_userns` | executable attachment/profile | yes | AppArmor audit + agent enrichment | Use `flags=(default_allow)` plus `userns,` to avoid fully confining browsers |
| SELinux/new enough RHEL/Fedora kernels | `user_namespace:create` permission in SELinux policy | domain/type, executable label | yes | AVC + agent enrichment | Requires policy module and correct entrypoint/domain transitions |
| Older distro kernel with vendor backport | Distro AppArmor/SELinux hook or vendor sysctl/MAC extension | varies | often | audit | Detect the actual feature; do not infer from `uname` alone |
| Older upstream-like kernel < 6.1 without MAC backport | tracepoint/kprobe/audit observation only | process/exe | **no safe global deny** | yes | Upgrade or use a signed LSM; do not pretend tracing prevents creation |
| systemd service workloads on older kernels | `RestrictNamespaces=` / systemd seccomp | unit/cgroup | yes for unit | journal + agent | Excellent for registered services, not a system-wide executable policy by itself |
| PAM/launcher-managed user sessions | seccomp `USER_NOTIF` broker | per session/descendant; broker reads `/proc` | yes after filter is installed | full ancestry | Coverage depends on PAM/launcher installation; not automatic for PID 1 or pre-existing processes |
| `LD_PRELOAD` / ptrace | libc calls or syscall stops | launched process tree | partial | yes | Bypassable by static binaries/raw syscalls and unsafe as the primary boundary |

## Why not only seccomp?

A conventional seccomp filter can match `unshare` and the flags argument to
`clone`/`clone3`, but stock seccomp cannot make a policy decision from
`/proc/<pid>/exe`, SHA-256, package identity, or ancestor chain. Seccomp user
notification can delegate that decision to a privileged Rust broker, but the
filter still has to be installed for the target session or service tree. That
makes it a good compatibility fallback for PAM/systemd-managed workloads, not a
reliable way to retroactively cover every process on an arbitrary old server.

## Why not only `unprivileged_userns_clone=0` or `max_user_namespaces=0`?

These are global switches. They stop unknown local privilege-escalation proof of
concepts, but they also stop rootless Podman/Buildah, Flatpak/bwrap, Chromium,
Firefox and Electron sandboxes. They are useful as a defense-in-depth baseline
only after registered workloads have a selective MAC/LSM path.

## Handling kernel and distribution variance

1. Run `userns-guard detect --json` and record the result with host inventory.
2. Prefer BPF LSM when `userns_create` exists in BTF and `bpf` is active.
3. Otherwise use the distribution MAC backend that already ships and loads
   early: AppArmor or SELinux.
4. On unsupported kernels, run audit-only tracing and set a coarse sysctl only
   after workload testing. Plan a kernel upgrade; do not claim global
   per-program enforcement.
5. Test the exact kernel, userspace package versions, Snap/Flatpak variants,
   and container runtime configuration. Distribution backports frequently change
   the answer.
