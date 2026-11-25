# userns-guard

`userns-guard` is a Rust policy core and operator CLI for controlling which
programs may create Linux user namespaces. It is designed for company servers
where only container runtimes, rootless image-build tools, and browser/desktop
sandboxes should need `CLONE_NEWUSER`.

The repository currently provides a tested, cross-platform policy and
diagnostics core plus a modern BPF LSM reference program and an AppArmor
backend renderer:

- exact-path, SHA-256, `dev:inode`, cgroup, LSM-label and ancestor-chain rules;
- `disabled` / `audit` / `enforce` modes where the policy verdict is retained
  even when audit mode does not return `EPERM`;
- built-in presets for runc/crun/youki, containerd shims, Podman/rootlesskit,
  LXC, bwrap/Flatpak, Chrome/Chromium/Firefox/Edge/Brave;
- Linux capability detection across BPF LSM, AppArmor and SELinux;
- `/proc` process and ancestor-call-chain reconstruction with PID-reuse
  metadata;
- JSONL event schema for ring-buffer/audit enrichment;
- AppArmor `flags=(default_allow)` profile and sysctl rendering for Ubuntu
  23.10/24.04-style selective userns mediation;
- a reference `userns_create` BPF LSM program in [`bpf/`](bpf/).

The production map-loading/ring-buffer consumer is intentionally documented as
the Linux-specific integration point; see
[`bpf/README.md`](bpf/README.md). The policy, identity and audit pieces it
needs are already implemented and tested.

## Why this is not a one-line sysctl

Global switches such as `kernel.unprivileged_userns_clone=0` or
`user.max_user_namespaces=0` reduce exploit surface but break rootless
containers, Flatpak/bwrap and browser sandboxes. Conversely, intercepting only
`unshare(2)` misses `clone(2)` and `clone3(2)` callers.

The canonical modern interception point is the `userns_create` LSM hook merged
for Linux 6.1. Distribution kernels may backport equivalent AppArmor or
SELinux support. Older kernels without a vendor backport do **not** provide a
safe global per-executable deny point; tracing can record but not atomically
prevent creation. See [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

## Build and test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

The Rust core and CLI also build and test on macOS/other development hosts;
Linux-only `/proc` and syscall/LSM features return a clear unsupported error
outside Linux.

## Quick start

Inspect the current host's best interception backend:

```sh
userns-guard detect
userns-guard detect --json
```

Print and customize built-in candidates:

```sh
userns-guard preset > /etc/userns-guard/policy.toml
$EDITOR /etc/userns-guard/policy.toml
userns-guard validate --policy /etc/userns-guard/policy.toml
```

Evaluate one executable:

```sh
userns-guard check \
  --policy /etc/userns-guard/policy.toml \
  --exe /usr/bin/runc

userns-guard check \
  --policy /etc/userns-guard/policy.toml \
  --exe /tmp/some-poc \
  --json
```

Evaluate a live process and reconstruct its ancestor chain:

```sh
sudo userns-guard check --pid 12345 --json
userns-guard snapshot 12345 --json
```

Resolve paths to kernel-map identities:

```sh
userns-guard reconcile \
  --policy /etc/userns-guard/policy.toml \
  --hash --json
```

## AppArmor backend

On Ubuntu 23.10+, 24.04, or a compatible AppArmor ABI 4.0 host:

```sh
userns-guard render apparmor \
  --policy /etc/userns-guard/policy.toml \
  --out-dir build

sudo cp build/apparmor.d/userns-guard \
        /etc/apparmor.d/userns-guard
sudo cp build/sysctl.d/99-userns-guard.conf \
        /etc/sysctl.d/99-userns-guard.conf
sudo apparmor_parser -r /etc/apparmor.d/userns-guard
sudo sysctl --system
```

The generated profile uses `flags=(default_allow)` and adds only `userns,`,
following Ubuntu's low-breakage pattern for applications that should remain
otherwise unconfined. Review and test it before enforcement.

## Example policy

See [`config/policy.example.toml`](config/policy.example.toml). The important
semantics are:

```toml
version = 1
mode = "audit"       # disabled | audit | enforce
failure_mode = "open"
default_action = "deny"

[[allow]]
name = "oci-runc"
paths = ["/usr/bin/runc", "/usr/bin/crun"]
# sha256 = ["..."]
# cgroup_prefixes = ["/system.slice/containerd.service/"]
```

An unknown executable in audit mode returns policy verdict `Deny` but enforced
action `Allow`; this lets operators build the allowlist without breaking
browsers. In enforce mode the BPF LSM or MAC backend returns `EPERM`.

## Logged call chain

Events use the `userns-guard/event/v1` JSON schema in
[`src/audit.rs`](src/audit.rs). Each event includes the decision/reason,
subject process, ancestor chain, UID, cgroup, LSM label, executable identity,
syscall/flags and optional kernel stack id. PID plus
`/proc/<pid>/stat` start time is used to reduce PID-reuse confusion.

## Safe rollout

Do not switch a server fleet directly to enforce. Follow
[`docs/ROLLOUT.md`](docs/ROLLOUT.md): inventory, audit one business cycle, pin
identities, canary one cgroup/node/desktop group, watch browser and container
startup metrics, then broaden with a fast audit/detach kill switch.

## Security boundaries

This control meaningfully raises the bar against local privilege-escalation
exploit preconditions launched from arbitrary programs. It is not a sandbox
for allowed programs and does not stop exploitation of an allowed browser or
runtime after code execution inside it. Generic helpers such as `/usr/bin/bwrap`
should be constrained by ancestor, cgroup, path, package and MAC-label rules.
A compromised root user can usually unload an unprotected BPF program or edit
policy; protect the agent, pinned maps and policy file with systemd hardening,
IMA and appropriate MAC policy.
