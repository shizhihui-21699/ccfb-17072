# Rollout and anti-breakage runbook

User namespace controls sit directly on the browser/container startup path. A
false positive does not produce a quiet failed request; Chromium/Electron may
crash at startup and Firefox/Flatpak may lose sandboxing or refuse to start.

## 1. Inventory before blocking

Run for at least one full business cycle, including scheduled jobs and desktop
login:

```sh
sudo userns-guard detect --json
sudo userns-guard snapshot <pid> --json
```

Collect every `unshare(CLONE_NEWUSER)`, `clone(CLONE_NEWUSER)`, and
`clone3` event through one of:

- BPF LSM/tracepoint ring buffer on modern kernels;
- AppArmor audit logs after loading `complain`/`default_allow` profiles;
- auditd/ftrace on older kernels where enforcement is not available.

For each event retain:

- PID/TGID and `/proc/<pid>/stat` start time (PID-reuse key);
- PPID chain up to PID 1;
- `exe`, deleted-exe state, `cmdline`;
- UID/GID and capabilities;
- cgroup/systemd unit/container ID;
- AppArmor/SELinux label;
- `dev:inode:generation` and SHA-256/package owner;
- kernel stack and optional user stack.

## 2. Build the allowlist from identities, not process names

Process names (`comm`) are attacker-controlled and truncated. Use this order:

1. exact executable path for human review;
2. resolved `dev:inode:generation` for kernel lookup;
3. package ownership and package version;
4. SHA-256, IMA appraisal, or fs-verity for content integrity;
5. cgroup/LSM profile/ancestor constraints to reduce broad helpers.

Run:

```sh
userns-guard preset > /etc/userns-guard/policy.toml
$EDITOR /etc/userns-guard/policy.toml
userns-guard validate --policy /etc/userns-guard/policy.toml
userns-guard reconcile --policy /etc/userns-guard/policy.toml --hash --json
```

Remove preset paths that do not exist in the server image. Register internal
browser forks, Electron apps, CI container tools, and alternate runc locations
explicitly.

## 3. Audit mode

Set:

```toml
mode = "audit"
failure_mode = "open"
default_action = "deny" # policy verdict is deny, but mode prevents EPERM
```

The CLI models this distinction:

```sh
userns-guard check --policy policy.toml --exe /tmp/unknown
# verdict:   Deny
# enforced:  Allow
```

Triage would-deny events. A sudden new path under `/tmp`, a deleted executable,
or a browser launched from an unusual ancestor is higher risk than a missing
distro path.

## 4. Canary enforcement

Pick one canary group:

- a single CI runner group;
- one Kubernetes node pool;
- a small desktop OU;
- a systemd slice/cgroup.

Switch only that group to:

```toml
mode = "enforce"
failure_mode = "closed"
```

Watch:

- browser startup/crash metrics;
- Flatpak/Snap launch success;
- rootless Podman/Buildah jobs;
- Kubernetes/containerd/runc creation latency and failures;
- deny-event volume and top call chains.

Keep a one-command kill switch that sets `mode = "audit"` or detaches the BPF
program. Policy reload must be atomic from the operator's point of view.

## 5. Broaden carefully

After a full update/reboot cycle:

1. expand canary from one host to a rack/OU;
2. then a percentage of nodes;
3. then all server hosts;
4. treat desktop images separately because browser variants are more diverse.

Do not immediately set the global sysctls to zero while testing selective
enforcement; that removes the exceptions needed to identify profile gaps.

## Known false-positive sources

- Chromium, Chrome, Edge, Brave, Electron, VS Code and Slack child/zygote
  processes using the same browser executable.
- Distribution-specific paths and Snap/Flatpak wrappers.
- Firefox content processes and ESR variants.
- `bwrap` invoked by Flatpak, GNOME thumbnailers, tests, and some package
  managers.
- Rootless Podman/Buildah: `podman`, `rootlesskit`, `runc`/`crun`, and
  `slirp4netns`/`pasta` can all appear in the chain.
- CI tools that bundle their own `runc` or `bwrap`.
- Applications that probe namespace support at startup and treat `EPERM` as a
  fatal error instead of falling back.

## Residual risk

This control removes the unprivileged namespace primitive from arbitrary
programs. It does not stop a correctly registered browser or runtime from being
exploited after it is allowed, and program identity alone cannot prevent code
injection into an allowed process. Combine it with timely kernel patches,
least privilege, AppArmor/SELinux confinement, seccomp, IMA/fs-verity, and
workload isolation.
