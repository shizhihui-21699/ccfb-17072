# BPF LSM reference program

`userns_guard.bpf.c` is the modern-kernel enforcement point. It is intentionally
small:

1. Attach to the sleepable `lsm.s/userns_create` LSM hook.
2. Resolve the current executable's `(s_dev, i_ino, i_generation)`.
3. Look that `dev:ino` key up in the pinned `allowed_inodes` map; the map
   value can optionally require an inode-generation match.
4. Emit one ring-buffer event with pid/tgid/ppid, uid/gid, cgroup, comm, inode
   key, and kernel stack id.
5. Return `0` in audit mode and `-EPERM` in enforce mode for misses.

## Kernel requirements

- Linux 6.1 or newer for the upstream `userns_create` LSM hook.
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_LSM=y`
- `bpf` must be present in `/sys/kernel/security/lsm`; often set with
  `lsm=lockdown,capability,landlock,yama,apparmor,bpf` or the distribution
  equivalent.

Distribution kernels may backport the hook even when `uname -r` reports an older
version. Use `userns-guard detect` and inspect BTF for
`bpf_lsm_userns_create` rather than relying only on version numbers.

## Build

On a Linux build host with `clang`, `llvm`, `libbpf-dev`, and `bpftool`:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
  -c bpf/userns_guard.bpf.c -o bpf/userns_guard.bpf.o
```

A production Rust agent should use Aya or `libbpf-rs` to load the object, pin
the maps under `/sys/fs/bpf/userns-guard/`, reconcile `policy.toml` into
`allowed_inodes`, and consume `guard_events`. The CLI in this repository
already implements policy validation, identity reconciliation, `/proc`
ancestry reconstruction, and JSONL event schema; the map loader is the
remaining host-specific integration piece.

## Why inode keys instead of path keys?

`/proc/<pid>/exe` and `mm->exe_file` already point at the resolved executable,
so symlinks and most `PATH` ambiguity are removed. Paths are still needed for
human review and initial registration, but the fast kernel lookup should use
`dev:ino`. The Rust reconciler also reads `i_generation` through
`FS_IOC_GETVERSION`; the BPF map value can require it to reduce stale-entry
risk after inode reuse. The Rust reconciler additionally verifies
SHA-256, package metadata, IMA appraisal, or fs-verity and refuse to insert a
key when that check fails.

A replaced executable normally gets a new inode. An in-place writable overwrite
can preserve the inode, which is why content hashing, package verification,
IMA/fs-verity, and read-only package-managed binaries remain necessary.

The BPF program encodes `s_dev` with the equivalent of `new_encode_dev()` so
the key's `dev` matches Rust/Unix `MetadataExt::dev()` (`st_dev`) produced by
`userns-guard reconcile`.
