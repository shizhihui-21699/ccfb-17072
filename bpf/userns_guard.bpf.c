// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * userns-guard modern-kernel enforcement program.
 *
 * Attach this as an LSM BPF program to the upstream userns_create hook
 * (merged for Linux v6.1). It catches unshare(2), clone(2), and clone3(2)
 * because all successful paths eventually invoke security_userns_create().
 *
 * Build on a Linux host with BTF:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
 *   clang -g -O2 -target bpf -D__TARGET_ARCH_$(uname -m) \
 *         -c bpf/userns_guard.bpf.c -o bpf/userns_guard.bpf.o
 *
 * The Rust control plane reconciles policy.toml into allowed_inodes and reads
 * events from the ring buffer, then enriches them with /proc ancestry.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

#define GUARD_MODE_DISABLED 0
#define GUARD_MODE_AUDIT 1
#define GUARD_MODE_ENFORCE 2

struct inode_key {
	__u64 dev;
	__u64 ino;
};

struct allowed_value {
	__u32 rule_id;
	__u32 generation;
	/* bit 0: require i_generation to match generation. */
	__u32 flags;
	__u32 pad;
};

struct guard_config {
	__u32 mode;
	/* If non-zero, deny when an audit event cannot be enqueued. */
	__u32 deny_on_ringbuf_failure;
};

struct guard_event {
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 exe_generation;
	__s32 kernel_stack_id;
	__u64 cgroup_id;
	struct inode_key exe;
	__u32 rule_id;
	__u8 allowed;
	__u8 enforced_deny;
	__u16 event_pad;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct inode_key);
	__type(value, struct allowed_value);
} allowed_inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_config);
} guard_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} guard_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
} guard_stacks SEC(".maps");

static __always_inline __u32 guard_encode_dev(__u32 dev)
{
	/* Match Linux's new_encode_dev()/userspace st_dev encoding. */
	const __u32 minor_bits = 20;
	const __u32 minor_mask = (1U << minor_bits) - 1;
	__u32 major = dev >> minor_bits;
	__u32 minor = dev & minor_mask;

	return (minor & 0xff) | (major << 8) |
	       ((minor & 0x000fff00U) << 12);
}

static __always_inline int read_exe_key(struct inode_key *key,
					__u32 *generation, __u32 *ppid)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent;
	struct mm_struct *mm;
	struct file *exe_file;
	struct inode *inode;
	struct super_block *sb;

	if (!task)
		return -1;

	parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		*ppid = BPF_CORE_READ(parent, tgid);

	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return -1;

	exe_file = BPF_CORE_READ(mm, exe_file);
	if (!exe_file)
		return -1;

	inode = BPF_CORE_READ(exe_file, f_inode);
	if (!inode)
		return -1;

	key->ino = BPF_CORE_READ(inode, i_ino);
	*generation = BPF_CORE_READ(inode, i_generation);

	sb = BPF_CORE_READ(inode, i_sb);
	if (sb) {
		__u32 raw_dev = BPF_CORE_READ(sb, s_dev);

		key->dev = guard_encode_dev(raw_dev);
	}

	return 0;
}

/*
 * userns_create is exposed as a sleepable BPF LSM hook. The ".s" section
 * suffix tells libbpf/Aya to load the program with BPF_F_SLEEPABLE.
 */
SEC("lsm.s/userns_create")
int BPF_PROG(userns_guard_create, const struct cred *cred)
{
	__u32 zero = 0;
	struct guard_config *cfg;
	struct inode_key key = {};
	struct allowed_value *allow;
	struct guard_event *event;
	__u64 pid_tgid;
	__u64 uid_gid;
	__u32 ppid = 0;
	__u32 generation = 0;
	__u32 rule_id = 0;
	int have_exe;
	int allowed = 0;
	int ret = 0;

	(void)cred;
	cfg = bpf_map_lookup_elem(&guard_config_map, &zero);
	if (cfg && cfg->mode == GUARD_MODE_DISABLED)
		return 0;

	have_exe = read_exe_key(&key, &generation, &ppid);
	if (have_exe == 0) {
		allow = bpf_map_lookup_elem(&allowed_inodes, &key);
		if (allow &&
		    (!(allow->flags & 1) || allow->generation == generation)) {
			allowed = 1;
			rule_id = allow->rule_id;
		}
	}

	/*
	 * In enforce mode every unresolved or unregistered executable misses.
	 * Audit mode returns zero below and relies on the ring event.
	 */
	if (!allowed && cfg && cfg->mode == GUARD_MODE_ENFORCE)
		ret = -EPERM;

	event = bpf_ringbuf_reserve(&guard_events, sizeof(*event), 0);
	if (!event) {
		if (cfg && cfg->mode == GUARD_MODE_ENFORCE &&
		    cfg->deny_on_ringbuf_failure)
			ret = -EPERM;
		goto decision;
	}

	__builtin_memset(event, 0, sizeof(*event));
	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	event->pid = pid_tgid >> 32;
	event->tgid = pid_tgid & 0xffffffff;
	event->ppid = ppid;
	event->uid = uid_gid & 0xffffffff;
	event->gid = uid_gid >> 32;
	event->exe_generation = generation;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->kernel_stack_id = bpf_get_stackid(ctx, &guard_stacks, 0);
	event->exe = key;
	event->allowed = allowed;
	event->enforced_deny = ret == -EPERM;
	event->rule_id = rule_id;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);

decision:
	/* An explicit ring-buffer failure policy can also override allows. */
	if (ret == -EPERM)
		return ret;
	if (allowed)
		return 0;
	if (cfg && cfg->mode == GUARD_MODE_ENFORCE)
		return -EPERM;
	/* No config map or audit mode: fail open during initial bring-up. */
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
