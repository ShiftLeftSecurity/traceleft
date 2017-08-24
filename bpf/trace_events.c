#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/fs.h>
#include <uapi/linux/bpf.h>
#pragma clang diagnostic pop
#include "bpf_helpers.h"

#include "events-map.h"
#include "program-id-map.h"

/* This is a set of PIDs (technically TGIDs) to ignore when tracking. Values
 * are ignored. It is populated by userspace. */
struct bpf_map_def SEC("maps/untracked_pids") untracked_pids = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8),
	.max_entries = 64,
	.map_flags = 0,
};

/* Syscalls */

struct bpf_map_def SEC("maps/handle_open_progs") handle_open_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_open_progs_ret") handle_open_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_close_progs") handle_close_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_close_progs_ret") handle_close_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_read_progs") handle_read_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_read_progs_ret") handle_read_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_write_progs") handle_write_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_write_progs_ret") handle_write_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_mkdir_progs") handle_mkdir_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_mkdir_progs_ret") handle_mkdir_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_mkdirat_progs") handle_mkdirat_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_mkdirat_progs_ret") handle_mkdirat_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchown_progs") handle_fchown_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchown_progs_ret") handle_fchown_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchownat_progs") handle_fchownat_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchownat_progs_ret") handle_fchownat_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmod_progs") handle_fchmod_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmod_progs_ret") handle_fchmod_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmodat_progs") handle_fchmodat_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmodat_progs_ret") handle_fchmodat_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chmod_progs") handle_chmod_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chmod_progs_ret") handle_chmod_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chown_progs") handle_chown_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chown_progs_ret") handle_chown_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

/* This is a key/value store with the keys being pid_tgid and values being
 * fd_install_t.
 *
 * It is populated by userspace and read by the eBPF program to know which pids
 * to watch.
 * */
struct bpf_map_def SEC("maps/file_events_pids_to_watch") file_events_pids_to_watch = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = 0,
};

typedef struct {
	unsigned long fd;
	struct file *file;
} fd_install_t;

/* This is a key/value store with the keys being pid_tgid and values being
 * fd_install_t.
 *
 * It is used to keep context between kprobe/fd_install and
 * kretprobe/fd_install.
 * */
struct bpf_map_def SEC("maps/fdinstall_args") fdinstall_args = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(fd_install_t),
	.max_entries = 1024,
};

typedef struct {
	common_event_t common;
	u64 fd;
	u64 ino;
	u64 major;
	u64 minor;
} file_event_t;

SEC("kprobe/fd_install")
int kprobe__fd_install(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u32 tgid = pid >> 32;
	u32 *exists = NULL;
	unsigned long fd = (unsigned long) PT_REGS_PARM1(ctx);
	struct file *f = (struct file *) PT_REGS_PARM2(ctx);

	fd_install_t fd_i = {
		.fd = fd,
		.file = f,
	};

	exists = bpf_map_lookup_elem(&file_events_pids_to_watch, &tgid);
	if (exists == NULL || !*exists) {
		return 0;
	}

	bpf_map_update_elem(&fdinstall_args, &pid, &fd_i, BPF_ANY);

	return 0;
}

SEC("kretprobe/fd_install")
int kretprobe__fd_install(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u32 cpu = bpf_get_smp_processor_id();
	fd_install_t *fd_ip;
	fd_ip = bpf_map_lookup_elem(&fdinstall_args, &pid);
	if (fd_ip == NULL) {
		return 0; // missed entry
	}
	bpf_map_delete_elem(&fdinstall_args, &pid);

	fd_install_t fd_i;
	bpf_probe_read(&fd_i, sizeof(fd_i), fd_ip);

	struct inode *f_inode;
	unsigned long i_ino;
	struct super_block *sb = NULL;
	dev_t s_dev;

	bpf_probe_read(&f_inode, sizeof(f_inode), &fd_i.file->f_inode);
	bpf_probe_read(&i_ino, sizeof(i_ino), &f_inode->i_ino);
	bpf_probe_read(&sb, sizeof(sb), &f_inode->i_sb);
	bpf_probe_read(&s_dev, sizeof(s_dev), &sb->s_dev);

	u64 *program_id = bpf_map_lookup_elem(&program_id_per_pid, &pid);

	file_event_t ev = {
		.common = {
			.timestamp = bpf_ktime_get_ns(),
			.program_id = program_id ? *program_id : 0,
			.tgid = pid >> 32,
			.ret = 0,
			.name = "fd_install",
			.hash = 0,
		},
		.fd = fd_i.fd,
		.ino = i_ino,
		.major = MAJOR(s_dev),
		.minor = MINOR(s_dev),
	};

	bpf_perf_event_output(ctx, &events, cpu, &ev, sizeof(ev));

	return 0;
}

SEC("kprobe/SyS_read")
int kprobe__sys_read(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_read_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_read_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_read")
int kretprobe__sys_read(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_read_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_read_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_write")
int kprobe__sys_write(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_write_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_write_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_write")
int kretprobe__handle_write(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_write_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_write_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_open")
int kprobe__handle_open(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_open_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_open_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_open")
int kretprobe__handle_open(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_open_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_open_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_close")
int kprobe__handle_close(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_close_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_close_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_close")
int kretprobe__handle_close(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_close_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_close_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_mkdir")
int kprobe__handle_mkdir(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_mkdir_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_mkdir_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_mkdir")
int kretprobe__handle_mkdir(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_mkdir_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_mkdir_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_mkdirat")
int kprobe__handle_mkdirat(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_mkdirat_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_mkdirat_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_mkdirat")
int kretprobe__handle_mkdirat(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_mkdirat_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_mkdirat_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_chown")
int kprobe__handle_chown(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_chown_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_chown_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_chown")
int kretprobe__handle_chwon(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_chown_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_chown_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_fchown")
int kprobe__handle_fchown(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchown_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchown_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_fchown")
int kretprobe__handle_fchwon(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchown_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchown_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_fchownat")
int kprobe__handle_fchownat(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchownat_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchownat_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_fchownat")
int kretprobe__handle_fchownat(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchownat_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchownat_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_chmod")
int kprobe__handle_chmod(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_chmod_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_chmod_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_chmod")
int kretprobe__handle_chmod(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_chmod_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_chmod_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_fchmod")
int kprobe__handle_fchmod(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchmod_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchmod_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_fchmod")
int kretprobe__handle_fchmod(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchmod_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchmod_progs_ret, 0);

	return 0;
}

SEC("kprobe/SyS_fchmodat")
int kprobe__handle_fchmodat(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchmodat_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchmodat_progs, 0);

	return 0;
}

SEC("kretprobe/SyS_fchmodat")
int kretprobe__handle_fchmodat(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_fchmodat_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_fchmodat_progs_ret, 0);

	return 0;
}

/* Network Events */

struct bpf_map_def SEC("maps/handle_tcp_v4_connect_progs") handle_tcp_v4_connect_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_v4_connect_progs_ret") handle_tcp_v4_connect_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_v6_connect_progs") handle_tcp_v6_connect_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_v6_connect_progs_ret") handle_tcp_v6_connect_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_inet_csk_accept_progs") handle_inet_csk_accept_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_inet_csk_accept_progs_ret") handle_inet_csk_accept_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_set_state_progs") handle_tcp_set_state_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_set_state_progs_ret") handle_tcp_set_state_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_close_progs") handle_tcp_close_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_close_progs_ret") handle_tcp_close_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

SEC("kprobe/tcp_v4_connect")
int kprobe__handle_tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs, 0);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__handle_tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs_ret, 0);

	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe__handle_tcp_v6_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_v6_connect_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_v6_connect_progs, 0);

	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe__handle_tcp_v6_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_v6_connect_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_v6_connect_progs_ret, 0);

	return 0;
}

SEC("kprobe/inet_csk_accept")
int kprobe__handle_inet_csk_accept(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs, 0);

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__handle_inet_csk_accept(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs_ret, 0);

	return 0;
}

SEC("kprobe/tcp_set_state")
int kprobe__handle_tcp_set_state(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_set_state_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_set_state_progs, 0);

	return 0;
}

SEC("kretprobe/tcp_set_state")
int kretprobe__handle_tcp_set_state(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_set_state_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_set_state_progs_ret, 0);

	return 0;
}

SEC("kprobe/tcp_close")
int kprobe__handle_tcp_close(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_close_progs, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_close_progs, 0);

	return 0;
}

SEC("kretprobe/tcp_close")
int kretprobe__handle_tcp_close(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid>>32;

	void *untracked = bpf_map_lookup_elem(&untracked_pids, &tgid);
	if (untracked != NULL) {
		return 0;
	}

	bpf_tail_call(ctx, (void *)&handle_tcp_close_progs_ret, tgid);
	bpf_tail_call(ctx, (void *)&handle_tcp_close_progs_ret, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
