#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16
#define MAX_SYSCALL_LEN 8

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u64 inode;
    __u64 offset;
    __u64 count;
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char syscall[MAX_SYSCALL_LEN];
};

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct event);
} data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} target_pid_map SEC(".maps");

static __always_inline bool should_trace(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    int key = 0;
    int *target = bpf_map_lookup_elem(&target_pid_map, &key);

    // 添加调试输出
    bpf_printk("Current PID: %d\n", pid);
    if (target) {
        bpf_printk("Target PID: %d\n", *target);
    } else {
        bpf_printk("No target PID set\n");
        return true;
    }

    if (pid == *target) {
        return true;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    if (ppid == *target) {
        return true;
    }

    return false;
}

static __always_inline __u64 get_file_offset(int fd) {
    __u64 offset = 0;
    struct file *file;

    if (fd < 0)
        return 0;

    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    // 读取 files_struct
    struct files_struct *files;
    files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    // 读取 fdtable
    struct fdtable *fdt;
    fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;

    // 读取最大文件描述符
    unsigned int max_fds;
    max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((__u32)fd >= max_fds)
        return 0;

    // 获取文件指针数组地址
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return 0;

    // 读取特定文件描述符对应的文件指针
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (!file)
        return 0;

    // 读取文件位置
    offset = BPF_CORE_READ(file, f_pos);
    return offset;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx)
{

    if (!should_trace())
        return 0;

    int zero = 0;
    struct event *data = bpf_map_lookup_elem(&data_map, &zero);
    if (!data)
        return 0;

    data->timestamp = bpf_ktime_get_ns();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->count = (unsigned long)ctx->args[2];
    int fd = (int)ctx->args[0];
    __u64 offset = get_file_offset(fd);
    data->offset = offset;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    __builtin_memset(data->syscall, 0, MAX_SYSCALL_LEN);
    __builtin_memcpy(data->syscall, "read", 5);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    // 添加调试输出
    bpf_printk("Write syscall entered\n");

    if (!should_trace())
        return 0;

    int zero = 0;
    struct event *data = bpf_map_lookup_elem(&data_map, &zero);
    if (!data)
        return 0;

    data->timestamp = bpf_ktime_get_ns();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->count = (unsigned long)ctx->args[2];
    int fd = (int)ctx->args[0];
    __u64 offset = get_file_offset(fd);
    data->offset = offset;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    __builtin_memset(data->syscall, 0, MAX_SYSCALL_LEN);
    __builtin_memcpy(data->syscall, "write", 6);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    // 添加调试输出
    bpf_printk("Open syscall entered\n");

    if (!should_trace())
        return 0;

    int zero = 0;
    struct event *data = bpf_map_lookup_elem(&data_map, &zero);
    if (!data)
        return 0;

    data->timestamp = bpf_ktime_get_ns();
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->count = 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    const char *pathname = (const char *)ctx->args[1];
    if (pathname) {
        bpf_probe_read_user_str(data->filename, sizeof(data->filename), pathname);
    }

    __builtin_memset(data->syscall, 0, MAX_SYSCALL_LEN);
    __builtin_memcpy(data->syscall, "open", 5);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(*data));

    return 0;
}