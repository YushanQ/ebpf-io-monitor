#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

static volatile bool exiting = false;

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u64 inode;
    __u64 offset;
    __u64 count;
    __s32 fd;
    char comm[16];
    char filename[256];
    char syscall[8];
};

static void print_event(const struct event *e)
{
    if (!e->syscall[0]) // 跳过空系统调用
        return;

    time_t sec = e->timestamp / 1000000000;
    unsigned int nsec = e->timestamp % 1000000000;

    struct tm *tm = localtime(&sec);
    char ts[32];
    // 格式化时间，包含纳秒
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%09u",
             tm->tm_hour, tm->tm_min, tm->tm_sec, nsec);

    // 根据不同的系统调用格式化输出
    if (strcmp(e->syscall, "lseek") == 0) {
        const char *whence;
        switch (e->count) {
        case 0: whence = "SEEK_SET"; break;
        case 1: whence = "SEEK_CUR"; break;
        case 2: whence = "SEEK_END"; break;
        default: whence = "UNKNOWN"; break;
        }
        printf("%-8s %-7d %-7s %-16s [fd=%-3d] %-16llu %s\n",
               ts, e->pid, e->syscall, e->comm, e->fd, e->offset, whence);
    }
    else if (strcmp(e->syscall, "mmap") == 0) {
        printf("%-8s %-7d %-7s %-16s [fd=%-3d] offset=%-10llu len=%-8llu %s\n",
               ts, e->pid, e->syscall, e->comm, e->fd, e->offset, e->count, e->filename[0] ? e->filename : "");
    }
    else if (strcmp(e->syscall, "fsync") == 0 || strcmp(e->syscall, "fdsync") == 0) {
        printf("%-8s %-7d %-7s %-16s [fd=%-3d] %s\n",
               ts, e->pid, e->syscall, e->comm, e->fd, e->filename[0] ? e->filename : "");
    }
    else {
        printf("%-8s %-7d %-7s %-16s [fd=%-3d] %-10llu %-8llu %s\n",
               ts, e->pid, e->syscall, e->comm, e->fd,
               e->offset, e->count, e->filename[0] ? e->filename : "");
    }
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
    const struct event *e = data;
    print_event(e);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_header(void)
{
    printf("\n%-8s %-7s %-7s %-16s %-7s %-10s %-8s %s\n",
           "TIME", "PID", "SYSCALL", "COMM", "FD", "OFFSET", "SIZE", "FILENAME/INFO");
    printf("%-8s %-7s %-7s %-16s %-7s %-10s %-8s %s\n",
           "--------", "-------", "-------", "----------------",
           "-------", "----------", "--------", "----------------");
}

static int libbpf_debug_print(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static int handle_child_exit(pid_t child_pid)
{
    int status;
    int err = 0;

    if (waitpid(child_pid, &status, WNOHANG) > 0) {
        if (WIFEXITED(status)) {
            int exit_status = WEXITSTATUS(status);
            if (exit_status != 0) {
                printf("\nMonitored process %d exited with status %d\n",
                       child_pid, exit_status);
                printf("Check python_error.log for details.\n");
                err = exit_status;
            } else {
                printf("\nMonitored process %d completed successfully.\n", child_pid);
            }
        } else if (WIFSIGNALED(status)) {
            printf("\nMonitored process %d was terminated by signal %d\n",
                   child_pid, WTERMSIG(status));
            err = 1;
        }
        return err;
    }
    return -1; // 进程仍在运行
}

int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj = NULL;
    struct perf_buffer *pb = NULL;
    int err;
    pid_t child_pid;
    int efd_read = -1, efd_write = -1, efd_openat = -1;
    int efd_lseek = -1, efd_mmap = -1, efd_fsync = -1, efd_fdatasync = -1;

    // 检查参数
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    // 设置 libbpf 的调试输出级别
    libbpf_set_print(libbpf_debug_print);

    // 设置资源限制
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "Failed to set rlimit: %s\n", strerror(errno));
        return 1;
    }

    // 创建子进程
    child_pid = fork();
    if (child_pid < 0) {
        fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
        return 1;
    }

    if (child_pid == 0) {
        // 子进程：重定向输出并执行命令
        if (freopen("python_output.log", "w", stdout) == NULL) {
            fprintf(stderr, "Failed to redirect stdout: %s\n", strerror(errno));
            exit(1);
        }
        if (freopen("python_error.log", "w", stderr) == NULL) {
            fprintf(stderr, "Failed to redirect stderr: %s\n", strerror(errno));
            exit(1);
        }
        execvp(argv[1], &argv[1]);
        fprintf(stderr, "Failed to execute %s: %s\n", argv[1], strerror(errno));
        exit(1);
    }

    // 父进程：加载和设置 eBPF 程序
    obj = bpf_object__open_file("ext4_io_tracker.bpf.o", NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));
        goto cleanup;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        goto cleanup;
    }

    // 获取并设置 map
    int pid_map_fd = bpf_object__find_map_fd_by_name(obj, "target_pid_map");
    if (pid_map_fd < 0) {
        fprintf(stderr, "Failed to find target_pid map\n");
        err = -1;
        goto cleanup;
    }

    int key = 0;
    err = bpf_map_update_elem(pid_map_fd, &key, &child_pid, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update target PID: %s\n", strerror(errno));
        goto cleanup;
    }

    // 设置性能事件缓冲区
    int perf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (perf_map_fd < 0) {
        fprintf(stderr, "Failed to find events map\n");
        err = -1;
        goto cleanup;
    }

    pb = perf_buffer__new(perf_map_fd, PERF_BUFFER_PAGES,
                         handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    // 附加所有跟踪点
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        int prog_fd = bpf_program__fd(prog);

        // 根据程序名称选择正确的跟踪点
        if (strcmp(prog_name, "trace_enter_read") == 0)
            efd_read = bpf_program__attach(prog);
        else if (strcmp(prog_name, "trace_enter_write") == 0)
            efd_write = bpf_program__attach(prog);
        else if (strcmp(prog_name, "trace_enter_openat") == 0)
            efd_openat = bpf_program__attach(prog);
        else if (strcmp(prog_name, "trace_enter_lseek") == 0)
            efd_lseek = bpf_program__attach(prog);
        else if (strcmp(prog_name, "trace_enter_mmap") == 0)
            efd_mmap = bpf_program__attach(prog);
        else if (strcmp(prog_name, "trace_enter_fsync") == 0)
            efd_fsync = bpf_program__attach(prog);
        else if (strcmp(prog_name, "trace_enter_fdatasync") == 0)
            efd_fdatasync = bpf_program__attach(prog);

        if (prog_fd < 0) {
            fprintf(stderr, "Failed to attach %s\n", prog_name);
            err = -1;
            goto cleanup;
        }
    }

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 打印表头
    print_header();

    // 主循环
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }

        // 检查子进程状态
        int child_status = handle_child_exit(child_pid);
        if (child_status >= 0) {
            err = child_status;
            break;
        }
    }

cleanup:
    printf("Cleaning up...\n");
    if (efd_read >= 0) close(efd_read);
    if (efd_write >= 0) close(efd_write);
    if (efd_openat >= 0) close(efd_openat);
    if (efd_lseek >= 0) close(efd_lseek);
    if (efd_mmap >= 0) close(efd_mmap);
    if (efd_fsync >= 0) close(efd_fsync);
    if (efd_fdatasync >= 0) close(efd_fdatasync);
    perf_buffer__free(pb);
    bpf_object__close(obj);

    return err != 0;
}