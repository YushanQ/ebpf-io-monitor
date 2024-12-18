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
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>

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
    char comm[16];
    char filename[256];
    char syscall[8];
};

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
    const struct event *e = data;
    time_t t = e->timestamp / 1000000000;
    struct tm *tm = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-8s %-5d %-7s %-16s %-8llu %-8llu %s\n",
           ts, e->pid, e->syscall, e->comm,
           e->offset, e->count, e->filename);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_debug_print(enum libbpf_print_level level,
                            const char *format, va_list args)
{
    fprintf(stderr, "[LIBBPF ");
    switch (level) {
        case LIBBPF_WARN:
            fprintf(stderr, "WARN");
            break;
        case LIBBPF_INFO:
            fprintf(stderr, "INFO");
            break;
        case LIBBPF_DEBUG:
            fprintf(stderr, "DEBUG");
            break;
        default:
            fprintf(stderr, "???");
    }
    fprintf(stderr, "] ");
    return vfprintf(stderr, format, args);
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                          int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int attach_tracepoint(int prog_fd, const char *tp_category, const char *tp_name)
{
    char buf[256];
    struct perf_event_attr attr = {
        .type = PERF_TYPE_TRACEPOINT,
        .sample_type = PERF_SAMPLE_RAW,
        .sample_period = 1,
        .wakeup_events = 1,
    };
    int fd, err;

    // Get tracepoint ID
    snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%s/%s/id",
             tp_category, tp_name);
    fd = open(buf, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open tracepoint id file: %s\n", strerror(errno));
        return -1;
    }

    err = read(fd, buf, sizeof(buf));
    close(fd);
    if (err < 0 || err >= sizeof(buf)) {
        fprintf(stderr, "Failed to read tracepoint id: %s\n", strerror(errno));
        return -1;
    }
    buf[err] = '\0';
    attr.config = strtol(buf, NULL, 0);

    // Create perf event
    fd = perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Failed to open perf event: %s\n", strerror(errno));
        return -1;
    }

    // Attach BPF program to perf event
    err = ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program to perf event: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    // Enable the event
    err = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    if (err) {
        fprintf(stderr, "Failed to enable perf event: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Successfully attached to tracepoint %s/%s\n", tp_category, tp_name);
    return fd;
}

int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj = NULL;
    struct perf_buffer *pb = NULL;
    int err;
    pid_t child_pid;
    int efd_read = -1, efd_write = -1, efd_openat = -1;

    // Set maximum verbosity for libbpf
    libbpf_set_print(libbpf_debug_print);

    // Check arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    printf("Step 1: Setting rlimit...\n");
    // Set rlimit
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "Failed to set rlimit: %s\n", strerror(errno));
        return 1;
    }

    printf("Step 2: Forking process...\n");
    // Fork the process
    child_pid = fork();
    if (child_pid < 0) {
        fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
        return 1;
    }

    if (child_pid == 0) {
        // Child process
        printf("Child process starting with PID: %d\n", getpid());
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

    printf("Step 3: Opening BPF object file...\n");
    // Open BPF object
    obj = bpf_object__open_file("ext4_io_tracker.bpf.o", NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open BPF object file: error=%d errno=%d (%s)\n",
                err, errno, strerror(errno));
        goto cleanup;
    }

    printf("Step 4: Loading BPF object...\n");
    // Load BPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: error=%d errno=%d (%s)\n",
                err, errno, strerror(errno));
        goto cleanup;
    }

    // List all programs in the object
    struct bpf_program *prog;
    printf("Loaded programs:\n");
    bpf_object__for_each_program(prog, obj) {
        printf("  %s\n", bpf_program__name(prog));

        // Get program type
        enum bpf_prog_type prog_type = bpf_program__get_type(prog);
        printf("    Type: %d\n", prog_type);

        // Get program ID
        int prog_fd = bpf_program__fd(prog);
        printf("    FD: %d\n", prog_fd);
    }

    printf("Step 4a: Attaching programs to tracepoints...\n");
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        int prog_fd = bpf_program__fd(prog);

        if (strcmp(prog_name, "trace_enter_read") == 0) {
            efd_read = attach_tracepoint(prog_fd, "syscalls", "sys_enter_read");
            if (efd_read < 0) {
                err = efd_read;
                goto cleanup;
            }
        } else if (strcmp(prog_name, "trace_enter_write") == 0) {
            efd_write = attach_tracepoint(prog_fd, "syscalls", "sys_enter_write");
            if (efd_write < 0) {
                err = efd_write;
                goto cleanup;
            }
        } else if (strcmp(prog_name, "trace_enter_openat") == 0) {
            efd_openat = attach_tracepoint(prog_fd, "syscalls", "sys_enter_openat");
            if (efd_openat < 0) {
                err = efd_openat;
                goto cleanup;
            }
        }
    }

    printf("Step 5: Finding maps...\n");
    // Find maps
    int pid_map_fd = bpf_object__find_map_fd_by_name(obj, "target_pid_map");
    if (pid_map_fd < 0) {
        fprintf(stderr, "Failed to find target_pid map: error=%d\n", pid_map_fd);
        err = -1;
        goto cleanup;
    }
    printf("Found target_pid_map: fd=%d\n", pid_map_fd);

    int events_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (events_map_fd < 0) {
        fprintf(stderr, "Failed to find events map: error=%d\n", events_map_fd);
        err = -1;
        goto cleanup;
    }
    printf("Found events map: fd=%d\n", events_map_fd);

    printf("Step 6: Updating target PID...\n");
    // Update target PID
    int key = 0;
    err = bpf_map_update_elem(pid_map_fd, &key, &child_pid, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update target PID: error=%d errno=%d (%s)\n",
                err, errno, strerror(errno));
        goto cleanup;
    }

    printf("Step 7: Setting up perf buffer...\n");
    // Set up perf buffer
    pb = perf_buffer__new(events_map_fd, PERF_BUFFER_PAGES,
                         handle_event, handle_lost_events,
                         NULL, NULL);
    if (libbpf_get_error(pb)) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer: error=%ld\n",
                libbpf_get_error(pb));
        goto cleanup;
    }

    printf("Setup complete. Starting main loop...\n\n");
    // Print header
    printf("%-8s %-5s %-7s %-16s %-8s %-8s %s\n",
           "TIME", "PID", "SYSCALL", "COMM", "OFFSET", "SIZE", "FILENAME");

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Main loop
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }

        // Check if monitored process has exited
        int status;
        if (waitpid(child_pid, &status, WNOHANG) > 0) {
            printf("\nMonitored process %d has exited with status %d\n",
                   child_pid, WEXITSTATUS(status));
            break;
        }
    }

cleanup:
    printf("Cleaning up...\n");
    if (efd_read >= 0) close(efd_read);
    if (efd_write >= 0) close(efd_write);
    if (efd_openat >= 0) close(efd_openat);
    perf_buffer__free(pb);
    bpf_object__close(obj);

    return err != 0;
}