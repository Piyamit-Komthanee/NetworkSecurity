// CODAX tracer (userspace loader). Loads codax.bpf.o, registers the container cgroup ids to
// watch, then streams connection-lifecycle events as one JSON object per line (JSONL) to
// stdout. All detection logic lives downstream in Python; this program only captures.
//
// Usage:  sudo ./codax_tracer <cgid> [<cgid> ...]
//   <cgid> = cgroup v2 id (the inode number of the container's cgroup dir). The helper
//   script scripts/cgids.sh prints them for the running containers.
//
// Output line example:
//   {"type":"accept","ts_ns":123,"start_ns":123,"elapsed_ns":0,"cgid":456,"sk":140,"pid":9,"comm":"python"}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "codax.skel.h"
#include "codax.h"

static volatile sig_atomic_t stop;
static void on_sigint(int s) { stop = 1; }

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct event *e = data;
    if (sz < sizeof(*e))
        return 0;

    printf("{\"type\":\"%s\",\"ts_ns\":%llu,\"start_ns\":%llu,\"elapsed_ns\":%llu,"
           "\"cgid\":%llu,\"sk\":%llu,\"sport\":%u,\"dport\":%u,\"pid\":%u,\"comm\":\"%s\"}\n",
           e->type == EVT_ACCEPT ? "accept" : "close",
           e->ts_ns, e->start_ns, e->elapsed_ns, e->cgid, e->sk,
           e->sport, e->dport, e->pid, e->comm);
    fflush(stdout); /* line-buffer so a downstream reader sees events immediately */
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <cgid> [<cgid> ...]\n", argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print);

    struct codax_bpf *skel = codax_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    /* Register the container cgroup ids to watch. */
    int map_fd = bpf_map__fd(skel->maps.watched_cgroups);
    for (int i = 1; i < argc; i++) {
        __u64 cgid = strtoull(argv[i], NULL, 10);
        __u8 one = 1;
        if (bpf_map_update_elem(map_fd, &cgid, &one, BPF_ANY)) {
            fprintf(stderr, "failed to add cgid %llu: %s\n", cgid, strerror(errno));
        } else {
            fprintf(stderr, "watching cgid %llu\n", cgid);
        }
    }

    int err = codax_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF (need root / CAP_BPF): %d\n", err);
        goto cleanup;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                                              handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    fprintf(stderr, "codax_tracer started; streaming events (Ctrl-C to stop)\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 200 /* ms */);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) { fprintf(stderr, "poll error: %d\n", err); break; }
    }

    ring_buffer__free(rb);
cleanup:
    codax_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
