/* Shared definitions between the BPF program (codax.bpf.c) and the loader (codax_tracer.c). */
#ifndef __CODAX_H
#define __CODAX_H

#define TASK_COMM_LEN 16

enum evt_type {
    EVT_ACCEPT = 0, /* a new connection was accepted inside a watched container */
    EVT_CLOSE  = 1, /* a previously accepted connection closed */
};

/* One connection-lifecycle event, pushed to userspace via the ring buffer.
 * Times are from bpf_ktime_get_ns() (CLOCK_MONOTONIC), so they are directly
 * comparable on the target VM and immune to the two-VM clock skew. */
struct event {
    unsigned int  type;        /* enum evt_type */
    unsigned int  pid;         /* tgid of the task doing accept/close */
    unsigned long long cgid;   /* cgroup v2 id -> identifies the container */
    unsigned long long sk;     /* struct sock* pointer: unique per connection */
    unsigned long long start_ns;   /* accept timestamp */
    unsigned long long ts_ns;      /* this event's timestamp */
    unsigned long long elapsed_ns; /* ts_ns - start_ns (0 for ACCEPT) */
    unsigned int  sport;           /* server-side local port (8001/8002/8003) */
    unsigned int  dport;           /* client ephemeral port -> ground-truth join key */
    char comm[TASK_COMM_LEN];
};

#endif /* __CODAX_H */
