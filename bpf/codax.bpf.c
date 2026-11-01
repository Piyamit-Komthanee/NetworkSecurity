// CODAX tracer (kernel side). CO-RE / libbpf.
//
// What it does, and why each piece exists:
//   * fexit/inet_csk_accept : inet_csk_accept() is the kernel function behind the accept()
//     syscall for TCP. It RETURNS the struct sock* of the newly accepted connection, so an
//     fexit (function-exit) probe is the natural place to learn "a new connection was born".
//     We use the returned pointer as a per-connection key.
//   * fentry/tcp_close : tcp_close() runs when a TCP socket is torn down. Its first argument
//     is the same struct sock*, so we can match it to the accept and compute the lifetime.
//
// Container filtering: a connection is reported only if its cgroup id is present in
// `watched_cgroups`, a map the loader fills with our 3 containers' cgroup ids. That is the
// cgroup-v2 way to tell "container vs host" (the paper's Container Tracing Module, Alg. 1),
// without the fragile comm=="doc" heuristic the upstream repo used.
//
// The program emits raw lifecycle events only. Thresholds, CODA vs CODAX decision logic and
// metrics live in userspace/Python so the capture can be replayed and tested offline.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "codax.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Active connections: key = struct sock* (as u64), value kept until close. */
struct conn_info {
    __u64 start_ns;
    __u64 cgid;
    __u32 sport;
    __u32 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct conn_info);
} conns SEC(".maps");

/* cgroup ids the loader wants traced (our containers). value is unused (presence = watched). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} watched_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline int is_watched(__u64 cgid)
{
    return bpf_map_lookup_elem(&watched_cgroups, &cgid) != NULL;
}

static __always_inline void emit(__u32 type, __u64 sk, __u64 cgid,
                                 __u64 start_ns, __u64 ts_ns,
                                 __u32 sport, __u32 dport)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;
    e->type       = type;
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->cgid       = cgid;
    e->sk         = sk;
    e->start_ns   = start_ns;
    e->ts_ns      = ts_ns;
    e->elapsed_ns = ts_ns - start_ns;
    e->sport      = sport;
    e->dport      = dport;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

/* struct sock *inet_csk_accept(struct sock *sk, struct proto_accept_arg *arg)  [kernel >= 6.10]
 * For fexit, BPF_PROG appends the return value as the last parameter. */
SEC("fexit/inet_csk_accept")
int BPF_PROG(accept_exit, struct sock *sk, struct proto_accept_arg *arg, struct sock *ret)
{
    if (!ret)
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_watched(cgid))
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 key = (__u64)(unsigned long)ret;

    /* Read the connection 4-tuple ports from the accepted sock (CO-RE).
     * skc_num is the local/server port in host order (8001/8002/8003);
     * skc_dport is the remote/client port in network order -> ntohs. */
    __u32 sport = BPF_CORE_READ(ret, __sk_common.skc_num);
    __u32 dport = bpf_ntohs(BPF_CORE_READ(ret, __sk_common.skc_dport));

    struct conn_info ci = { .start_ns = now, .cgid = cgid, .sport = sport, .dport = dport };
    bpf_map_update_elem(&conns, &key, &ci, BPF_ANY);

    emit(EVT_ACCEPT, key, cgid, now, now, sport, dport);
    return 0;
}

/* void tcp_close(struct sock *sk, long timeout) */
SEC("fentry/tcp_close")
int BPF_PROG(close_enter, struct sock *sk, long timeout)
{
    __u64 key = (__u64)(unsigned long)sk;
    struct conn_info *ci = bpf_map_lookup_elem(&conns, &key);
    if (!ci)
        return 0; /* not one of our accepted container connections */

    __u64 now = bpf_ktime_get_ns();
    emit(EVT_CLOSE, key, ci->cgid, ci->start_ns, now, ci->sport, ci->dport);
    bpf_map_delete_elem(&conns, &key);
    return 0;
}
