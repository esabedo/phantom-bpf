#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf/phantom_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} dropped_events SEC(".maps");

static __always_inline void bump_dropped_events(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&dropped_events, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline int has_prefix(const char *buf, const char *prefix, int len) {
#pragma unroll
  for (int i = 0; i < 8; i++) {
    if (i >= len) {
      break;
    }
    if (buf[i] != prefix[i]) {
      return 0;
    }
  }
  return 1;
}

static __always_inline void copy_method(char *dst, const char *method, int len) {
#pragma unroll
  for (int i = 0; i < PHANTOM_HTTP_METHOD_MAX; i++) {
    dst[i] = i < len ? method[i] : 0;
  }
}

static __always_inline void parse_http_prefix(struct phantom_http_event *event, const char *buf) {
  event->http_kind = PHANTOM_HTTP_UNKNOWN;

  if (has_prefix(buf, "GET ", 4)) {
    event->http_kind = PHANTOM_HTTP_REQUEST;
    copy_method(event->method, "GET", 3);
  } else if (has_prefix(buf, "POST ", 5)) {
    event->http_kind = PHANTOM_HTTP_REQUEST;
    copy_method(event->method, "POST", 4);
  } else if (has_prefix(buf, "PUT ", 4)) {
    event->http_kind = PHANTOM_HTTP_REQUEST;
    copy_method(event->method, "PUT", 3);
  } else if (has_prefix(buf, "PATCH ", 6)) {
    event->http_kind = PHANTOM_HTTP_REQUEST;
    copy_method(event->method, "PATCH", 5);
  } else if (has_prefix(buf, "DELETE ", 7)) {
    event->http_kind = PHANTOM_HTTP_REQUEST;
    copy_method(event->method, "DELETE", 6);
  } else if (has_prefix(buf, "HEAD ", 5)) {
    event->http_kind = PHANTOM_HTTP_REQUEST;
    copy_method(event->method, "HEAD", 4);
  } else if (has_prefix(buf, "OPTIONS ", 8)) {
    event->http_kind = PHANTOM_HTTP_REQUEST;
    copy_method(event->method, "OPTIONS", 7);
  } else if (has_prefix(buf, "HTTP/1.", 7)) {
    event->http_kind = PHANTOM_HTTP_RESPONSE;
    event->status_code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
  }

  if (event->http_kind != PHANTOM_HTTP_REQUEST) {
    return;
  }

  int path_start = 0;
#pragma unroll
  for (int i = 0; i < 16; i++) {
    if (buf[i] == ' ') {
      path_start = i + 1;
      break;
    }
  }

  if (path_start == 0) {
    return;
  }

#pragma unroll
  for (int i = 0; i < PHANTOM_HTTP_PATH_MAX - 1; i++) {
    char c = buf[path_start + i];
    if (c == ' ' || c == '\r' || c == '\n' || c == 0) {
      break;
    }
    event->path[i] = c;
  }
}

static __always_inline int submit_event(struct sock *sk, size_t bytes, __u32 direction, const char *payload) {
  struct phantom_http_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    bump_dropped_events();
    return 0;
  }

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp_ns = bpf_ktime_get_ns();
  event->pid_tgid = pid_tgid;
  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;
  event->bytes = (__u32)bytes;
  event->direction = direction;
  event->socket_cookie = sk ? bpf_get_socket_cookie(sk) : 0;
  event->http_kind = PHANTOM_HTTP_UNKNOWN;
  event->status_code = 0;
  __builtin_memset(event->comm, 0, sizeof(event->comm));
  __builtin_memset(event->method, 0, sizeof(event->method));
  __builtin_memset(event->path, 0, sizeof(event->path));
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  char prefix[128] = {};
  if (payload) {
    long read = bpf_probe_read_user(prefix, sizeof(prefix), payload);
    if (read == 0) {
      parse_http_prefix(event, prefix);
    }
  }

  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  const struct iovec *iov = BPF_CORE_READ(msg, msg_iter, __iov);
  const char *payload = iov ? BPF_CORE_READ(iov, iov_base) : 0;
  return submit_event(sk, size, PHANTOM_DIR_SEND, payload);
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
  const struct iovec *iov = BPF_CORE_READ(msg, msg_iter, __iov);
  const char *payload = iov ? BPF_CORE_READ(iov, iov_base) : 0;
  return submit_event(sk, len, PHANTOM_DIR_RECV, payload);
}
