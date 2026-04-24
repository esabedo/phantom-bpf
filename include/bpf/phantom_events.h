#pragma once

#ifdef __cplusplus
#include <cstdint>
using __u32 = std::uint32_t;
using __u64 = std::uint64_t;
#else
#include "vmlinux.h"
#endif

#define PHANTOM_HTTP_METHOD_MAX 8
#define PHANTOM_HTTP_PATH_MAX 96
#define PHANTOM_COMM_MAX 16

enum phantom_direction {
  PHANTOM_DIR_UNKNOWN = 0,
  PHANTOM_DIR_SEND = 1,
  PHANTOM_DIR_RECV = 2,
};

enum phantom_http_kind {
  PHANTOM_HTTP_UNKNOWN = 0,
  PHANTOM_HTTP_REQUEST = 1,
  PHANTOM_HTTP_RESPONSE = 2,
};

struct phantom_http_event {
  __u64 timestamp_ns;
  __u64 pid_tgid;
  __u64 socket_cookie;
  __u32 pid;
  __u32 tid;
  __u32 bytes;
  __u32 direction;
  __u32 http_kind;
  __u32 status_code;
  char comm[PHANTOM_COMM_MAX];
  char method[PHANTOM_HTTP_METHOD_MAX];
  char path[PHANTOM_HTTP_PATH_MAX];
};
