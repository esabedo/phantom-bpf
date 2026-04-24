#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "bpf/phantom_events.h"

namespace phantom {

enum class Direction {
  Unknown,
  Send,
  Recv,
};

enum class HttpKind {
  Unknown,
  Request,
  Response,
};

struct HttpEvent {
  std::uint64_t timestamp_ns{};
  std::uint64_t pid_tgid{};
  std::uint64_t socket_cookie{};
  std::uint32_t pid{};
  std::uint32_t tid{};
  std::uint32_t bytes{};
  std::uint32_t payload_size{};
  Direction direction{Direction::Unknown};
  HttpKind http_kind{HttpKind::Unknown};
  std::uint32_t status_code{};
  std::string comm;
  std::string method;
  std::string path;
  std::string payload_prefix;
};

HttpEvent from_bpf_event(const phantom_http_event &event);
std::string direction_name(Direction direction);
std::string http_kind_name(HttpKind kind);
std::string bounded_c_string(const char *value, std::size_t max_len);

}  // namespace phantom
