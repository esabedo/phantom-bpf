#include "phantom/event.hpp"

namespace phantom {

std::string bounded_c_string(const char *value, std::size_t max_len) {
  std::string output;
  for (std::size_t i = 0; i < max_len && value[i] != '\0'; ++i) {
    output.push_back(value[i]);
  }
  return output;
}

Direction direction_from_raw(std::uint32_t direction) {
  switch (direction) {
    case PHANTOM_DIR_SEND:
      return Direction::Send;
    case PHANTOM_DIR_RECV:
      return Direction::Recv;
    default:
      return Direction::Unknown;
  }
}

HttpKind http_kind_from_raw(std::uint32_t kind) {
  switch (kind) {
    case PHANTOM_HTTP_REQUEST:
      return HttpKind::Request;
    case PHANTOM_HTTP_RESPONSE:
      return HttpKind::Response;
    default:
      return HttpKind::Unknown;
  }
}

HttpEvent from_bpf_event(const phantom_http_event &event) {
  HttpEvent result;
  result.timestamp_ns = event.timestamp_ns;
  result.pid_tgid = event.pid_tgid;
  result.socket_cookie = event.socket_cookie;
  result.pid = event.pid;
  result.tid = event.tid;
  result.bytes = event.bytes;
  result.direction = direction_from_raw(event.direction);
  result.http_kind = http_kind_from_raw(event.http_kind);
  result.status_code = event.status_code;
  result.comm = bounded_c_string(event.comm, sizeof(event.comm));
  result.method = bounded_c_string(event.method, sizeof(event.method));
  result.path = bounded_c_string(event.path, sizeof(event.path));
  return result;
}

std::string direction_name(Direction direction) {
  switch (direction) {
    case Direction::Send:
      return "send";
    case Direction::Recv:
      return "recv";
    default:
      return "unknown";
  }
}

std::string http_kind_name(HttpKind kind) {
  switch (kind) {
    case HttpKind::Request:
      return "request";
    case HttpKind::Response:
      return "response";
    default:
      return "unknown";
  }
}

}  // namespace phantom
