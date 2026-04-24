#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include <bpf/libbpf.h>

#include "bpf/phantom_events.h"
#include "phantom_http.skel.h"

namespace {

std::atomic_bool g_shutdown{false};

void handle_signal(int) {
  g_shutdown.store(true);
}

std::string json_escape(const char *value, std::size_t max_len) {
  std::string output;
  for (std::size_t i = 0; i < max_len && value[i] != '\0'; ++i) {
    switch (value[i]) {
      case '\\':
        output += "\\\\";
        break;
      case '"':
        output += "\\\"";
        break;
      case '\n':
        output += "\\n";
        break;
      case '\r':
        output += "\\r";
        break;
      case '\t':
        output += "\\t";
        break;
      default:
        output += value[i];
        break;
    }
  }
  return output;
}

const char *direction_name(std::uint32_t direction) {
  switch (direction) {
    case PHANTOM_DIR_SEND:
      return "send";
    case PHANTOM_DIR_RECV:
      return "recv";
    default:
      return "unknown";
  }
}

const char *http_kind_name(std::uint32_t kind) {
  switch (kind) {
    case PHANTOM_HTTP_REQUEST:
      return "request";
    case PHANTOM_HTTP_RESPONSE:
      return "response";
    default:
      return "unknown";
  }
}

int handle_event(void *, void *data, std::size_t data_size) {
  if (data_size < sizeof(phantom_http_event)) {
    return 0;
  }

  const auto *event = static_cast<const phantom_http_event *>(data);

  std::cout << "{"
            << "\"timestamp_ns\":" << event->timestamp_ns << ","
            << "\"pid\":" << event->pid << ","
            << "\"tid\":" << event->tid << ","
            << "\"comm\":\"" << json_escape(event->comm, sizeof(event->comm)) << "\","
            << "\"direction\":\"" << direction_name(event->direction) << "\","
            << "\"bytes\":" << event->bytes << ","
            << "\"socket_cookie\":" << event->socket_cookie << ","
            << "\"http_kind\":\"" << http_kind_name(event->http_kind) << "\","
            << "\"method\":\"" << json_escape(event->method, sizeof(event->method)) << "\","
            << "\"path\":\"" << json_escape(event->path, sizeof(event->path)) << "\","
            << "\"status_code\":" << event->status_code
            << "}" << std::endl;

  return 0;
}

int handle_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
  if (level == LIBBPF_DEBUG) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

}  // namespace

int main() {
  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);

  libbpf_set_print(handle_libbpf_log);

  struct phantom_http_bpf *skel = phantom_http_bpf__open_and_load();
  if (!skel) {
    std::cerr << "failed to open and load phantom_http BPF skeleton" << std::endl;
    return EXIT_FAILURE;
  }

  if (phantom_http_bpf__attach(skel) != 0) {
    std::cerr << "failed to attach phantom_http BPF probes" << std::endl;
    phantom_http_bpf__destroy(skel);
    return EXIT_FAILURE;
  }

  struct ring_buffer *ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);
  if (!ring) {
    std::cerr << "failed to create BPF ring buffer" << std::endl;
    phantom_http_bpf__destroy(skel);
    return EXIT_FAILURE;
  }

  std::cerr << "phantom-agent started" << std::endl;
  while (!g_shutdown.load()) {
    const int result = ring_buffer__poll(ring, 250);
    if (result == -EINTR) {
      break;
    }
    if (result < 0) {
      std::cerr << "ring buffer poll failed: " << result << std::endl;
      break;
    }
  }

  ring_buffer__free(ring);
  phantom_http_bpf__destroy(skel);
  std::cerr << "phantom-agent stopped" << std::endl;
  return EXIT_SUCCESS;
}
