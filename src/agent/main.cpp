#include <atomic>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <bpf/libbpf.h>

#include "bpf/phantom_events.h"
#include "phantom/event.hpp"
#include "phantom/pipeline.hpp"
#include "phantom_http.skel.h"

namespace {

std::atomic_bool g_shutdown{false};

void handle_signal(int) {
  g_shutdown.store(true);
}

int handle_event(void *ctx, void *data, std::size_t data_size) {
  if (data_size < sizeof(phantom_http_event)) {
    return 0;
  }

  const auto *event = static_cast<const phantom_http_event *>(data);
  auto *pipeline = static_cast<phantom::EventPipeline *>(ctx);
  if (pipeline) {
    pipeline->submit(phantom::from_bpf_event(*event));
  }

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

  const auto worker_count = std::max(1u, std::thread::hardware_concurrency());
  phantom::EventPipeline pipeline(8192, worker_count, std::cout);
  pipeline.start();

  struct ring_buffer *ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &pipeline, nullptr);
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
  pipeline.stop();
  const auto stats = pipeline.stats();
  std::cerr << "pipeline stats accepted=" << stats.accepted << " dropped=" << stats.dropped
            << " exported=" << stats.exported << std::endl;
  phantom_http_bpf__destroy(skel);
  std::cerr << "phantom-agent stopped" << std::endl;
  return EXIT_SUCCESS;
}
