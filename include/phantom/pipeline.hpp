#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "phantom/bounded_queue.hpp"
#include "phantom/correlator.hpp"
#include "phantom/event.hpp"
#include "phantom/http_aggregator.hpp"

namespace phantom {

struct PipelineStats {
  std::uint64_t accepted{};
  std::uint64_t dropped{};
  std::uint64_t exported{};
  std::uint64_t correlated{};
  std::uint64_t pending_correlations{};
  std::uint64_t pending_fragments{};
};

class EventPipeline {
 public:
  EventPipeline(std::size_t queue_capacity, std::size_t worker_count, std::ostream &out);
  ~EventPipeline();

  EventPipeline(const EventPipeline &) = delete;
  EventPipeline &operator=(const EventPipeline &) = delete;

  bool submit(HttpEvent event);
  void start();
  void stop();
  PipelineStats stats() const;

 private:
  void worker_loop();

  BoundedQueue<HttpEvent> queue_;
  std::size_t worker_count_;
  std::ostream &out_;
  std::mutex out_mutex_;
  mutable std::mutex ingest_mutex_;
  HttpFragmentAggregator aggregator_;
  HttpCorrelator correlator_;
  std::vector<std::thread> workers_;
  std::atomic_bool started_{false};
  std::atomic_bool stopped_{false};
  std::atomic_uint64_t accepted_{0};
  std::atomic_uint64_t dropped_{0};
  std::atomic_uint64_t exported_{0};
  std::atomic_uint64_t correlated_{0};
};

}  // namespace phantom
