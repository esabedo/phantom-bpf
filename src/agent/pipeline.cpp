#include "phantom/pipeline.hpp"

#include <algorithm>
#include <ostream>

#include "phantom/json_exporter.hpp"

namespace phantom {

EventPipeline::EventPipeline(std::size_t queue_capacity, std::size_t worker_count, std::ostream &out)
    : queue_(queue_capacity), worker_count_(std::max<std::size_t>(1, worker_count)), out_(out) {}

EventPipeline::~EventPipeline() {
  stop();
}

bool EventPipeline::submit(HttpEvent event) {
  if (stopped_.load()) {
    dropped_.fetch_add(1);
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(ingest_mutex_);
    event = aggregator_.observe(std::move(event));
    if (correlator_.observe(event).has_value()) {
      correlated_.fetch_add(1);
    }
  }

  if (!queue_.try_push(std::move(event))) {
    dropped_.fetch_add(1);
    return false;
  }

  accepted_.fetch_add(1);
  return true;
}

void EventPipeline::start() {
  bool expected = false;
  if (!started_.compare_exchange_strong(expected, true)) {
    return;
  }

  workers_.reserve(worker_count_);
  for (std::size_t i = 0; i < worker_count_; ++i) {
    workers_.emplace_back([this] { worker_loop(); });
  }
}

void EventPipeline::stop() {
  bool expected = false;
  if (!stopped_.compare_exchange_strong(expected, true)) {
    return;
  }

  queue_.close();
  for (auto &worker : workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
}

PipelineStats EventPipeline::stats() const {
  std::lock_guard<std::mutex> lock(ingest_mutex_);
  return PipelineStats{
      accepted_.load(),
      dropped_.load(),
      exported_.load(),
      correlated_.load(),
      static_cast<std::uint64_t>(correlator_.pending_requests()),
      static_cast<std::uint64_t>(aggregator_.pending_fragments()),
  };
}

void EventPipeline::worker_loop() {
  while (true) {
    auto event = queue_.pop();
    if (!event) {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(out_mutex_);
      write_json_line(out_, *event);
    }
    exported_.fetch_add(1);
  }
}

}  // namespace phantom
