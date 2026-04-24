#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

#include "bpf/phantom_events.h"
#include "phantom/bounded_queue.hpp"
#include "phantom/event.hpp"
#include "phantom/json_exporter.hpp"
#include "phantom/pipeline.hpp"

namespace {

void require(bool condition, const char *message) {
  if (!condition) {
    std::cerr << "test failure: " << message << '\n';
    std::exit(EXIT_FAILURE);
  }
}

void test_bounded_queue_capacity() {
  phantom::BoundedQueue<int> queue(1);
  require(queue.try_push(7), "first queue push should succeed");
  require(!queue.try_push(9), "second queue push should fail at capacity");
  auto value = queue.pop();
  require(value.has_value(), "queue pop should return a value");
  require(*value == 7, "queue pop should preserve pushed value");
}

void test_event_conversion_and_json() {
  phantom_http_event raw{};
  raw.timestamp_ns = 42;
  raw.pid = 100;
  raw.tid = 101;
  raw.bytes = 512;
  raw.direction = PHANTOM_DIR_SEND;
  raw.http_kind = PHANTOM_HTTP_REQUEST;
  raw.socket_cookie = 99;
  raw.comm[0] = 'c';
  raw.comm[1] = 'u';
  raw.comm[2] = 'r';
  raw.comm[3] = 'l';
  raw.method[0] = 'G';
  raw.method[1] = 'E';
  raw.method[2] = 'T';
  raw.path[0] = '/';
  raw.path[1] = 'v';
  raw.path[2] = '1';

  const auto event = phantom::from_bpf_event(raw);
  const auto json = phantom::to_json_line(event);
  require(json.find("\"direction\":\"send\"") != std::string::npos, "json should include send direction");
  require(json.find("\"http_kind\":\"request\"") != std::string::npos, "json should include request kind");
  require(json.find("\"method\":\"GET\"") != std::string::npos, "json should include method");
  require(json.find("\"path\":\"/v1\"") != std::string::npos, "json should include path");
}

void test_pipeline_exports() {
  std::ostringstream out;
  phantom::EventPipeline pipeline(8, 2, out);
  pipeline.start();

  phantom::HttpEvent event;
  event.pid = 1;
  event.tid = 2;
  event.bytes = 3;
  event.direction = phantom::Direction::Recv;
  event.http_kind = phantom::HttpKind::Response;
  event.status_code = 200;
  require(pipeline.submit(event), "pipeline submit should succeed");
  pipeline.stop();

  const auto stats = pipeline.stats();
  require(stats.accepted == 1, "pipeline should accept one event");
  require(stats.dropped == 0, "pipeline should not drop events");
  require(stats.exported == 1, "pipeline should export one event");
  require(out.str().find("\"status_code\":200") != std::string::npos, "pipeline output should include status");
}

}  // namespace

int main() {
  test_bounded_queue_capacity();
  test_event_conversion_and_json();
  test_pipeline_exports();
  return 0;
}
