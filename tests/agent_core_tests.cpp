#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

#include "bpf/phantom_events.h"
#include "phantom/bounded_queue.hpp"
#include "phantom/correlator.hpp"
#include "phantom/event.hpp"
#include "phantom/http_aggregator.hpp"
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
  raw.payload_size = 16;
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
  raw.payload_prefix[0] = 'G';
  raw.payload_prefix[1] = 'E';
  raw.payload_prefix[2] = 'T';

  const auto event = phantom::from_bpf_event(raw);
  require(event.payload_size == 16, "event conversion should preserve payload size");
  require(event.payload_prefix == "GET", "event conversion should preserve payload prefix");
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
  require(stats.correlated == 0, "single response should not create correlation");
  require(out.str().find("\"status_code\":200") != std::string::npos, "pipeline output should include status");
}

void test_pipeline_counts_correlations() {
  std::ostringstream out;
  phantom::EventPipeline pipeline(8, 2, out);
  pipeline.start();

  phantom::HttpEvent request;
  request.timestamp_ns = 10;
  request.pid = 44;
  request.tid = 45;
  request.socket_cookie = 1000;
  request.direction = phantom::Direction::Send;
  request.http_kind = phantom::HttpKind::Request;
  request.method = "GET";
  request.path = "/ready";

  phantom::HttpEvent response;
  response.timestamp_ns = 20;
  response.pid = 44;
  response.tid = 45;
  response.socket_cookie = 1000;
  response.direction = phantom::Direction::Recv;
  response.http_kind = phantom::HttpKind::Response;
  response.status_code = 204;

  require(pipeline.submit(request), "pipeline should accept request");
  require(pipeline.submit(response), "pipeline should accept response");
  pipeline.stop();

  const auto stats = pipeline.stats();
  require(stats.accepted == 2, "pipeline should accept request and response");
  require(stats.correlated == 1, "pipeline should count one correlated exchange");
  require(stats.pending_correlations == 0, "completed correlation should not remain pending");
}

void test_parses_fragmented_http_request() {
  phantom::HttpFragmentAggregator aggregator;

  phantom::HttpEvent first;
  first.pid = 10;
  first.socket_cookie = 500;
  first.direction = phantom::Direction::Recv;
  first.payload_prefix = "PO";

  phantom::HttpEvent second = first;
  second.payload_prefix = "ST /orders HTTP/1.1\r\nHost: local\r\n";

  const auto pending = aggregator.observe(first);
  require(pending.http_kind == phantom::HttpKind::Unknown, "first fragment should remain unknown");
  require(aggregator.pending_fragments() == 1, "first fragment should be buffered");

  const auto parsed = aggregator.observe(second);
  require(parsed.http_kind == phantom::HttpKind::Request, "second fragment should complete request parse");
  require(parsed.method == "POST", "aggregator should parse fragmented method");
  require(parsed.path == "/orders", "aggregator should parse fragmented path");
  require(aggregator.pending_fragments() == 0, "completed fragmented request should clear buffer");
}

void test_parses_fragmented_http_response() {
  phantom::HttpFragmentAggregator aggregator;

  phantom::HttpEvent first;
  first.pid = 11;
  first.socket_cookie = 501;
  first.direction = phantom::Direction::Send;
  first.payload_prefix = "HTTP/1.";

  phantom::HttpEvent second = first;
  second.payload_prefix = "1 503 Service Unavailable\r\n";

  aggregator.observe(first);
  const auto parsed = aggregator.observe(second);
  require(parsed.http_kind == phantom::HttpKind::Response, "aggregator should parse fragmented response");
  require(parsed.status_code == 503, "aggregator should parse fragmented status");
}

void test_correlates_client_exchange() {
  phantom::HttpCorrelator correlator;

  phantom::HttpEvent request;
  request.timestamp_ns = 100;
  request.pid = 42;
  request.tid = 43;
  request.socket_cookie = 9001;
  request.bytes = 80;
  request.direction = phantom::Direction::Send;
  request.http_kind = phantom::HttpKind::Request;
  request.method = "GET";
  request.path = "/items";

  phantom::HttpEvent response;
  response.timestamp_ns = 175;
  response.pid = 42;
  response.tid = 43;
  response.socket_cookie = 9001;
  response.bytes = 256;
  response.direction = phantom::Direction::Recv;
  response.http_kind = phantom::HttpKind::Response;
  response.status_code = 200;

  require(!correlator.observe(request).has_value(), "request should be pending");
  require(correlator.pending_requests() == 1, "correlator should hold one pending request");
  const auto exchange = correlator.observe(response);
  require(exchange.has_value(), "response should complete client exchange");
  require(exchange->role == phantom::ExchangeRole::Client, "exchange role should be client");
  require(exchange->duration_ns == 75, "exchange duration should be computed");
  require(exchange->method == "GET", "exchange should preserve method");
  require(exchange->path == "/items", "exchange should preserve path");
  require(exchange->status_code == 200, "exchange should preserve status code");
  require(correlator.pending_requests() == 0, "completed exchange should clear pending request");
}

void test_correlates_server_exchange() {
  phantom::HttpCorrelator correlator;

  phantom::HttpEvent request;
  request.timestamp_ns = 300;
  request.pid = 7;
  request.tid = 8;
  request.socket_cookie = 1234;
  request.direction = phantom::Direction::Recv;
  request.http_kind = phantom::HttpKind::Request;
  request.method = "POST";
  request.path = "/submit";

  phantom::HttpEvent response;
  response.timestamp_ns = 450;
  response.pid = 7;
  response.tid = 9;
  response.socket_cookie = 1234;
  response.direction = phantom::Direction::Send;
  response.http_kind = phantom::HttpKind::Response;
  response.status_code = 201;

  correlator.observe(request);
  const auto exchange = correlator.observe(response);
  require(exchange.has_value(), "response should complete server exchange");
  require(exchange->role == phantom::ExchangeRole::Server, "exchange role should be server");
  require(exchange->request_tid == 8, "exchange should preserve request tid");
  require(exchange->response_tid == 9, "exchange should preserve response tid");
  require(exchange->duration_ns == 150, "server exchange duration should be computed");
}

}  // namespace

int main() {
  test_bounded_queue_capacity();
  test_event_conversion_and_json();
  test_pipeline_exports();
  test_pipeline_counts_correlations();
  test_parses_fragmented_http_request();
  test_parses_fragmented_http_response();
  test_correlates_client_exchange();
  test_correlates_server_exchange();
  return 0;
}
