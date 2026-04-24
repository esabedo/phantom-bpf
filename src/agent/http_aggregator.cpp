#include "phantom/http_aggregator.hpp"

#include <algorithm>
#include <array>

namespace phantom {

namespace {

constexpr std::array<const char *, 7> kMethods = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
};

bool starts_with(const std::string &value, const std::string &prefix) {
  return value.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool has_complete_start_line(const std::string &payload) {
  return payload.find("\r\n") != std::string::npos || payload.find('\n') != std::string::npos;
}

std::optional<ParsedHttpPrefix> parse_request_prefix(const std::string &payload) {
  for (const char *method : kMethods) {
    const std::string method_text(method);
    const std::string prefix = method_text + " ";
    if (!starts_with(payload, prefix)) {
      continue;
    }

    const auto path_start = prefix.size();
    const auto path_end = payload.find(' ', path_start);
    if (path_end == std::string::npos || path_end == path_start) {
      return std::nullopt;
    }

    ParsedHttpPrefix parsed;
    parsed.kind = HttpKind::Request;
    parsed.method = method_text;
    parsed.path = payload.substr(path_start, path_end - path_start);
    return parsed;
  }
  return std::nullopt;
}

std::optional<ParsedHttpPrefix> parse_response_prefix(const std::string &payload) {
  if (!starts_with(payload, "HTTP/1.") || payload.size() < 12) {
    return std::nullopt;
  }

  const char hundreds = payload[9];
  const char tens = payload[10];
  const char ones = payload[11];
  if (hundreds < '0' || hundreds > '9' || tens < '0' || tens > '9' || ones < '0' || ones > '9') {
    return std::nullopt;
  }

  ParsedHttpPrefix parsed;
  parsed.kind = HttpKind::Response;
  parsed.status_code = static_cast<std::uint32_t>((hundreds - '0') * 100 + (tens - '0') * 10 + (ones - '0'));
  return parsed;
}

}  // namespace

ParsedHttpPrefix parse_http_prefix(const std::string &payload) {
  if (auto parsed = parse_request_prefix(payload)) {
    return *parsed;
  }
  if (auto parsed = parse_response_prefix(payload)) {
    return *parsed;
  }
  return ParsedHttpPrefix{};
}

HttpFragmentAggregator::HttpFragmentAggregator(std::size_t max_buffer_size) : max_buffer_size_(max_buffer_size) {}

HttpEvent HttpFragmentAggregator::observe(HttpEvent event) {
  if (event.http_kind != HttpKind::Unknown || event.payload_prefix.empty() || event.socket_cookie == 0 || event.pid == 0) {
    return event;
  }

  const Key key{event.pid, event.socket_cookie, event.direction};
  auto &buffer = fragments_[key];
  const auto remaining = max_buffer_size_ > buffer.size() ? max_buffer_size_ - buffer.size() : 0;
  buffer.append(event.payload_prefix.data(), std::min(remaining, event.payload_prefix.size()));

  const auto parsed = parse_http_prefix(buffer);
  if (parsed.kind != HttpKind::Unknown) {
    event.http_kind = parsed.kind;
    event.method = parsed.method;
    event.path = parsed.path;
    event.status_code = parsed.status_code;
    fragments_.erase(key);
    return event;
  }

  if (buffer.size() >= max_buffer_size_ || has_complete_start_line(buffer)) {
    fragments_.erase(key);
  }
  return event;
}

std::size_t HttpFragmentAggregator::pending_fragments() const {
  return fragments_.size();
}

void HttpFragmentAggregator::clear() {
  fragments_.clear();
}

}  // namespace phantom
