#include "phantom/correlator.hpp"

namespace phantom {

namespace {

ExchangeRole role_for_request(Direction direction) {
  switch (direction) {
    case Direction::Send:
      return ExchangeRole::Client;
    case Direction::Recv:
      return ExchangeRole::Server;
    default:
      return ExchangeRole::Unknown;
  }
}

bool response_matches_role(Direction response_direction, ExchangeRole role) {
  if (role == ExchangeRole::Client) {
    return response_direction == Direction::Recv;
  }
  if (role == ExchangeRole::Server) {
    return response_direction == Direction::Send;
  }
  return false;
}

}  // namespace

std::optional<CorrelatedHttpExchange> HttpCorrelator::observe(const HttpEvent &event) {
  if (event.socket_cookie == 0 || event.pid == 0) {
    return std::nullopt;
  }

  const Key key{event.pid, event.socket_cookie};
  if (event.http_kind == HttpKind::Request) {
    pending_[key] = PendingRequest{event, role_for_request(event.direction)};
    return std::nullopt;
  }

  if (event.http_kind != HttpKind::Response) {
    return std::nullopt;
  }

  auto found = pending_.find(key);
  if (found == pending_.end()) {
    return std::nullopt;
  }

  const PendingRequest pending = found->second;
  if (!response_matches_role(event.direction, pending.role)) {
    return std::nullopt;
  }

  pending_.erase(found);

  CorrelatedHttpExchange exchange;
  exchange.socket_cookie = event.socket_cookie;
  exchange.pid = event.pid;
  exchange.request_tid = pending.event.tid;
  exchange.response_tid = event.tid;
  exchange.start_ns = pending.event.timestamp_ns;
  exchange.end_ns = event.timestamp_ns;
  exchange.duration_ns = event.timestamp_ns >= pending.event.timestamp_ns ? event.timestamp_ns - pending.event.timestamp_ns : 0;
  exchange.request_bytes = pending.event.bytes;
  exchange.response_bytes = event.bytes;
  exchange.status_code = event.status_code;
  exchange.request_direction = pending.event.direction;
  exchange.response_direction = event.direction;
  exchange.role = pending.role;
  exchange.comm = pending.event.comm;
  exchange.method = pending.event.method;
  exchange.path = pending.event.path;
  return exchange;
}

std::size_t HttpCorrelator::pending_requests() const {
  return pending_.size();
}

void HttpCorrelator::clear() {
  pending_.clear();
}

std::string exchange_role_name(ExchangeRole role) {
  switch (role) {
    case ExchangeRole::Client:
      return "client";
    case ExchangeRole::Server:
      return "server";
    default:
      return "unknown";
  }
}

}  // namespace phantom
