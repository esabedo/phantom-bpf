#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "phantom/event.hpp"

namespace phantom {

enum class ExchangeRole {
  Unknown,
  Client,
  Server,
};

struct CorrelatedHttpExchange {
  std::uint64_t socket_cookie{};
  std::uint32_t pid{};
  std::uint32_t request_tid{};
  std::uint32_t response_tid{};
  std::uint64_t start_ns{};
  std::uint64_t end_ns{};
  std::uint64_t duration_ns{};
  std::uint32_t request_bytes{};
  std::uint32_t response_bytes{};
  std::uint32_t status_code{};
  Direction request_direction{Direction::Unknown};
  Direction response_direction{Direction::Unknown};
  ExchangeRole role{ExchangeRole::Unknown};
  std::string comm;
  std::string method;
  std::string path;
};

class HttpCorrelator {
 public:
  std::optional<CorrelatedHttpExchange> observe(const HttpEvent &event);
  std::size_t pending_requests() const;
  void clear();

 private:
  struct Key {
    std::uint32_t pid{};
    std::uint64_t socket_cookie{};

    bool operator==(const Key &other) const {
      return pid == other.pid && socket_cookie == other.socket_cookie;
    }
  };

  struct KeyHash {
    std::size_t operator()(const Key &key) const {
      return static_cast<std::size_t>(key.socket_cookie ^ (static_cast<std::uint64_t>(key.pid) << 32));
    }
  };

  struct PendingRequest {
    HttpEvent event;
    ExchangeRole role{ExchangeRole::Unknown};
  };

  std::unordered_map<Key, PendingRequest, KeyHash> pending_;
};

std::string exchange_role_name(ExchangeRole role);

}  // namespace phantom
