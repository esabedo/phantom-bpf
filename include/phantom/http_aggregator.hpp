#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "phantom/event.hpp"

namespace phantom {

struct ParsedHttpPrefix {
  HttpKind kind{HttpKind::Unknown};
  std::string method;
  std::string path;
  std::uint32_t status_code{};
};

ParsedHttpPrefix parse_http_prefix(const std::string &payload);

class HttpFragmentAggregator {
 public:
  explicit HttpFragmentAggregator(std::size_t max_buffer_size = 4096);

  HttpEvent observe(HttpEvent event);
  std::size_t pending_fragments() const;
  void clear();

 private:
  struct Key {
    std::uint32_t pid{};
    std::uint64_t socket_cookie{};
    Direction direction{Direction::Unknown};

    bool operator==(const Key &other) const {
      return pid == other.pid && socket_cookie == other.socket_cookie && direction == other.direction;
    }
  };

  struct KeyHash {
    std::size_t operator()(const Key &key) const {
      const auto direction = static_cast<std::uint64_t>(key.direction == Direction::Send ? 1 : key.direction == Direction::Recv ? 2 : 0);
      return static_cast<std::size_t>(key.socket_cookie ^ (static_cast<std::uint64_t>(key.pid) << 32) ^ direction);
    }
  };

  std::size_t max_buffer_size_;
  std::unordered_map<Key, std::string, KeyHash> fragments_;
};

}  // namespace phantom
