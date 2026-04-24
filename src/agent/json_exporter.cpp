#include "phantom/json_exporter.hpp"

#include <ostream>
#include <sstream>

namespace phantom {

namespace {

std::string json_escape(const std::string &value) {
  std::string output;
  for (char c : value) {
    switch (c) {
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
        output += c;
        break;
    }
  }
  return output;
}

}  // namespace

std::string to_json_line(const HttpEvent &event) {
  std::ostringstream out;
  out << "{"
      << "\"timestamp_ns\":" << event.timestamp_ns << ","
      << "\"pid\":" << event.pid << ","
      << "\"tid\":" << event.tid << ","
      << "\"comm\":\"" << json_escape(event.comm) << "\","
      << "\"direction\":\"" << direction_name(event.direction) << "\","
      << "\"bytes\":" << event.bytes << ","
      << "\"socket_cookie\":" << event.socket_cookie << ","
      << "\"http_kind\":\"" << http_kind_name(event.http_kind) << "\","
      << "\"method\":\"" << json_escape(event.method) << "\","
      << "\"path\":\"" << json_escape(event.path) << "\","
      << "\"status_code\":" << event.status_code
      << "}";
  return out.str();
}

void write_json_line(std::ostream &out, const HttpEvent &event) {
  out << to_json_line(event) << '\n';
}

}  // namespace phantom
