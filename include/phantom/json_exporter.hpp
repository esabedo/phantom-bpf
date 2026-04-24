#pragma once

#include <iosfwd>
#include <string>

#include "phantom/event.hpp"

namespace phantom {

std::string to_json_line(const HttpEvent &event);
void write_json_line(std::ostream &out, const HttpEvent &event);

}  // namespace phantom
