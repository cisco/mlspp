#pragma once

#include "common.h"
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace mls;

static std::string
to_hex(const bytes& data)
{
  std::stringstream hex;
  hex.flags(std::ios::hex);
  for (const auto& byte : data) {
    hex << std::setw(2) << std::setfill('0') << int(byte);
  }
  return hex.str();
}

static bytes
from_hex(const std::string& hex)
{
  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  int len = hex.length() / 2;
  bytes out(len);
  for (int i = 0; i < len; i += 1) {
    std::string byte = hex.substr(2 * i, 2);
    out[i] = strtol(byte.c_str(), nullptr, 16);
  }

  return out;
}
