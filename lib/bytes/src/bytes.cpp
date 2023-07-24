#include <bytes/bytes.h>

#include <array>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace bytes_ns {

bool
bytes::operator==(const bytes& other) const
{
  return *this == other._data;
}

bool
bytes::operator!=(const bytes& other) const
{
  return !(*this == other._data);
}

bool
bytes::operator==(const std::vector<uint8_t>& other) const
{
  const size_t size = other.size();
  if (_data.size() != size) {
    return false;
  }

  unsigned char diff = 0;
  for (size_t i = 0; i < size; ++i) {
    // Not sure why the linter thinks `diff` is signed
    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    diff |= (_data.at(i) ^ other.at(i));
  }
  return (diff == 0);
}

bool
bytes::operator!=(const std::vector<uint8_t>& other) const
{
  return !(*this == other);
}

bytes&
bytes::operator+=(const bytes& other)
{
  // Not sure what the default argument is here
  // NOLINTNEXTLINE(fuchsia-default-arguments)
  _data.insert(end(), other.begin(), other.end());
  return *this;
}

bytes
bytes::operator+(const bytes& rhs) const
{
  bytes out = *this;
  out += rhs;
  return out;
}

bool
bytes::operator<(const bytes& rhs) const
{
  return _data < rhs._data;
}

bytes
bytes::operator^(const bytes& rhs) const
{
  if (size() != rhs.size()) {
    throw std::invalid_argument("XOR with unequal size");
  }

  bytes out = *this;
  for (size_t i = 0; i < size(); ++i) {
    out.at(i) ^= rhs.at(i);
  }
  return out;
}

bytes
from_ascii(const std::string& ascii)
{
  return std::vector<uint8_t>(ascii.begin(), ascii.end());
}

std::string
to_hex(const bytes& data)
{
  std::stringstream hex(std::ios_base::out);
  hex.flags(std::ios::hex);
  for (const auto& byte : data) {
    hex << std::setw(2) << std::setfill('0') << int(byte);
  }
  return hex.str();
}

bytes
from_hex(const std::string& hex)
{
  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  auto len = hex.length() / 2;
  auto out = bytes(len);
  for (size_t i = 0; i < len; i += 1) {
    const std::string byte = hex.substr(2 * i, 2);
    out.at(i) = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
  }

  return out;
}

std::ostream&
operator<<(std::ostream& out, const bytes& data)
{
  // Adjust this threshold to make output more compact
  const size_t threshold = 0xffff;
  if (data.size() < threshold) {
    return out << to_hex(data);
  }

  return out << to_hex(data.slice(0, threshold)) << "...";
}

bool
operator==(const std::vector<uint8_t>& lhs, const bytes_ns::bytes& rhs)
{
  return rhs == lhs;
}

bool
operator!=(const std::vector<uint8_t>& lhs, const bytes_ns::bytes& rhs)
{
  return rhs != lhs;
}

std::string
to_base64(const bytes& data)
{
  bool done = false;
  int result = 0;

  if (data.empty()) {
    return "";
  }

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO* out = BIO_new(BIO_s_mem());
  BIO_push(b64, out);

  while (!done) {
    result = BIO_write(b64, data.data(), static_cast<int>(data.size()));

    if (result <= 0) {
      if (BIO_should_retry(b64)) {
        continue;
      }
      throw std::runtime_error("base64 encode failed");
    }
    done = true;
  }
  BIO_flush(b64);
  char* string_ptr = nullptr;
  // long string_len = BIO_get_mem_data(out, &string_ptr);
  // BIO_get_mem_data failed clang-tidy
  long string_len = BIO_ctrl(out, BIO_CTRL_INFO, 0, &string_ptr);
  auto return_value = std::string(string_ptr, string_len);

  BIO_set_close(out, BIO_NOCLOSE);
  BIO_free(b64);
  BIO_free(out);
  return return_value;
}

std::string
to_base64url(const bytes& data)
{
  if (data.empty()) {
    return "";
  }

  std::string return_value = to_base64(data);

  // remove the end padding
  auto sz = return_value.find_first_of('=');

  if (sz != std::string::npos) {
    return_value = return_value.substr(0, sz);
  }

  // replace plus with hyphen
  std::replace(return_value.begin(), return_value.end(), '+', '-');

  // replace slash with underscore
  std::replace(return_value.begin(), return_value.end(), '/', '_');
  return return_value;
}

bytes
from_base64(const std::string& enc)
{
  if (enc.length() == 0) {
    return {};
  }

  if (enc.length() % 4 != 0) {
    throw std::runtime_error("Base64 length is not divisible by 4");
  }
  bytes input = from_ascii(enc);
  bytes output(input.size() / 4 * 3);
  int output_buffer_length = static_cast<int>(output.size());
  EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
  EVP_DecodeInit(ctx);

  int result = EVP_DecodeUpdate(ctx,
                                output.data(),
                                &output_buffer_length,
                                input.data(),
                                static_cast<int>(input.size()));

  if (result == -1) {
    auto code = ERR_get_error();
    throw std::runtime_error(ERR_error_string(code, nullptr));
  }

  if (result == 0 && enc.substr(enc.length() - 2, enc.length()) == "==") {
    output = output.slice(0, output.size() - 2);
  } else if (result == 0 && enc.substr(enc.length() - 1, enc.length()) == "=") {
    output = output.slice(0, output.size() - 1);
  } else if (result == 0) {
    throw std::runtime_error("Base64 padding was malformed.");
  }
  EVP_DecodeFinal(ctx, output.data(), &output_buffer_length);
  EVP_ENCODE_CTX_free(ctx);
  return output;
}

bytes
from_base64url(const std::string& enc)
{
  if (enc.empty()) {
    return {};
  }
  std::string enc_copy = enc; // copy
  std::replace(enc_copy.begin(), enc_copy.end(), '-', '+');
  std::replace(enc_copy.begin(), enc_copy.end(), '_', '/');

  while (enc_copy.length() % 4 != 0) {
    enc_copy += "=";
  }
  bytes return_value = from_base64(enc_copy);
  return return_value;
}

} // namespace bytes_ns
