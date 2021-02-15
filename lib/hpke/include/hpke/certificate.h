#pragma once
#include <memory>
#include <optional>

#include <bytes/bytes.h>
#include <hpke/signature.h>
#include <map>

using namespace bytes_ns;

namespace hpke {

struct Certificate
{
private:
  struct ParsedCertificate;
  std::unique_ptr<ParsedCertificate> parsed_cert;

public:
  struct NameType
  {
    static const int organization;
    static const int common_name;
    static const int organizational_unit;
    static const int country;
    static const int serial_number;
    static const int state_or_province_name;
  };

  using ParsedName = std::map<int, std::string>;

  explicit Certificate(const bytes& der);
  Certificate() = delete;
  Certificate(const Certificate& other);
  ~Certificate();

  bool valid_from(const Certificate& parent) const;

  // Accessors for parsed certificate elements
  uint64_t issuer_hash() const;
  uint64_t subject_hash() const;
  ParsedName issuer() const;
  ParsedName subject() const;
  bool is_ca() const;
  std::optional<bytes> subject_key_id() const;
  std::optional<bytes> authority_key_id() const;
  std::vector<std::string> email_addresses() const;
  std::vector<std::string> dns_names() const;
  bytes hash() const;

  const Signature::ID public_key_algorithm;
  const std::unique_ptr<Signature::PublicKey> public_key;
  const bytes raw;
};

} // namespace hpke
