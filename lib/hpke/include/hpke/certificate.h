#pragma once
#include <memory>
#include <optional>

#include <bytes/bytes.h>
#include <hpke/signature.h>

using namespace bytes_ns;

namespace hpke {

struct Certificate
{
private:
  struct ParsedCertificate;
  std::unique_ptr<ParsedCertificate> parsed_cert;

public:
  explicit Certificate(const bytes& der);
  Certificate() = delete;
  Certificate(const Certificate& other);
  ~Certificate();

  bool valid_from(const Certificate& parent) const;

  // Accessors for parsed certificate elements
  uint64_t issuer() const;          // hash of the issuer
  uint64_t subject() const;         // hash of the subject
  std::string subject_name() const; // textual format of the subject CN
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
