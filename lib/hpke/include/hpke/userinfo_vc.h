#pragma once
#include <memory>
#include <optional>

#include <bytes/bytes.h>
#include <chrono>
#include <hpke/signature.h>
#include <map>

using namespace bytes_ns;

namespace hpke {

struct UserInfoVC
{
private:
  struct ParsedCredential;
  std::shared_ptr<ParsedCredential> parsed_cred;

public:
  explicit UserInfoVC(std::string jwt);
  UserInfoVC() = default;
  UserInfoVC(const UserInfoVC& other) = default;
  ~UserInfoVC() = default;

  std::string issuer() const;
  std::string key_id() const;
  std::chrono::system_clock::time_point not_before() const;
  std::chrono::system_clock::time_point not_after() const;
  std::map<std::string, std::string> subject() const;
  Signature::ID public_key_algorithm() const;
  const Signature::PublicKey public_key() const;

  bool valid_from(const Signature::PublicKey& issuer_key) const;

  const std::string raw;
};

bool
operator==(const UserInfoVC& lhs, const UserInfoVC& rhs);

} // namespace hpke
