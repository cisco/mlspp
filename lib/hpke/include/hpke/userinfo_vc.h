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
  std::unique_ptr<ParsedCredential> parsed_cred;

public:
  explicit UserInfoVC(std::string jwt);
  UserInfoVC() = delete;
  UserInfoVC(const UserInfoVC& other);
  ~UserInfoVC() = default;

  std::string issuer() const;
  std::string key_id() const;
  bool valid_from(const Signature::PublicKey& issuer_key) const;

  // Accessors
  std::map<std::string, std::string> subject() const;
  std::chrono::system_clock::time_point not_before() const;
  std::chrono::system_clock::time_point not_after() const;

  const std::string raw;
};

bool
operator==(const UserInfoVC& lhs, const UserInfoVC& rhs);

} // namespace hpke
