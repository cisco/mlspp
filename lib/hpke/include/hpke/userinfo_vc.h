#pragma once
#include <memory>
#include <optional>

#include <bytes/bytes.h>
#include <chrono>
#include <hpke/signature.h>
#include <map>

using namespace MLS_NAMESPACE::bytes_ns;

namespace MLS_NAMESPACE::hpke {

struct UserInfoVC
{
private:
  struct ParsedCredential;
  std::shared_ptr<ParsedCredential> parsed_cred;

public:
  explicit UserInfoVC(std::string jwt,
                      const std::map<std::string, std::string>& keep_list);
  UserInfoVC() = default;
  UserInfoVC(const UserInfoVC& other) = default;
  ~UserInfoVC() = default;
  UserInfoVC& operator=(const UserInfoVC& other) = default;
  UserInfoVC& operator=(UserInfoVC&& other) = default;

  std::string issuer() const;
  std::string key_id() const;
  std::chrono::system_clock::time_point not_before() const;
  std::chrono::system_clock::time_point not_after() const;
  std::map<std::string, std::string> subject() const;
  const Signature::PublicJWK& public_key() const;

  bool valid_from(const Signature::PublicKey& issuer_key) const;

  std::string raw;
};

bool
operator==(const UserInfoVC& lhs, const UserInfoVC& rhs);

} // namespace MLS_NAMESPACE::hpke
