#include "draft-08.h"

namespace draft08 {

tls::ostream&
operator<<(tls::ostream& str, const Welcome& obj)
{
  str << obj.version << obj.cipher_suite << obj.key_packages
      << obj.encrypted_group_info;
  return str;
}

tls::istream&
operator>>(tls::istream& str, Welcome& obj)
{
  str >> obj.version >> obj.cipher_suite;

  obj.key_packages =
    tls::variant_vector<EncryptedKeyPackage, CipherSuite, 4>(obj.cipher_suite);
  str >> obj.key_packages >> obj.encrypted_group_info;
  return str;
}

} // namespace draft08
