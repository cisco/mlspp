#include "credential.h"
#include "tls_syntax.h"

#define DUMMY_SIG_SCHEME SignatureScheme::P256_SHA256

namespace mls {

///
/// CredentialType
///

tls::ostream&
operator<<(tls::ostream& out, CredentialType type)
{
  return out << uint8_t(type);
}

tls::istream&
operator>>(tls::istream& in, CredentialType& type)
{
  uint8_t temp;
  in >> temp;
  type = CredentialType(temp);
  return in;
}

///
/// BasicCredential
///

// struct {
//     opaque identity<0..2^16-1>;
//     SignatureScheme algorithm;
//     SignaturePublicKey public_key;
// } BasicCredential;
class BasicCredential : public AbstractCredential
{
public:
  BasicCredential();
  BasicCredential(bytes identity, SignaturePublicKey public_key);

  std::unique_ptr<AbstractCredential> dup() const override;
  bytes identity() const override;
  SignaturePublicKey public_key() const override;
  void read(tls::istream& in) override;
  void write(tls::ostream& out) const override;
  bool equal(const AbstractCredential* other) const override;

private:
  tls::opaque<2> _identity;
  SignaturePublicKey _public_key;
};

BasicCredential::BasicCredential()
  : _public_key(DUMMY_SIG_SCHEME)
{}

BasicCredential::BasicCredential(bytes identity, SignaturePublicKey public_key)
  : _identity(std::move(identity))
  , _public_key(std::move(public_key))
{}

std::unique_ptr<AbstractCredential>
BasicCredential::dup() const
{
  return std::make_unique<BasicCredential>(_identity, _public_key);
}

bytes
BasicCredential::identity() const
{
  return _identity;
}

SignaturePublicKey
BasicCredential::public_key() const
{
  return _public_key;
}

void
BasicCredential::read(tls::istream& in)
{
  SignatureScheme scheme;
  in >> _identity >> scheme;

  _public_key = SignaturePublicKey(scheme);
  in >> _public_key;
}

void
BasicCredential::write(tls::ostream& out) const
{
  out << _identity << _public_key.signature_scheme() << _public_key;
}

bool
BasicCredential::equal(const AbstractCredential* other) const
{
  auto basic_other = dynamic_cast<const BasicCredential*>(other);
  return (_identity == basic_other->_identity) &&
         (_public_key == basic_other->_public_key);
}

///
/// Credential
///

Credential::Credential(const Credential& other)
  : _type(other._type)
  , _cred(nullptr)
{
  if (other._cred) {
    _cred = other._cred->dup();
  }
  if (other._priv.has_value()) {
    _priv = other._priv.value();
  }
}

Credential::Credential(Credential&& other) noexcept
  : _type(other._type)
  , _cred(nullptr)
{
  if (other._cred) {
    _cred = std::move(other._cred);
  }
  if (other._priv.has_value()) {
    _priv = other._priv.value();
  }
}

Credential&
Credential::operator=(const Credential& other)
{
  if (this != &other) {
    _type = other._type;
    _cred.reset(nullptr);
    if (other._cred) {
      _cred = other._cred->dup();
    }
    if (other._priv.has_value()) {
      _priv = other._priv.value();
    }
  }
  return *this;
}

bytes
Credential::identity() const
{
  return _cred->identity();
}

SignaturePublicKey
Credential::public_key() const
{
  return _cred->public_key();
}

bool
Credential::valid_for(const SignaturePrivateKey& priv) const
{
  return priv.public_key() == public_key();
}

Credential
Credential::basic(const bytes& identity, const SignaturePublicKey& public_key)
{
  auto cred = Credential{};
  cred._type = CredentialType::basic;
  cred._cred = std::make_unique<BasicCredential>(identity, public_key);
  cred._priv = std::nullopt;
  return cred;
}

Credential
Credential::basic(const bytes& identity, const SignaturePrivateKey& private_key)
{
  auto cred = Credential{};
  cred._type = CredentialType::basic;
  cred._cred =
    std::make_unique<BasicCredential>(identity, private_key.public_key());
  cred._priv = private_key;
  return cred;
}

std::optional<SignaturePrivateKey>
Credential::private_key() const
{
  return _priv;
}

AbstractCredential*
Credential::create(CredentialType type)
{
  switch (type) {
    case CredentialType::basic:
      return new BasicCredential();

    case CredentialType::x509:
      throw NotImplementedError();

    default:
      throw InvalidParameterError("Unknown credential type");
  }
}

bool
operator==(const Credential& lhs, const Credential& rhs)
{
  auto type = (lhs._type == rhs._type);
  auto cred = lhs._cred->equal(rhs._cred.get());
  return type && cred;
}

bool
operator!=(const Credential& lhs, const Credential& rhs)
{
  return !(lhs == rhs);
}

tls::ostream&
operator<<(tls::ostream& out, const Credential& obj)
{
  out << obj._type;
  obj._cred->write(out);
  return out;
}

tls::istream&
operator>>(tls::istream& in, Credential& obj)
{
  in >> obj._type;
  obj._cred.reset(Credential::create(obj._type));
  obj._cred->read(in);
  return in;
}

} // namespace mls
