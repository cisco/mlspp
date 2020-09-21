#include <mls/session.h>

#include <mls/messages.h>
#include <mls/state.h>

#include <map>

namespace mls {

///
/// Inner struct declarations for PendingJoin and Session
///

struct PendingJoin::Inner
{
  const CipherSuite suite;
  const HPKEPrivateKey init_priv;
  const SignaturePrivateKey sig_priv;
  const KeyPackage key_package;

  Inner(CipherSuite suite_in,
        SignaturePrivateKey sig_priv_in,
        Credential cred_in);

  static PendingJoin create(CipherSuite suite,
                            SignaturePrivateKey sig_priv,
                            Credential cred);
};

struct Session::Inner
{
  std::map<epoch_t, State> state;
  epoch_t current_epoch;
  bool encrypt_handshake;
  std::optional<std::tuple<bytes, State>> outbound_cache;

  static Session begin(const bytes& group_id,
                       const HPKEPrivateKey& init_priv,
                       const SignaturePrivateKey& sig_priv,
                       const KeyPackage& key_package);
  static Session join(const HPKEPrivateKey& init_priv,
                      const SignaturePrivateKey& sig_priv,
                      const KeyPackage& key_package,
                      const bytes& welcome_data);

  bytes fresh_secret() const;
  bytes export_message(const MLSPlaintext& plaintext);
  MLSPlaintext import_message(const bytes& encoded);
  void add_state(epoch_t prior_epoch, const State& group_state);
  const State& current_state() const;
  State& current_state();
};

///
/// Client
///

Client::Client(CipherSuite suite_in,
               SignaturePrivateKey sig_priv_in,
               Credential cred_in)
  : suite(suite_in)
  , sig_priv(std::move(sig_priv_in))
  , cred(std::move(cred_in))
{}

Session
Client::begin_session(const bytes& group_id) const
{
  auto init_priv = HPKEPrivateKey::generate(suite);
  auto kp = KeyPackage{ suite, init_priv.public_key, cred, sig_priv };
  return Session::Inner::begin(group_id, init_priv, sig_priv, kp);
}

PendingJoin
Client::start_join() const
{
  return PendingJoin::Inner::create(suite, sig_priv, cred);
}

///
/// PendingJoin
///

PendingJoin::Inner::Inner(CipherSuite suite_in,
                          SignaturePrivateKey sig_priv_in,
                          Credential cred_in)
  : suite(suite_in)
  , init_priv(HPKEPrivateKey::generate(suite))
  , sig_priv(std::move(sig_priv_in))
  , key_package(suite, init_priv.public_key, cred_in, sig_priv)
{}

PendingJoin
PendingJoin::Inner::create(CipherSuite suite,
                           SignaturePrivateKey sig_priv,
                           Credential cred)
{
  auto inner = std::make_unique<Inner>(suite, sig_priv, cred);
  return PendingJoin(inner.release());
}

PendingJoin::~PendingJoin() = default;

PendingJoin::PendingJoin(Inner* inner_in)
  : inner(inner_in)
{}

bytes
PendingJoin::key_package() const
{
  return tls::marshal(inner->key_package);
}

Session
PendingJoin::complete(const bytes& welcome) const
{
  return Session::Inner::join(
    inner->init_priv, inner->sig_priv, inner->key_package, welcome);
}

///
/// Session
///

Session
Session::Inner::begin(const bytes& group_id,
                      const HPKEPrivateKey& init_priv,
                      const SignaturePrivateKey& sig_priv,
                      const KeyPackage& key_package)
{
  auto inner = std::make_unique<Inner>();
  inner->add_state(
    0,
    { group_id, key_package.cipher_suite, init_priv, sig_priv, key_package });
  return Session(inner.release());
}

Session
Session::Inner::join(const HPKEPrivateKey& init_priv,
                     const SignaturePrivateKey& sig_priv,
                     const KeyPackage& key_package,
                     const bytes& welcome_data)
{
  auto welcome = tls::get<Welcome>(welcome_data);

  auto inner = std::make_unique<Inner>();
  inner->add_state(0, { init_priv, sig_priv, key_package, welcome });
  return Session(inner.release());
}

bytes
Session::Inner::fresh_secret() const
{
  const auto suite = current_state().cipher_suite();
  const auto secret_size = suite.get().hpke.kdf.hash_size();
  return random_bytes(secret_size);
}

bytes
Session::Inner::export_message(const MLSPlaintext& plaintext)
{
  if (!encrypt_handshake) {
    return tls::marshal(plaintext);
  }

  auto ciphertext = current_state().encrypt(plaintext);
  return tls::marshal(ciphertext);
}

MLSPlaintext
Session::Inner::import_message(const bytes& encoded)
{
  if (!encrypt_handshake) {
    return tls::get<MLSPlaintext>(encoded);
  }

  auto ciphertext = tls::get<MLSCiphertext>(encoded);
  return current_state().decrypt(ciphertext);
}

void
Session::Inner::add_state(epoch_t prior_epoch, const State& group_state)
{
  // XXX(rlb@ipv.sx) Assumes no epoch collisions, which is clearly
  // not the case with the current linear updating.
  state.emplace(group_state.epoch(), group_state);

  // XXX(rlb@ipv.sx) First successor updates the head pointer
  if (prior_epoch == current_epoch || state.size() == 1) {
    current_epoch = group_state.epoch();
  }
}

const State&
Session::Inner::current_state() const
{
  if (state.count(current_epoch) == 0) {
    throw MissingStateError("No state available for current epoch");
  }

  return state.at(current_epoch);
}

State&
Session::Inner::current_state()
{
  if (state.count(current_epoch) == 0) {
    throw MissingStateError("No state available for current epoch");
  }

  return state.at(current_epoch);
}

Session::Session(const Session& other)
  : inner(std::make_unique<Inner>(*other.inner))
{}

Session&
Session::operator=(const Session& other)
{
  if (&other != this) {
    inner = std::make_unique<Inner>(*other.inner);
  }
  return *this;
}

Session::~Session() = default;

Session::Session(Inner* inner_in)
  : inner(inner_in)
{}

void
Session::encrypt_handshake(bool enabled)
{
  inner->encrypt_handshake = enabled;
}

bytes
Session::add(const bytes& key_package_data)
{
  auto key_package = tls::get<KeyPackage>(key_package_data);
  auto proposal = inner->current_state().add(key_package);
  return inner->export_message(proposal);
}

bytes
Session::update()
{
  auto leaf_secret = inner->fresh_secret();
  auto proposal = inner->current_state().update(leaf_secret);
  return inner->export_message(proposal);
}

bytes
Session::remove(uint32_t index)
{
  auto proposal = inner->current_state().remove(LeafIndex{ index });
  return inner->export_message(proposal);
}

std::tuple<bytes, bytes>
Session::commit()
{
  auto commit_secret = inner->fresh_secret();
  auto [commit, welcome, new_state] =
    inner->current_state().commit(commit_secret);

  auto commit_msg = inner->export_message(commit);
  auto welcome_msg = tls::marshal(welcome);

  inner->outbound_cache = std::make_tuple(commit_msg, new_state);
  return std::make_tuple(welcome_msg, commit_msg);
}

bool
Session::handle(const bytes& handshake_data)
{
  auto handshake = inner->import_message(handshake_data);

  if (handshake.sender.sender_type != SenderType::member) {
    throw ProtocolError("External senders not supported");
  }

  auto is_commit = std::holds_alternative<CommitData>(handshake.content);
  if (is_commit &&
      LeafIndex(handshake.sender.sender) == inner->current_state().index()) {
    if (!inner->outbound_cache.has_value()) {
      throw ProtocolError("Received from self without sending");
    }

    const auto& cached_msg = std::get<0>(inner->outbound_cache.value());
    const auto& next_state = std::get<1>(inner->outbound_cache.value());
    if (cached_msg != handshake_data) {
      throw ProtocolError("Received message different from cached");
    }

    inner->add_state(handshake.epoch, next_state);
    inner->outbound_cache = std::nullopt;
    return true;
  }

  auto maybe_next_state = inner->current_state().handle(handshake);
  if (!maybe_next_state.has_value()) {
    return false;
  }

  inner->add_state(handshake.epoch, maybe_next_state.value());
  return true;
}

epoch_t
Session::current_epoch() const
{
  return inner->current_epoch;
}

uint32_t
Session::index() const
{
  return inner->current_state().index().val;
}

bytes
Session::protect(const bytes& plaintext)
{
  auto ciphertext = inner->current_state().protect(plaintext);
  return tls::marshal(ciphertext);
}

// TODO(rlb@ipv.sx): It would be good to expose identity information
// here, since ciphertexts are authenticated per sender.  Who sent
// this ciphertext?
bytes
Session::unprotect(const bytes& ciphertext)
{
  auto ciphertext_obj = tls::get<MLSCiphertext>(ciphertext);
  if (inner->state.count(ciphertext_obj.epoch) == 0) {
    throw MissingStateError("No state available to decrypt ciphertext");
  }

  auto& state = inner->state.at(ciphertext_obj.epoch);
  return state.unprotect(ciphertext_obj);
}

bool
operator==(const Session& lhs, const Session& rhs)
{
  if (lhs.inner->encrypt_handshake != rhs.inner->encrypt_handshake) {
    return false;
  }

  if (lhs.inner->current_epoch != rhs.inner->current_epoch) {
    return false;
  }

  for (const auto& pair : lhs.inner->state) {
    if (rhs.inner->state.count(pair.first) == 0) {
      continue;
    }

    if (rhs.inner->state.at(pair.first) != pair.second) {
      return false;
    }
  }

  return true;
}

bool
operator!=(const Session& lhs, const Session& rhs)
{
  return !(lhs == rhs);
}

} // namespace mls
