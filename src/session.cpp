#include <mls/session.h>

#include <mls/messages.h>
#include <mls/state.h>

#include <deque>

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
        Credential cred_in,
        const std::optional<KeyPackageOpts>& opts_in);

  static PendingJoin create(CipherSuite suite,
                            SignaturePrivateKey sig_priv,
                            Credential cred,
                            const std::optional<KeyPackageOpts>& opts_in);
};

struct Session::Inner
{
  std::deque<State> history;
  std::optional<std::tuple<bytes, State>> outbound_cache;
  bool encrypt_handshake;

  explicit Inner(State state);

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
  State& for_epoch(epoch_t epoch);
};

///
/// Client
///

Client::Client(CipherSuite suite_in,
               SignaturePrivateKey sig_priv_in,
               Credential cred_in,
               std::optional<KeyPackageOpts> opts_in)
  : suite(suite_in)
  , sig_priv(std::move(sig_priv_in))
  , cred(std::move(cred_in))
  , opts(std::move(opts_in))
{}

Session
Client::begin_session(const bytes& group_id) const
{
  auto init_priv = HPKEPrivateKey::generate(suite);
  auto kp = KeyPackage{ suite, init_priv.public_key, cred, sig_priv, opts };
  return Session::Inner::begin(group_id, init_priv, sig_priv, kp);
}

PendingJoin
Client::start_join() const
{
  return PendingJoin::Inner::create(suite, sig_priv, cred, opts);
}

///
/// PendingJoin
///

PendingJoin::Inner::Inner(CipherSuite suite_in,
                          SignaturePrivateKey sig_priv_in,
                          Credential cred_in,
                          const std::optional<KeyPackageOpts>& opts_in)
  : suite(suite_in)
  , init_priv(HPKEPrivateKey::generate(suite))
  , sig_priv(std::move(sig_priv_in))
  , key_package(suite,
                init_priv.public_key,
                std::move(cred_in),
                sig_priv,
                opts_in)
{}

PendingJoin
PendingJoin::Inner::create(CipherSuite suite,
                           SignaturePrivateKey sig_priv,
                           Credential cred,
                           const std::optional<KeyPackageOpts>& opts_in)
{
  auto inner = std::make_unique<Inner>(
    suite, std::move(sig_priv), std::move(cred), opts_in);
  return PendingJoin(inner.release());
}

PendingJoin::PendingJoin(PendingJoin&& other) noexcept = default;

PendingJoin&
PendingJoin::operator=(PendingJoin&& other) noexcept = default;

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

Session::Inner::Inner(State state)
  : history{ std::move(state) }
  , encrypt_handshake(true)
{}

Session
Session::Inner::begin(const bytes& group_id,
                      const HPKEPrivateKey& init_priv,
                      const SignaturePrivateKey& sig_priv,
                      const KeyPackage& key_package)
{
  auto state =
    State(group_id, key_package.cipher_suite, init_priv, sig_priv, key_package);
  auto inner = std::make_unique<Inner>(state);
  return Session(inner.release());
}

Session
Session::Inner::join(const HPKEPrivateKey& init_priv,
                     const SignaturePrivateKey& sig_priv,
                     const KeyPackage& key_package,
                     const bytes& welcome_data)
{
  auto welcome = tls::get<Welcome>(welcome_data);

  auto state = State(init_priv, sig_priv, key_package, welcome);
  auto inner = std::make_unique<Inner>(state);
  return Session(inner.release());
}

bytes
Session::Inner::fresh_secret() const
{
  const auto suite = history.front().cipher_suite();
  return random_bytes(suite.secret_size());
}

bytes
Session::Inner::export_message(const MLSPlaintext& plaintext)
{
  if (!encrypt_handshake) {
    return tls::marshal(plaintext);
  }

  auto ciphertext = history.front().encrypt(plaintext);
  return tls::marshal(ciphertext);
}

MLSPlaintext
Session::Inner::import_message(const bytes& encoded)
{
  if (!encrypt_handshake) {
    return tls::get<MLSPlaintext>(encoded);
  }

  auto ciphertext = tls::get<MLSCiphertext>(encoded);
  return history.front().decrypt(ciphertext);
}

void
Session::Inner::add_state(epoch_t prior_epoch, const State& state)
{
  if (!history.empty() && prior_epoch != history.front().epoch()) {
    throw MissingStateError("Discontinuity in history");
  }

  history.emplace_front(state);

  // TODO(rlb) bound the size of the queue
}

State&
Session::Inner::for_epoch(epoch_t epoch)
{
  for (auto& state : history) {
    if (state.epoch() == epoch) {
      return state;
    }
  }

  throw MissingStateError("No state for epoch");
}

Session::Session(Session&& other) noexcept = default;

Session&
Session::operator=(Session&& other) noexcept = default;

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
  auto proposal = inner->history.front().add(key_package);
  return inner->export_message(proposal);
}

bytes
Session::update()
{
  auto leaf_secret = inner->fresh_secret();
  auto proposal = inner->history.front().update(leaf_secret);
  return inner->export_message(proposal);
}

bytes
Session::remove(uint32_t index)
{
  auto proposal = inner->history.front().remove(RosterIndex{ index });
  return inner->export_message(proposal);
}

std::tuple<bytes, bytes>
Session::commit(const bytes& proposal)
{
  return commit(std::vector<bytes>{ proposal });
}

std::tuple<bytes, bytes>
Session::commit(const std::vector<bytes>& proposals)
{
  for (const auto& proposal_data : proposals) {
    const auto pt = inner->import_message(proposal_data);
    if (!var::holds_alternative<Proposal>(pt.content)) {
      throw ProtocolError("Only proposals can be committed");
    }

    inner->history.front().handle(pt);
  }

  return commit();
}

std::tuple<bytes, bytes>
Session::commit()
{
  auto commit_secret = inner->fresh_secret();
  auto [commit, welcome, new_state] =
    inner->history.front().commit(commit_secret);

  auto commit_msg = inner->export_message(commit);
  auto welcome_msg = tls::marshal(welcome);

  inner->outbound_cache = std::make_tuple(commit_msg, new_state);
  return std::make_tuple(welcome_msg, commit_msg);
}

bool
Session::handle(const bytes& handshake_data)
{
  auto pt = inner->import_message(handshake_data);

  if (pt.sender.sender_type != SenderType::member) {
    throw ProtocolError("External senders not supported");
  }

  const auto is_commit = var::holds_alternative<Commit>(pt.content);
  if (is_commit &&
      LeafIndex(pt.sender.sender) == inner->history.front().index()) {
    if (!inner->outbound_cache) {
      throw ProtocolError("Received from self without sending");
    }

    const auto& [msg, state] = opt::get(inner->outbound_cache);
    if (msg != handshake_data) {
      throw ProtocolError("Received message different from cached");
    }

    inner->add_state(pt.epoch, state);
    inner->outbound_cache = std::nullopt;
    return true;
  }

  auto maybe_next_state = inner->history.front().handle(pt);
  if (!maybe_next_state) {
    return false;
  }

  inner->add_state(pt.epoch, opt::get(maybe_next_state));
  return true;
}

epoch_t
Session::current_epoch() const
{
  return inner->history.front().epoch();
}

uint32_t
Session::index() const
{
  return inner->history.front().index().val;
}

bytes
Session::do_export(const std::string& label,
                   const bytes& context,
                   size_t size) const
{
  return inner->history.front().do_export(label, context, size);
}

std::vector<KeyPackage>
Session::roster() const
{
  return inner->history.front().roster();
}

bytes
Session::authentication_secret() const
{
  return inner->history.front().authentication_secret();
}

bytes
Session::protect(const bytes& plaintext)
{
  auto ciphertext = inner->history.front().protect(plaintext);
  return tls::marshal(ciphertext);
}

// TODO(rlb@ipv.sx): It would be good to expose identity information
// here, since ciphertexts are authenticated per sender.  Who sent
// this ciphertext?
bytes
Session::unprotect(const bytes& ciphertext)
{
  auto ciphertext_obj = tls::get<MLSCiphertext>(ciphertext);
  auto& state = inner->for_epoch(ciphertext_obj.epoch);
  return state.unprotect(ciphertext_obj);
}

bool
operator==(const Session& lhs, const Session& rhs)
{
  if (lhs.inner->encrypt_handshake != rhs.inner->encrypt_handshake) {
    return false;
  }

  auto size = std::min(lhs.inner->history.size(), rhs.inner->history.size());
  for (size_t i = 0; i < size; i += 1) {
    if (lhs.inner->history.at(i) != rhs.inner->history.at(i)) {
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
