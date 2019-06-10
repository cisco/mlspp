#include "state.h"

#include <iostream>

namespace mls {

///
/// GroupContext
///

tls::ostream&
operator<<(tls::ostream& out, const GroupContext& obj)
{
  return out << obj.group_id << obj.epoch << obj.tree_hash
             << obj.transcript_hash;
}

tls::istream&
operator>>(tls::istream& out, GroupContext& obj)
{
  return out >> obj.group_id >> obj.epoch >> obj.tree_hash >>
         obj.transcript_hash;
}

///
/// ApplicationKeyChain
///

const char* KeyChain::_secret_label = "sender";
const char* KeyChain::_nonce_label = "nonce";
const char* KeyChain::_key_label = "key";

void
KeyChain::start(LeafIndex my_sender, const bytes& root_secret)
{
  _my_generation = 0;
  _my_sender = my_sender;
  _root_secret = root_secret;
}

KeyChain::Generation
KeyChain::next()
{
  _my_generation += 1;
  return get(_my_sender, _my_generation);
}

KeyChain::Generation
KeyChain::get(LeafIndex sender, uint32_t generation) const
{
  auto sender_bytes = tls::marshal(sender.val);
  auto secret = _root_secret;

  // Split off onto the sender chain
  secret = derive(secret, _secret_label, sender_bytes, _secret_size);

  // Work down the generations
  for (uint32_t i = 0; i < generation; ++i) {
    secret = derive(secret, _secret_label, sender_bytes, _secret_size);
  }

  auto key = hkdf_expand_label(_suite, secret, _key_label, {}, _key_size);
  auto nonce = hkdf_expand_label(_suite, secret, _nonce_label, {}, _nonce_size);

  return Generation{ generation, secret, key, nonce };
}

bytes
KeyChain::derive(const bytes& secret,
                 const std::string& label,
                 const bytes& context,
                 const size_t size) const
{
  return hkdf_expand_label(_suite, secret, label, context, size);
}

///
/// Constructors
///

State::State(bytes group_id,
             CipherSuite suite,
             const bytes& leaf_secret,
             SignaturePrivateKey identity_priv,
             const Credential& credential)
  : _suite(suite)
  , _group_id(std::move(group_id))
  , _epoch(0)
  , _tree(suite, leaf_secret, credential)
  , _init_secret(Digest(suite).output_size())
  , _application_keys(suite)
  , _index(0)
  , _identity_priv(std::move(identity_priv))
  , _zero(Digest(suite).output_size(), 0)
{}

State::State(SignaturePrivateKey identity_priv,
             const Credential& credential,
             const bytes& init_secret,
             const Welcome& welcome,
             const MLSPlaintext& handshake)
  : _suite(welcome.cipher_suite)
  , _tree(welcome.cipher_suite)
  , _application_keys(welcome.cipher_suite)
  , _identity_priv(std::move(identity_priv))
{
  // Verify that we have an add and it is for us
  const auto& operation = handshake.operation.value();
  if (handshake.operation.value().type != GroupOperationType::add) {
    throw InvalidParameterError("Incorrect handshake type");
  }

  const auto& add = operation.add.value();
  if (credential != add.init_key.credential) {
    throw InvalidParameterError("Add not targeted for this node");
  }

  // Make sure that the init key for the chosen ciphersuite is the
  // one we sent
  auto init_cik = add.init_key.find_init_key(_suite);
  if (!init_cik) {
    throw ProtocolError("Selected cipher suite not supported");
  }

  auto init_priv = DHPrivateKey::node_derive(_suite, init_secret);
  if (*init_cik != init_priv.public_key()) {
    throw ProtocolError("Incorrect init key");
  }

  // Decrypt the Welcome
  auto welcome_info = welcome.decrypt(init_priv);

  // Make sure the WelcomeInfo matches the Add
  if (add.welcome_info_hash != welcome_info.hash(_suite)) {
    throw ProtocolError("Mismatch in welcome info hash");
  }

  // Ingest the WelcomeInfo
  _epoch = welcome_info.epoch + 1;
  _group_id = welcome_info.group_id;
  _tree = welcome_info.tree;
  _interim_transcript_hash = welcome_info.interim_transcript_hash;

  _init_secret = welcome_info.init_secret;
  _zero = bytes(Digest(_suite).output_size(), 0);

  // Add to the transcript hash
  update_transcript_hash(handshake);

  // Add to the tree
  _index = add.index;
  _tree.add_leaf(_index, init_secret, credential);

  // Ratchet forward into shared state
  update_epoch_secrets(_zero);

  if (!verify(handshake)) {
    throw InvalidParameterError("Handshake signature failed to verify");
  }
}

State::InitialInfo
State::negotiate(const bytes& group_id,
                 const std::vector<CipherSuite> supported_ciphersuites,
                 const bytes& leaf_secret,
                 const SignaturePrivateKey& identity_priv,
                 const Credential& credential,
                 const ClientInitKey& client_init_key)
{
  // Negotiate a ciphersuite with the other party
  CipherSuite suite;
  auto selected = false;
  for (auto my_suite : supported_ciphersuites) {
    for (auto other_suite : client_init_key.cipher_suites) {
      if (my_suite == other_suite) {
        selected = true;
        suite = my_suite;
        break;
      }
    }

    if (selected) {
      break;
    }
  }

  if (!selected) {
    throw ProtocolError("Negotiation failure");
  }

  // We have manually guaranteed that `suite` is always initialized
  // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
  auto state = State{ group_id, suite, leaf_secret, identity_priv, credential };
  return state.add(client_init_key);
}

///
/// Message factories
///

std::tuple<Welcome, MLSPlaintext, State>
State::add(const ClientInitKey& client_init_key) const
{
  return add(_tree.size(), client_init_key);
}

std::tuple<Welcome, MLSPlaintext, State>
State::add(uint32_t index, const ClientInitKey& client_init_key) const
{
  if (!client_init_key.verify()) {
    throw InvalidParameterError("bad signature on user init key");
  }

  auto pub = client_init_key.find_init_key(_suite);
  if (!pub) {
    throw ProtocolError("New member does not support the group's ciphersuite");
  }

  auto welcome_info_str = welcome_info();
  auto welcome =
    Welcome{ client_init_key.client_init_key_id, *pub, welcome_info_str };
  auto welcome_tuple = std::make_tuple(welcome);

  auto welcome_info_hash = welcome_info_str.hash(_suite);
  auto add_state =
    sign(Add{ LeafIndex{ index }, client_init_key, welcome_info_hash });
  return std::tuple_cat(welcome_tuple, add_state);
}

std::tuple<MLSPlaintext, State>
State::update(const bytes& leaf_secret)
{
  /* xxx
  auto path = _tree.encrypt(_index, leaf_secret);
  _cached_leaf_secret = leaf_secret;
  return sign(Update{ path });
  */

  auto next = *this;
  DirectPath path(_suite);
  bytes update_secret;
  std::tie(path, update_secret) = next._tree.encrypt(_index, leaf_secret);
  auto update = Update{ path };

  // TODO encapsulate the below in a new ratchet_and_sign() method
  auto handshake = MLSPlaintext{ _group_id, _epoch, _index, update };
  next.update_transcript_hash(handshake);
  next._epoch += 1;
  next.update_epoch_secrets(update_secret);

  handshake.confirmation =
    hmac(_suite, next._confirmation_key, next._confirmed_transcript_hash);
  handshake.sign(_identity_priv);

  std::cout << "conf_gen " << _index.val << std::endl;
  std::cout << "         " << next._confirmation_key << std::endl;
  std::cout << "       + " << next._confirmed_transcript_hash << std::endl;
  std::cout << "       = " << handshake.confirmation << std::endl;

  next._interim_transcript_hash = _interim_transcript_hash;
  next.update_transcript_hash(handshake);

  return std::make_tuple(handshake, next);
}

std::tuple<MLSPlaintext, State>
State::remove(const bytes& leaf_secret, uint32_t index)
{
  if (index >= _tree.size()) {
    throw InvalidParameterError("Index too large for tree");
  }

  if (index == _index.val) {
    throw InvalidParameterError("Cannot self-remove");
  }

  /* xxx
  auto tree = _tree;
  tree.blank_path(LeafIndex{ index });
  auto cut = tree.leaf_span();
  tree.truncate(cut);

  _cached_leaf_secret = leaf_secret;
  auto path = tree.encrypt(_index, leaf_secret);

  return sign(Remove{ LeafIndex{ index }, path });
  */

  auto next = *this;
  next._tree.blank_path(LeafIndex{ index });
  auto cut = next._tree.leaf_span();
  next._tree.truncate(cut);

  DirectPath path(_suite);
  bytes update_secret;
  std::tie(path, update_secret) = next._tree.encrypt(_index, leaf_secret);

  auto remove = Remove{ LeafIndex{ index }, path };

  // TODO encapsulate the below in a new ratchet_and_sign() method
  auto handshake = MLSPlaintext{ _group_id, _epoch, _index, remove };
  next.update_transcript_hash(handshake);
  next._epoch += 1;
  next.update_epoch_secrets(update_secret);

  handshake.confirmation =
    hmac(_suite, next._confirmation_key, next._confirmed_transcript_hash);
  handshake.sign(_identity_priv);

  next._interim_transcript_hash = _interim_transcript_hash;
  next.update_transcript_hash(handshake);

  return std::make_tuple(handshake, next);
}

///
/// Message handlers
///

State
State::apply(const MLSPlaintext& handshake) const
{
  const auto& operation = handshake.operation.value();
  auto next = *this;

  bytes update_secret;
  switch (operation.type) {
    case GroupOperationType::add:
      update_secret = next.handle(operation.add.value());
      break;
    case GroupOperationType::update:
      update_secret = next.handle(handshake.sender, operation.update.value());
      break;
    case GroupOperationType::remove:
      update_secret = next.handle(handshake.sender, operation.remove.value());
      break;
  }

  next.update_transcript_hash(handshake);
  next._epoch += 1;
  next.update_epoch_secrets(update_secret);
  return next;
}

State
State::handle(const MLSPlaintext& handshake) const
{
  // Pre-validate the MLSPlaintext
  if (handshake.group_id != _group_id) {
    throw InvalidParameterError("GroupID mismatch");
  }

  if (handshake.epoch != _epoch) {
    throw InvalidParameterError("Epoch mismatch");
  }

  if (handshake.content_type != ContentType::handshake) {
    throw InvalidParameterError("Incorrect content type");
  }

  if (handshake.sender == _index &&
      handshake.operation.value().type != GroupOperationType::add) {
    // xxx: remove add caveat
    throw InvalidParameterError("Handle own messages with caching");
  }

  if (!verify(handshake)) {
    throw ProtocolError("Invalid handshake message signature");
  }

  // Apply the operation
  auto next = apply(handshake);

  // Verify the  confirmation MAC
  if (!next.verify_confirmation(handshake.confirmation)) {
    throw InvalidParameterError("Invalid confirmation MAC");
  }

  return next;
}

bytes
State::handle(const Add& add)
{
  // Verify the ClientInitKey in the Add message
  if (!add.init_key.verify()) {
    throw InvalidParameterError("Invalid signature on init key in group add");
  }

  // Verify the index in the Add message
  if (add.index.val > _tree.size()) {
    throw InvalidParameterError("Invalid leaf index");
  }
  if (add.index.val < _tree.size() && _tree.occupied(add.index)) {
    throw InvalidParameterError("Leaf is not available for add");
  }

  // Verify the WelcomeInfo hash
  if (add.welcome_info_hash != welcome_info().hash(_suite)) {
    throw ProtocolError("Mismatch in welcome info hash");
  }

  // Add to the tree
  auto init_key = add.init_key.find_init_key(_suite);
  if (!init_key) {
    throw ProtocolError("New node does not support group's cipher suite");
  }
  _tree.add_leaf(add.index, *init_key, add.init_key.credential);

  return _zero;
}

bytes
State::handle(LeafIndex sender, const Update& update)
{
  std::optional<bytes> leaf_secret = std::nullopt;
  /* xxx
  if (sender == _index) {
    if (_cached_leaf_secret.empty()) {
      throw InvalidParameterError("Got self-update without generating one");
    }

    leaf_secret = _cached_leaf_secret;
    _cached_leaf_secret.clear();
  }
  */

  return update_leaf(sender, update.path, leaf_secret);
}

bytes
State::handle(LeafIndex sender, const Remove& remove)
{
  _tree.blank_path(remove.removed);
  auto cut = _tree.leaf_span();
  _tree.truncate(cut);

  std::optional<bytes> leaf_secret = std::nullopt;
  /* xxx
  if (sender == _index) {
    if (_cached_leaf_secret.empty()) {
      throw InvalidParameterError(
        "Got remove from myself without generating one");
    }

    leaf_secret = _cached_leaf_secret;
    _cached_leaf_secret.clear();
  }
  */

  return update_leaf(sender, remove.path, leaf_secret);
}

State::EpochSecrets
State::derive_epoch_secrets(CipherSuite suite,
                            const bytes& init_secret,
                            const bytes& update_secret,
                            const bytes& group_context)
{
  auto epoch_secret = hkdf_extract(suite, init_secret, update_secret);
  return {
    epoch_secret,
    derive_secret(suite, epoch_secret, "app", group_context),
    derive_secret(suite, epoch_secret, "handshake", group_context),
    derive_secret(suite, epoch_secret, "sender data", group_context),
    derive_secret(suite, epoch_secret, "confirm", group_context),
    derive_secret(suite, epoch_secret, "init", group_context),
  };
}

///
/// Message protection
///

MLSCiphertext
State::protect(const bytes& data)
{
  MLSPlaintext pt{ _group_id, _epoch, _index, data };
  pt.sign(_identity_priv);

  return encrypt(pt);
}

bytes
State::unprotect(const MLSCiphertext& ct)
{
  MLSPlaintext pt = decrypt(ct);

  if (!verify(pt)) {
    throw ProtocolError("Invalid message signature");
  }

  if (pt.content_type != ContentType::application) {
    throw ProtocolError("Unprotect of non-application message");
  }

  return pt.application_data;
}

///
/// Inner logic and convenience functions
///

bool
operator==(const State& lhs, const State& rhs)
{
  auto suite = (lhs._suite == rhs._suite);
  auto group_id = (lhs._group_id == rhs._group_id);
  auto epoch = (lhs._epoch == rhs._epoch);
  auto tree = (lhs._tree == rhs._tree);
  auto confirmed_transcript_hash =
    (lhs._confirmed_transcript_hash == rhs._confirmed_transcript_hash);
  auto interim_transcript_hash =
    (lhs._interim_transcript_hash == rhs._interim_transcript_hash);
  auto group_context = (lhs._group_context == rhs._group_context);

  auto epoch_secret = (lhs._epoch_secret == rhs._epoch_secret);
  auto application_secret =
    (lhs._application_secret == rhs._application_secret);
  auto confirmation_key = (lhs._confirmation_key == rhs._confirmation_key);
  auto init_secret = (lhs._init_secret == rhs._init_secret);

  return suite && group_id && epoch && tree && confirmed_transcript_hash &&
         interim_transcript_hash && group_context && epoch_secret &&
         application_secret && confirmation_key && init_secret;
}

bool
operator!=(const State& lhs, const State& rhs)
{
  return !(lhs == rhs);
}

WelcomeInfo
State::welcome_info() const
{
  return { _group_id, _epoch, _tree, _interim_transcript_hash, _init_secret };
}

void
State::update_transcript_hash(const MLSPlaintext& plaintext)
{
  // Transcript hash for use in this epoch
  _confirmed_transcript_hash = Digest(_suite)
                                 .write(_interim_transcript_hash)
                                 .write(plaintext.content())
                                 .digest();

  // Transcript hash input for the next epoch
  _interim_transcript_hash = Digest(_suite)
                               .write(_confirmed_transcript_hash)
                               .write(plaintext.auth_data())
                               .digest();

  std::cout << "upd_tx " << _index.val << std::endl;
  std::cout << "    ++ " << plaintext.content() << std::endl;
  std::cout << "    -> " << _confirmed_transcript_hash << std::endl;
  std::cout << "    ++ " << plaintext.auth_data() << std::endl;
  std::cout << "    -> " << _interim_transcript_hash << std::endl;
}

bytes
State::update_leaf(LeafIndex index,
                   const DirectPath& path,
                   const std::optional<bytes>& leaf_secret)
{
  bytes update_secret;
  if (leaf_secret.has_value()) {
    update_secret = _tree.set_path(index, *leaf_secret);
  } else {
    auto merge_path = _tree.decrypt(index, path);
    update_secret = merge_path.root_path_secret;
    _tree.merge_path(index, merge_path);
  }

  return update_secret;
}

void
State::update_epoch_secrets(const bytes& update_secret)
{
  std::cout << "upd_epch " << _index.val << std::endl;
  std::cout << "    init " << _init_secret << std::endl;
  std::cout << "     upd " << update_secret << std::endl;
  std::cout << "     gid " << _group_id << std::endl;
  std::cout << "    epch " << _epoch << std::endl;
  std::cout << "      th " << _tree.root_hash() << std::endl;
  std::cout << "      tx " << _confirmed_transcript_hash << std::endl;
  std::cout << "    tree " << _tree << std::endl << std::endl;

  auto group_context_str = GroupContext{
    _group_id,
    _epoch,
    _tree.root_hash(),
    _confirmed_transcript_hash,
  };
  _group_context = tls::marshal(group_context_str);

  auto secrets =
    derive_epoch_secrets(_suite, _init_secret, update_secret, _group_context);
  _epoch_secret = secrets.epoch_secret;
  _application_secret = secrets.application_secret;
  _handshake_secret = secrets.handshake_secret;
  _sender_data_secret = secrets.sender_data_secret;
  _confirmation_key = secrets.confirmation_key;
  _init_secret = secrets.init_secret;

  auto key_size = AESGCM::key_size(_suite);
  _sender_data_key =
    hkdf_expand_label(_suite, _sender_data_secret, "sd key", {}, key_size);
  _handshake_key_used.clear();

  _application_keys.start(_index, _application_secret);
}

///
/// Message encryption and decryption
///

// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     ContentType content_type;
//     opaque sender_data_nonce<0..255>;
//     opaque encrypted_sender_data<0..255>;
// } MLSCiphertextContentAAD;
static bytes
content_aad(const tls::opaque<1>& group_id,
            uint32_t epoch,
            ContentType content_type,
            const tls::opaque<1>& sender_data_nonce,
            const tls::opaque<1>& encrypted_sender_data)
{
  tls::ostream w;
  w << group_id << epoch << content_type << sender_data_nonce
    << encrypted_sender_data;
  return w.bytes();
}

// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     ContentType content_type;
//     opaque sender_data_nonce<0..255>;
// } MLSCiphertextSenderDataAAD;
static bytes
sender_data_aad(const tls::opaque<1>& group_id,
                uint32_t epoch,
                ContentType content_type,
                const tls::opaque<1>& sender_data_nonce)
{
  tls::ostream w;
  w << group_id << epoch << content_type << sender_data_nonce;
  return w.bytes();
}

std::tuple<MLSPlaintext, State>
State::sign(const GroupOperation& operation) const
{
  auto handshake = MLSPlaintext{ _group_id, _epoch, _index, operation };

  // Apply the operation
  auto next = apply(handshake);

  // Compute the confirmation MAC and signature
  handshake.confirmation =
    hmac(_suite, next._confirmation_key, next._confirmed_transcript_hash);
  handshake.sign(_identity_priv);

  // Reset the state's transcript hash to use the signed message
  next._interim_transcript_hash = _interim_transcript_hash;
  next.update_transcript_hash(handshake);

  return std::make_tuple(handshake, next);
}

bool
State::verify(const MLSPlaintext& pt) const
{
  auto pub = _tree.get_credential(pt.sender).public_key();
  return pt.verify(pub);
}

bool
State::verify_confirmation(const bytes& confirmation) const
{
  auto confirm = hmac(_suite, _confirmation_key, _confirmed_transcript_hash);

  std::cout << "conf_ver " << _index.val << std::endl;
  std::cout << "         " << _confirmation_key << std::endl;
  std::cout << "       + " << _confirmed_transcript_hash << std::endl;
  std::cout << "       = " << confirm << std::endl;
  std::cout << "       ? " << confirmation << std::endl;

  return constant_time_eq(confirm, confirmation);
}

KeyChain::Generation
State::generate_handshake_keys(const LeafIndex& sender, bool encrypt)
{
  auto context = tls::marshal(sender);
  auto key_size = AESGCM::key_size(_suite);
  auto nonce_size = AESGCM::nonce_size;

  if (encrypt && _handshake_key_used.count(sender) > 0) {
    throw ProtocolError("Attempt to encrypt two handshake messages");
  }

  if (encrypt) {
    _handshake_key_used.insert(sender);
  }

  return KeyChain::Generation{
    0,
    _handshake_secret,
    hkdf_expand_label(_suite, _handshake_secret, "hs key", context, key_size),
    hkdf_expand_label(
      _suite, _handshake_secret, "hs nonce", context, nonce_size),
  };
}

MLSCiphertext
State::encrypt(const MLSPlaintext& pt)
{
  // Pull from the key schedule
  KeyChain::Generation keys;
  switch (pt.content_type) {
    case ContentType::handshake:
      keys = generate_handshake_keys(_index, true);
      break;

    case ContentType::application:
      keys = _application_keys.next();
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  // Encrypt the sender data
  tls::ostream sender_data;
  sender_data << _index << keys.generation;

  auto sender_data_nonce = random_bytes(AESGCM::nonce_size);
  auto sender_data_aad_val =
    sender_data_aad(_group_id, _epoch, pt.content_type, sender_data_nonce);

  auto sender_data_gcm = AESGCM(_sender_data_key, sender_data_nonce);
  sender_data_gcm.set_aad(sender_data_aad_val);
  auto encrypted_sender_data = sender_data_gcm.encrypt(sender_data.bytes());

  // Compute the plaintext input and AAD
  // XXX(rlb@ipv.sx): Apply padding?
  auto content = pt.marshal_content(0);
  auto aad = content_aad(_group_id,
                         _epoch,
                         pt.content_type,
                         sender_data_nonce,
                         encrypted_sender_data);

  // Encrypt the plaintext
  auto gcm = AESGCM(keys.key, keys.nonce);
  gcm.set_aad(aad);
  auto ciphertext = gcm.encrypt(content);

  // Assemble the MLSCiphertext
  MLSCiphertext ct;
  ct.group_id = _group_id;
  ct.epoch = _epoch;
  ct.content_type = pt.content_type;
  ct.sender_data_nonce = sender_data_nonce;
  ct.encrypted_sender_data = encrypted_sender_data;
  ct.ciphertext = ciphertext;
  return ct;
}

MLSPlaintext
State::decrypt(const MLSCiphertext& ct)
{
  // Verify the epoch
  if (ct.group_id != _group_id) {
    throw InvalidParameterError("Ciphertext not from this group");
  }

  if (ct.epoch != _epoch) {
    throw InvalidParameterError("Ciphertext not from this epoch");
  }

  // Decrypt and parse the sender data
  auto sender_data_aad_val = sender_data_aad(
    ct.group_id, ct.epoch, ct.content_type, ct.sender_data_nonce);

  auto sender_data_gcm = AESGCM(_sender_data_key, ct.sender_data_nonce);
  sender_data_gcm.set_aad(sender_data_aad_val);
  auto sender_data = sender_data_gcm.decrypt(ct.encrypted_sender_data);

  tls::istream r(sender_data);
  LeafIndex sender;
  uint32_t generation;
  r >> sender >> generation;

  if (!_tree.occupied(sender)) {
    throw ProtocolError("Encryption from unoccupied leaf");
  }

  // Pull from the key schedule
  KeyChain::Generation keys;
  switch (ct.content_type) {
    case ContentType::handshake:
      keys = generate_handshake_keys(_index, false);
      break;

    case ContentType::application:
      keys = _application_keys.get(sender, generation);
      break;

    default:
      throw InvalidParameterError("Unknown content type");
  }

  // Compute the plaintext AAD and decrypt
  auto aad = content_aad(ct.group_id,
                         ct.epoch,
                         ct.content_type,
                         ct.sender_data_nonce,
                         ct.encrypted_sender_data);
  auto gcm = AESGCM(keys.key, keys.nonce);
  gcm.set_aad(aad);
  auto content = gcm.decrypt(ct.ciphertext);

  // Set up a template plaintext and parse into it
  auto pt = MLSPlaintext{ _suite };
  pt.group_id = _group_id;
  pt.epoch = _epoch;
  pt.sender = sender;
  pt.content_type = ct.content_type;
  pt.unmarshal_content(_suite, content);
  return pt;
}

} // namespace mls
