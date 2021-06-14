#include <mls/key_schedule.h>
#include <mls/log.h>

using mls::log::Log;
static const auto log_mod = "key_schedule"s;

namespace mls {

static void
zeroize(bytes& data) // NOLINT(google-runtime-references)
{
  for (auto& val : data) {
    val = 0;
  }
  data.resize(0);
}

///
/// Key Derivation Functions
///

struct TreeContext
{
  NodeIndex node;
  uint32_t generation = 0;

  TLS_SERIALIZABLE(node, generation)
};

static bytes
derive_tree_secret(CipherSuite suite,
                   const bytes& secret,
                   const std::string& label,
                   NodeIndex node,
                   uint32_t generation,
                   size_t length)
{
  auto ctx = tls::marshal(TreeContext{ node, generation });
  auto derived = suite.expand_with_label(secret, label, ctx, length);

  Log::crypto(log_mod, "=== DeriveTreeSecret ===");
  Log::crypto(log_mod, "  secret       ", to_hex(secret));
  Log::crypto(log_mod, "  label        ", label);
  Log::crypto(log_mod, "  node         ", node.val);
  Log::crypto(log_mod, "  generation   ", generation);
  Log::crypto(log_mod, "  tree_context ", to_hex(ctx));

  return derived;
}

///
/// HashRatchet
///

HashRatchet::HashRatchet(CipherSuite suite_in,
                         NodeIndex node_in,
                         bytes base_secret_in)
  : suite(suite_in)
  , node(node_in)
  , next_secret(std::move(base_secret_in))
  , next_generation(0)
  , key_size(suite.hpke().aead.key_size)
  , nonce_size(suite.hpke().aead.nonce_size)
  , secret_size(suite.secret_size())
{}

std::tuple<uint32_t, KeyAndNonce>
HashRatchet::next()
{
  auto key = derive_tree_secret(
    suite, next_secret, "key", node, next_generation, key_size);
  auto nonce = derive_tree_secret(
    suite, next_secret, "nonce", node, next_generation, nonce_size);
  auto secret = derive_tree_secret(
    suite, next_secret, "secret", node, next_generation, secret_size);

  auto generation = next_generation;

  next_generation += 1;
  zeroize(next_secret);
  next_secret = secret;

  cache[generation] = { key, nonce };
  return { generation, cache[generation] };
}

// Note: This construction deliberately does not preserve the forward-secrecy
// invariant, in that keys/nonces are not deleted after they are used.
// Otherwise, it would not be possible for a node to send to itself.  Keys can
// be deleted once they are not needed by calling HashRatchet::erase().
KeyAndNonce
HashRatchet::get(uint32_t generation)
{
  if (cache.count(generation) > 0) {
    auto out = cache[generation];
    return out;
  }

  if (next_generation > generation) {
    throw ProtocolError("Request for expired key");
  }

  while (next_generation < generation) {
    next();
  }

  auto [gen, key_nonce] = next();
  silence_unused(gen);
  return key_nonce;
}

void
HashRatchet::erase(uint32_t generation)
{
  if (cache.count(generation) == 0) {
    return;
  }

  zeroize(cache[generation].key);
  zeroize(cache[generation].nonce);
  cache.erase(generation);
}

///
/// SecretTree
///

SecretTree::SecretTree(CipherSuite suite_in,
                       LeafCount group_size_in,
                       bytes encryption_secret_in)
  : suite(suite_in)
  , root(tree_math::root(group_size_in))
  , group_size(group_size_in)
  , secrets(NodeCount{ group_size }.val)
  , secret_size(suite_in.secret_size())
{
  secrets[root.val] = std::move(encryption_secret_in);
}

bytes
SecretTree::get(LeafIndex sender)
{
  auto node = NodeIndex(sender);

  // Find an ancestor that is populated
  auto dirpath = tree_math::dirpath(node, group_size);
  dirpath.insert(dirpath.begin(), node);
  dirpath.push_back(root);
  uint32_t curr = 0;
  for (; curr < dirpath.size(); ++curr) {
    if (!secrets[dirpath[curr].val].empty()) {
      break;
    }
  }

  if (curr > dirpath.size()) {
    throw InvalidParameterError("No secret found to derive base key");
  }

  // Derive down
  for (; curr > 0; --curr) {
    auto curr_node = dirpath[curr];
    auto left = tree_math::left(curr_node);
    auto right = tree_math::right(curr_node, group_size);

    auto& secret = secrets[curr_node.val];
    secrets[left.val] =
      derive_tree_secret(suite, secret, "tree", left, 0, secret_size);
    secrets[right.val] =
      derive_tree_secret(suite, secret, "tree", right, 0, secret_size);
  }

  // Copy the leaf
  auto out = secrets[node.val];

  // Zeroize along the direct path
  for (auto i : dirpath) {
    zeroize(secrets[i.val]);
  }

  return out;
}

///
/// GroupKeySource
///

GroupKeySource::GroupKeySource(CipherSuite suite_in,
                               LeafCount group_size,
                               bytes encryption_secret)
  : suite(suite_in)
  , secret_tree(suite, group_size, std::move(encryption_secret))
{}

HashRatchet&
GroupKeySource::chain(RatchetType type, LeafIndex sender)
{
  auto key = Key{ type, sender };
  if (chains.count(key) > 0) {
    return chains[key];
  }

  auto sender_node = NodeIndex{ sender };
  auto secret_size = suite.secret_size();
  auto leaf_secret = secret_tree.get(sender);

  auto handshake_secret = derive_tree_secret(
    suite, leaf_secret, "handshake", sender_node, 0, secret_size);
  chains.emplace(
    std::make_pair(Key{ RatchetType::handshake, sender },
                   HashRatchet{ suite, sender_node, handshake_secret }));

  auto application_secret = derive_tree_secret(
    suite, leaf_secret, "application", sender_node, 0, secret_size);
  chains.emplace(
    std::make_pair(Key{ RatchetType::application, sender },
                   HashRatchet{ suite, sender_node, application_secret }));

  return chains[key];
}

std::tuple<uint32_t, KeyAndNonce>
GroupKeySource::next(RatchetType type, LeafIndex sender)
{
  return chain(type, sender).next();
}

KeyAndNonce
GroupKeySource::get(RatchetType type, LeafIndex sender, uint32_t generation)
{
  return chain(type, sender).get(generation);
}

void
GroupKeySource::erase(RatchetType type, LeafIndex sender, uint32_t generation)
{
  return chain(type, sender).erase(generation);
}

// struct {
//     opaque group_id<0..255>;
//     uint64 epoch;
//     ContentType content_type;
//     opaque authenticated_data<0..2^32-1>;
// } MLSCiphertextContentAAD;
struct MLSCiphertextContentAAD
{
  const bytes& group_id;
  const epoch_t epoch;
  const ContentType content_type;
  const bytes& authenticated_data;

  TLS_SERIALIZABLE(group_id, epoch, content_type, authenticated_data)
  TLS_TRAITS(tls::vector<1>, tls::pass, tls::pass, tls::vector<4>)
};

using ReuseGuard = std::array<uint8_t, 4>;

static ReuseGuard
new_reuse_guard()
{
  auto random = random_bytes(4);
  auto guard = ReuseGuard();
  std::copy(random.begin(), random.end(), guard.begin());
  return guard;
}

static void
apply_reuse_guard(const ReuseGuard& guard, bytes& nonce)
{
  for (size_t i = 0; i < guard.size(); i++) {
    nonce.at(i) ^= guard.at(i);
  }
}

// struct {
//     uint32 sender;
//     uint32 generation;
//     opaque reuse_guard[4];
// } MLSSenderData;
struct MLSSenderData
{
  uint32_t sender;
  uint32_t generation;
  ReuseGuard reuse_guard;

  TLS_SERIALIZABLE(sender, generation, reuse_guard)
};

// struct {
//     opaque group_id<0..255>;
//     uint64 epoch;
//     ContentType content_type;
// } MLSSenderDataAAD;
struct MLSSenderDataAAD
{
  const bytes& group_id;
  const epoch_t epoch;
  const ContentType content_type;

  TLS_SERIALIZABLE(group_id, epoch, content_type)
  TLS_TRAITS(tls::vector<1>, tls::pass, tls::pass)
};

MLSCiphertext
GroupKeySource::encrypt(LeafIndex index,
                        const bytes& sender_data_secret,
                        const MLSPlaintext& pt)
{
  // Pull from the key schedule
  static const auto get_key_type = overloaded{
    [](const ApplicationData& /*unused*/) {
      return GroupKeySource::RatchetType::application;
    },
    [](const Proposal& /*unused*/) {
      return GroupKeySource::RatchetType::handshake;
    },
    [](const Commit& /*unused*/) {
      return GroupKeySource::RatchetType::handshake;
    },
  };

  auto key_type = var::visit(get_key_type, pt.content);
  auto [generation, content_keys] = next(key_type, index);

  // Encrypt the content
  // XXX(rlb@ipv.sx): Apply padding?
  auto content = pt.marshal_content(0);
  auto content_type_val = pt.content_type();
  auto content_aad = tls::marshal(MLSCiphertextContentAAD{
    pt.group_id, pt.epoch, content_type_val, pt.authenticated_data });

  auto reuse_guard = new_reuse_guard();
  apply_reuse_guard(reuse_guard, content_keys.nonce);

  auto content_ct = suite.hpke().aead.seal(
    content_keys.key, content_keys.nonce, content_aad, content);

  // Encrypt the sender data
  auto sender_data_obj = MLSSenderData{ index.val, generation, reuse_guard };
  auto sender_data = tls::marshal(sender_data_obj);

  auto sender_data_keys =
    KeyScheduleEpoch::sender_data_keys(suite, sender_data_secret, content_ct);
  auto sender_data_aad =
    tls::marshal(MLSSenderDataAAD{ pt.group_id, pt.epoch, content_type_val });

  auto encrypted_sender_data = suite.hpke().aead.seal(
    sender_data_keys.key, sender_data_keys.nonce, sender_data_aad, sender_data);

  // Assemble the MLSCiphertext
  MLSCiphertext ct;
  ct.group_id = pt.group_id;
  ct.epoch = pt.epoch;
  ct.content_type = content_type_val;
  ct.encrypted_sender_data = encrypted_sender_data;
  ct.authenticated_data = pt.authenticated_data;
  ct.ciphertext = content_ct;
  return ct;
}

MLSPlaintext
GroupKeySource::decrypt(const bytes& sender_data_secret,
                        const MLSCiphertext& ct)
{
  // Decrypt and parse the sender data
  auto sender_data_keys = KeyScheduleEpoch::sender_data_keys(
    suite, sender_data_secret, ct.ciphertext);
  auto sender_data_aad =
    tls::marshal(MLSSenderDataAAD{ ct.group_id, ct.epoch, ct.content_type });
  auto sender_data_pt = suite.hpke().aead.open(sender_data_keys.key,
                                               sender_data_keys.nonce,
                                               sender_data_aad,
                                               ct.encrypted_sender_data);
  if (!sender_data_pt) {
    throw ProtocolError("Sender data decryption failed");
  }

  auto sender_data = tls::get<MLSSenderData>(opt::get(sender_data_pt));
  auto sender = LeafIndex(sender_data.sender);

  // Pull from the key schedule
  auto key_type = GroupKeySource::RatchetType::handshake;
  switch (ct.content_type) {
    case ContentType::proposal:
    case ContentType::commit:
      key_type = GroupKeySource::RatchetType::handshake;
      break;

    case ContentType::application:
      key_type = GroupKeySource::RatchetType::application;
      break;

    default:
      throw ProtocolError("Unsupported content type");
  }

  auto content_keys = get(key_type, sender, sender_data.generation);
  erase(key_type, sender, sender_data.generation);
  apply_reuse_guard(sender_data.reuse_guard, content_keys.nonce);

  // Compute the plaintext AAD and decrypt
  auto content_aad = tls::marshal(MLSCiphertextContentAAD{
    ct.group_id,
    ct.epoch,
    ct.content_type,
    ct.authenticated_data,
  });
  auto content = suite.hpke().aead.open(
    content_keys.key, content_keys.nonce, content_aad, ct.ciphertext);
  if (!content) {
    throw ProtocolError("Content decryption failed");
  }

  // Set up a new plaintext based on the content
  return MLSPlaintext{ ct.group_id,
                       ct.epoch,
                       { SenderType::member, sender_data.sender },
                       ct.content_type,
                       ct.authenticated_data,
                       opt::get(content) };
}

///
/// KeyScheduleEpoch
///

static bytes
make_joiner_secret(CipherSuite suite,
                   const bytes& init_secret,
                   const bytes& commit_secret)
{
  auto pre_joiner_secret = suite.hpke().kdf.extract(init_secret, commit_secret);
  return suite.derive_secret(pre_joiner_secret, "joiner");
}

static bytes
make_epoch_secret(CipherSuite suite,
                  const bytes& joiner_secret,
                  const bytes& psk_secret,
                  const bytes& context)
{
  auto member_secret = suite.hpke().kdf.extract(joiner_secret, psk_secret);
  return suite.expand_with_label(
    member_secret, "epoch", context, suite.secret_size());
}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in,
                                   const bytes& joiner_secret,
                                   const bytes& psk_secret,
                                   const bytes& context)
  : suite(suite_in)
  , joiner_secret(joiner_secret)
  , epoch_secret(
      make_epoch_secret(suite_in, joiner_secret, psk_secret, context))
  , sender_data_secret(suite.derive_secret(epoch_secret, "sender data"))
  , encryption_secret(suite.derive_secret(epoch_secret, "encryption"))
  , exporter_secret(suite.derive_secret(epoch_secret, "exporter"))
  , authentication_secret(suite.derive_secret(epoch_secret, "authentication"))
  , external_secret(suite.derive_secret(epoch_secret, "external"))
  , confirmation_key(suite.derive_secret(epoch_secret, "confirm"))
  , membership_key(suite.derive_secret(epoch_secret, "membership"))
  , resumption_secret(suite.derive_secret(epoch_secret, "resumption"))
  , init_secret(suite.derive_secret(epoch_secret, "init"))
  , external_priv(HPKEPrivateKey::derive(suite, external_secret))
{}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in)
  : suite(suite_in)
{}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in,
                                   const bytes& init_secret,
                                   const bytes& context)
  : KeyScheduleEpoch(suite_in,
                     make_joiner_secret(suite_in, init_secret, suite_in.zero()),
                     suite_in.zero(),
                     context)
{}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in,
                                   const bytes& init_secret,
                                   const bytes& commit_secret,
                                   const bytes& psk_secret,
                                   const bytes& context)
  : KeyScheduleEpoch(suite_in,
                     make_joiner_secret(suite_in, init_secret, commit_secret),
                     psk_secret,
                     context)
{}

std::tuple<bytes, bytes>
KeyScheduleEpoch::external_init(CipherSuite suite,
                                const HPKEPublicKey& external_pub)
{
  auto size = suite.secret_size();
  return external_pub.do_export(suite, "MLS 1.0 external init", size);
}

bytes
KeyScheduleEpoch::receive_external_init(const bytes& kem_output) const
{
  auto size = suite.secret_size();
  return external_priv.do_export(
    suite, kem_output, "MLS 1.0 external init", size);
}

KeyScheduleEpoch
KeyScheduleEpoch::next(const bytes& commit_secret,
                       const bytes& psk_secret,
                       const std::optional<bytes>& force_init_secret,
                       const bytes& context) const
{
  auto actual_init_secret = init_secret;
  if (force_init_secret) {
    actual_init_secret = opt::get(force_init_secret);
  }

  return KeyScheduleEpoch(
    suite, actual_init_secret, commit_secret, psk_secret, context);
}

GroupKeySource
KeyScheduleEpoch::encryption_keys(LeafCount size) const
{
  return GroupKeySource(suite, size, encryption_secret);
}

bytes
KeyScheduleEpoch::membership_tag(const GroupContext& context,
                                 const MLSPlaintext& pt) const
{
  auto tbm = pt.membership_tag_input(context);
  return suite.digest().hmac(membership_key, tbm);
}

bytes
KeyScheduleEpoch::confirmation_tag(const bytes& confirmed_transcript_hash) const
{
  return suite.digest().hmac(confirmation_key, confirmed_transcript_hash);
}

bytes
KeyScheduleEpoch::do_export(const std::string& label,
                            const bytes& context,
                            size_t size) const
{
  auto secret = suite.derive_secret(exporter_secret, label);
  auto context_hash = suite.digest().hash(context);
  return suite.expand_with_label(secret, "exporter", context_hash, size);
}

bytes
KeyScheduleEpoch::welcome_secret(CipherSuite suite,
                                 const bytes& joiner_secret,
                                 const bytes& psk_secret)
{
  auto extract = suite.hpke().kdf.extract(joiner_secret, psk_secret);
  return suite.derive_secret(extract, "welcome");
}

KeyAndNonce
KeyScheduleEpoch::sender_data_keys(CipherSuite suite,
                                   const bytes& sender_data_secret,
                                   const bytes& ciphertext)
{
  auto sample_size = suite.secret_size();
  auto sample = bytes(sample_size);
  if (ciphertext.size() < sample_size) {
    sample = ciphertext;
  } else {
    sample = bytes(
      ciphertext.begin(),
      ciphertext.begin() +
        sample_size); // NOLINT
                      // (bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
  }

  auto key_size = suite.hpke().aead.key_size;
  auto nonce_size = suite.hpke().aead.nonce_size;
  return {
    suite.expand_with_label(sender_data_secret, "key", sample, key_size),
    suite.expand_with_label(sender_data_secret, "nonce", sample, nonce_size),
  };
}

bool
operator==(const KeyScheduleEpoch& lhs, const KeyScheduleEpoch& rhs)
{
  auto epoch_secret = (lhs.epoch_secret == rhs.epoch_secret);
  auto sender_data_secret = (lhs.sender_data_secret == rhs.sender_data_secret);
  auto encryption_secret = (lhs.encryption_secret == rhs.encryption_secret);
  auto exporter_secret = (lhs.exporter_secret == rhs.exporter_secret);
  auto confirmation_key = (lhs.confirmation_key == rhs.confirmation_key);
  auto init_secret = (lhs.init_secret == rhs.init_secret);
  auto external_priv = (lhs.external_priv == rhs.external_priv);

  return epoch_secret && sender_data_secret && encryption_secret &&
         exporter_secret && confirmation_key && init_secret && external_priv;
}

TranscriptHash::TranscriptHash(CipherSuite suite_in)
  : suite(suite_in)
{}

void
TranscriptHash::update(const MLSPlaintext& pt)
{
  update_confirmed(pt);
  update_interim(pt);
}

void
TranscriptHash::update_confirmed(const MLSPlaintext& pt)
{
  const auto transcript = interim + pt.commit_content();
  confirmed = suite.digest().hash(transcript);
}

void
TranscriptHash::update_interim(const MAC& confirmation_tag)
{
  const auto opt_tag = std::optional<MAC>(confirmation_tag);
  const auto transcript = confirmed + tls::marshal(opt_tag);
  interim = suite.digest().hash(transcript);
}

void
TranscriptHash::update_interim(const MLSPlaintext& pt)
{
  const auto transcript = confirmed + pt.commit_auth_data();
  interim = suite.digest().hash(transcript);
}

bool
operator==(const TranscriptHash& lhs, const TranscriptHash& rhs)
{
  auto confirmed = (lhs.confirmed == rhs.confirmed);
  auto interim = (lhs.interim == rhs.interim);
  return confirmed && interim;
}

} // namespace mls
