#include <mls/key_schedule.h>
#include <mls/log.h>

using mls::log::Log;
static const auto log_mod = "key_schedule"s;

namespace mls {

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
{
}

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
    secrets[i.val] = {};
  }

  return out;
}

///
/// ReuseGuard
///

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

///
/// GroupKeySource
///

GroupKeySource::GroupKeySource(CipherSuite suite_in,
                               LeafCount group_size,
                               bytes encryption_secret)
  : suite(suite_in)
  , secret_tree(suite, group_size, std::move(encryption_secret))
{
}

HashRatchet&
GroupKeySource::chain(ContentType type, LeafIndex sender)
{
  switch (type) {
    case ContentType::proposal:
    case ContentType::commit:
      return chain(RatchetType::handshake, sender);

    case ContentType::application:
      return chain(RatchetType::application, sender);

    default:
      throw InvalidParameterError("Invalid content type");
  }
}

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

std::tuple<uint32_t, ReuseGuard, KeyAndNonce>
GroupKeySource::next(ContentType type, LeafIndex sender)
{
  auto [generation, keys] = chain(type, sender).next();

  auto reuse_guard = new_reuse_guard();
  apply_reuse_guard(reuse_guard, keys.nonce);

  return { generation, reuse_guard, keys };
}

KeyAndNonce
GroupKeySource::get(ContentType type,
                    LeafIndex sender,
                    uint32_t generation,
                    ReuseGuard reuse_guard)
{
  auto keys = chain(type, sender).get(generation);
  apply_reuse_guard(reuse_guard, keys.nonce);
  return keys;
}

void
GroupKeySource::erase(ContentType type, LeafIndex sender, uint32_t generation)
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
};

///
/// KeyScheduleEpoch
///

struct PSKLabel
{
  const PreSharedKeyID& id;
  uint16_t index;
  uint16_t count;

  TLS_SERIALIZABLE(id, index, count);
};

static bytes
make_psk_secret(CipherSuite suite, const std::vector<PSKWithSecret>& psks)
{
  auto psk_secret = suite.zero();
  auto count = uint16_t(psks.size());
  auto index = uint16_t(0);
  for (const auto& psk : psks) {
    auto psk_extracted = suite.hpke().kdf.extract(suite.zero(), psk.secret);
    auto psk_label = tls::marshal(PSKLabel{ psk.id, index, count });
    auto psk_input = suite.expand_with_label(
      psk_extracted, "derived psk", psk_label, suite.secret_size());
    psk_secret = suite.hpke().kdf.extract(psk_input, psk_secret);
    index += 1;
  }
  return psk_secret;
}

static bytes
make_joiner_secret(CipherSuite suite,
                   const bytes& context,
                   const bytes& init_secret,
                   const bytes& commit_secret)
{
  auto pre_joiner_secret = suite.hpke().kdf.extract(init_secret, commit_secret);
  return suite.expand_with_label(
    pre_joiner_secret, "joiner", context, suite.secret_size());
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
                                   const std::vector<PSKWithSecret>& psks,
                                   const bytes& context)
  : suite(suite_in)
  , joiner_secret(joiner_secret)
  , psk_secret(make_psk_secret(suite_in, psks))
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
{
}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in)
  : suite(suite_in)
{
}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in,
                                   const bytes& init_secret,
                                   const bytes& context)
  : KeyScheduleEpoch(
      suite_in,
      make_joiner_secret(suite_in, context, init_secret, suite_in.zero()),
      { /* no PSKs */ },
      context)
{
}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in,
                                   const bytes& init_secret,
                                   const bytes& commit_secret,
                                   const std::vector<PSKWithSecret>& psks,
                                   const bytes& context)
  : KeyScheduleEpoch(
      suite_in,
      make_joiner_secret(suite_in, context, init_secret, commit_secret),
      psks,
      context)
{
}

std::tuple<bytes, bytes>
KeyScheduleEpoch::external_init(CipherSuite suite,
                                const HPKEPublicKey& external_pub)
{
  auto size = suite.secret_size();
  return external_pub.do_export(
    suite, {}, "MLS 1.0 external init secret", size);
}

bytes
KeyScheduleEpoch::receive_external_init(const bytes& kem_output) const
{
  auto size = suite.secret_size();
  return external_priv.do_export(
    suite, {}, kem_output, "MLS 1.0 external init secret", size);
}

KeyScheduleEpoch
KeyScheduleEpoch::next(const bytes& commit_secret,
                       const std::vector<PSKWithSecret>& psks,
                       const std::optional<bytes>& force_init_secret,
                       const bytes& context) const
{
  auto actual_init_secret = init_secret;
  if (force_init_secret) {
    actual_init_secret = opt::get(force_init_secret);
  }

  return { suite, actual_init_secret, commit_secret, psks, context };
}

GroupKeySource
KeyScheduleEpoch::encryption_keys(LeafCount size) const
{
  return { suite, size, encryption_secret };
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

PSKWithSecret
KeyScheduleEpoch::branch_psk(const bytes& group_id, epoch_t epoch)
{
  auto nonce = random_bytes(suite.secret_size());
  return { { BranchPSK{ group_id, epoch }, nonce }, resumption_secret };
}

PSKWithSecret
KeyScheduleEpoch::reinit_psk(const bytes& group_id, epoch_t epoch)
{
  auto nonce = random_bytes(suite.secret_size());
  return { { ReInitPSK{ group_id, epoch }, nonce }, resumption_secret };
}

bytes
KeyScheduleEpoch::welcome_secret(CipherSuite suite,
                                 const bytes& joiner_secret,
                                 const std::vector<PSKWithSecret>& psks)
{
  auto psk_secret = make_psk_secret(suite, psks);
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
  if (ciphertext.size() <= sample_size) {
    sample = ciphertext;
  } else {
    sample = ciphertext.slice(0, sample_size);
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
{
}

TranscriptHash::TranscriptHash(CipherSuite suite_in,
                               bytes confirmed_in,
                               const bytes& confirmation_tag)
  : suite(suite_in)
  , confirmed(std::move(confirmed_in))
{
  update_interim(confirmation_tag);
}

void
TranscriptHash::update(const MLSMessageContentAuth& content_auth)
{
  update_confirmed(content_auth);
  update_interim(content_auth);
}

void
TranscriptHash::update_confirmed(const MLSMessageContentAuth& content_auth)
{
  const auto transcript = interim + content_auth.commit_content();
  confirmed = suite.digest().hash(transcript);
}

void
TranscriptHash::update_interim(const bytes& confirmation_tag)
{
  const auto transcript = confirmed + tls::marshal(confirmation_tag);
  interim = suite.digest().hash(transcript);
}

void
TranscriptHash::update_interim(const MLSMessageContentAuth& content_auth)
{
  const auto transcript = confirmed + content_auth.commit_auth_data();
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
