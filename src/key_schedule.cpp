#include "mls/key_schedule.h"

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
  return suite.expand_with_label(secret, label, ctx, length);
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
  , key_size(suite.get().hpke.aead.key_size)
  , nonce_size(suite.get().hpke.aead.key_size)
  , secret_size(suite.secret_size())
{}

std::tuple<uint32_t, KeyAndNonce>
HashRatchet::next()
{
  auto key = derive_tree_secret(
    suite, next_secret, "app-key", node, next_generation, key_size);
  auto nonce = derive_tree_secret(
    suite, next_secret, "app-nonce", node, next_generation, nonce_size);
  auto secret = derive_tree_secret(
    suite, next_secret, "app-secret", node, next_generation, secret_size);

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
                       LeafCount group_size,
                       bytes encryption_secret_in)
  : suite(suite_in)
  , root(tree_math::root(NodeCount{ group_size }))
  , width(NodeCount{ group_size })
  , secrets(NodeCount{ group_size }.val)
  , secret_size(suite_in.secret_size())
{
  secrets[root.val] = std::move(encryption_secret_in);
}

bytes
SecretTree::get(LeafIndex sender)
{
  // Find an ancestor that is populated
  auto dirpath = tree_math::dirpath(NodeIndex{ sender }, width);
  dirpath.insert(dirpath.begin(), NodeIndex{ sender });
  dirpath.push_back(tree_math::root(width));
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
    auto node = dirpath[curr];
    auto left = tree_math::left(node);
    auto right = tree_math::right(node, width);

    auto& secret = secrets[node.val];
    secrets[left.val] =
      derive_tree_secret(suite, secret, "tree", left, 0, secret_size);
    secrets[right.val] =
      derive_tree_secret(suite, secret, "tree", right, 0, secret_size);
  }

  // Copy the leaf
  auto out = secrets[NodeIndex{ sender }.val];

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

///
/// KeyScheduleEpoch
///

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in)
  : suite(suite_in)
{
  epoch_secret = random_bytes(suite.secret_size());
  init_secrets(LeafCount{ 1 });
}

KeyScheduleEpoch::KeyScheduleEpoch(CipherSuite suite_in,
                                   bytes joiner_secret_in,
                                   const bytes& psk_secret,
                                   const bytes& context,
                                   LeafCount size)
  : suite(suite_in)
  , joiner_secret(std::move(joiner_secret_in))
{
  auto joiner_expand = suite.derive_secret(joiner_secret, "member");

  member_secret = suite.get().hpke.kdf.extract(joiner_expand, psk_secret);

  epoch_secret =
    suite.expand_with_label(member_secret, "epoch", context, suite.secret_size());
  init_secrets(size);
}

void
KeyScheduleEpoch::init_secrets(LeafCount size)
{
  sender_data_secret = suite.derive_secret(epoch_secret, "sender data");
  encryption_secret = suite.derive_secret(epoch_secret, "encryption");
  exporter_secret = suite.derive_secret(epoch_secret, "exporter");
  authentication_secret = suite.derive_secret(epoch_secret, "authentication");
  external_secret = suite.derive_secret(epoch_secret, "external");
  confirmation_key = suite.derive_secret(epoch_secret, "confirm");
  membership_key = suite.derive_secret(epoch_secret, "membership");
  resumption_secret = suite.derive_secret(epoch_secret, "resumption");
  init_secret = suite.derive_secret(epoch_secret, "init");

  external_priv = HPKEPrivateKey::derive(suite, external_secret);
  keys = GroupKeySource(suite, size, encryption_secret);
}

KeyScheduleEpoch
KeyScheduleEpoch::next(const bytes& commit_secret,
                       const bytes& psk_secret,
                       const bytes& context,
                       LeafCount size) const
{
  auto joiner_secret = suite.get().hpke.kdf.extract(init_secret, commit_secret);
  return KeyScheduleEpoch(suite, joiner_secret, psk_secret, context, size);
}

KeyAndNonce
KeyScheduleEpoch::sender_data(const bytes& ciphertext) const
{
  auto sample_size = suite.secret_size();
  auto sample = bytes(sample_size);
  if (ciphertext.size() < sample_size) {
    sample = ciphertext;
  } else {
    sample = bytes(ciphertext.begin(), ciphertext.begin() + sample_size);
  }

  auto key_size = suite.get().hpke.aead.key_size;
  auto nonce_size = suite.get().hpke.aead.nonce_size;
  return {
    suite.expand_with_label(sender_data_secret, "key", sample, key_size),
    suite.expand_with_label(sender_data_secret, "nonce", sample, nonce_size),
  };
}

bool
operator==(const KeyScheduleEpoch& lhs, const KeyScheduleEpoch& rhs)
{
  // NB: Does not compare the GroupKeySource field, since these are dynamically
  // generated as needed.  Rather, we check the roots from which they started.
  auto suite = (lhs.suite == rhs.suite);
  auto epoch_secret = (lhs.epoch_secret == rhs.epoch_secret);
  auto sender_data_secret = (lhs.sender_data_secret == rhs.sender_data_secret);
  auto encryption_secret = (lhs.encryption_secret == rhs.encryption_secret);
  auto exporter_secret = (lhs.exporter_secret == rhs.exporter_secret);
  auto confirmation_key = (lhs.confirmation_key == rhs.confirmation_key);
  auto init_secret = (lhs.init_secret == rhs.init_secret);

  return suite && epoch_secret && sender_data_secret && encryption_secret &&
         exporter_secret && confirmation_key && init_secret;
}

} // namespace mls
