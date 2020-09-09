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

bytes
derive_secret(CipherSuite suite,
              const bytes& secret,
              const std::string& label,
              const bytes& context)
{
  auto context_hash = suite.get().digest.hash(context);
  auto size = suite.get().digest.hash_size();
  return suite.expand_with_label(secret, label, context_hash, size);
}

struct ApplicationContext
{
  NodeIndex node;
  uint32_t generation;

  ApplicationContext(NodeIndex node_in, uint32_t generation_in)
    : node(node_in)
    , generation(generation_in)
  {}

  TLS_SERIALIZABLE(node, generation)
};

bytes
derive_app_secret(CipherSuite suite,
                  const bytes& secret,
                  const std::string& label,
                  NodeIndex node,
                  uint32_t generation,
                  size_t length)
{
  auto ctx = tls::marshal(ApplicationContext{ node, generation });
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
  , key_size(suite.get().hpke.aead.key_size())
  , nonce_size(suite.get().hpke.aead.key_size())
  , secret_size(suite.get().hpke.kdf.hash_size())
{}

std::tuple<uint32_t, KeyAndNonce>
HashRatchet::next()
{
  auto key = derive_app_secret(
    suite, next_secret, "app-key", node, next_generation, key_size);
  auto nonce = derive_app_secret(
    suite, next_secret, "app-nonce", node, next_generation, nonce_size);
  auto secret = derive_app_secret(
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
/// Base Key Sources
///

BaseKeySource::BaseKeySource(CipherSuite suite_in)
  : suite(suite_in)
  , secret_size(suite_in.get().hpke.kdf.hash_size())
{}

struct NoFSBaseKeySource : public BaseKeySource
{
  bytes root_secret;

  NoFSBaseKeySource(CipherSuite suite_in, bytes root_secret_in)
    : BaseKeySource(suite_in)
    , root_secret(std::move(root_secret_in))
  {}

  BaseKeySource* dup() const override { return new NoFSBaseKeySource(*this); }

  bytes get(LeafIndex sender) override
  {
    return derive_app_secret(
      suite, root_secret, "hs-secret", NodeIndex{ sender }, 0, secret_size);
  }
};

struct TreeBaseKeySource : public BaseKeySource
{
  NodeIndex root;
  NodeCount width;
  std::vector<bytes> secrets;
  size_t secret_size;

  TreeBaseKeySource(CipherSuite suite_in,
                    LeafCount group_size,
                    bytes application_secret_in)
    : BaseKeySource(suite_in)
    , root(tree_math::root(NodeCount{ group_size }))
    , width(NodeCount{ group_size })
    , secrets(NodeCount{ group_size }.val)
    , secret_size(suite_in.get().hpke.kdf.hash_size())
  {
    secrets[root.val] = std::move(application_secret_in);
  }

  BaseKeySource* dup() const override { return new TreeBaseKeySource(*this); }

  bytes get(LeafIndex sender) override
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
        derive_app_secret(suite, secret, "tree", left, 0, secret_size);
      secrets[right.val] =
        derive_app_secret(suite, secret, "tree", right, 0, secret_size);
    }

    // Copy the leaf
    auto out = secrets[NodeIndex{ sender }.val];

    // Zeroize along the direct path
    for (auto i : dirpath) {
      zeroize(secrets[i.val]);
    }

    return out;
  };
};

///
/// GroupKeySource
///

GroupKeySource::GroupKeySource()
  : suite{ CipherSuite::ID::unknown }
  , base_source(nullptr)
{}

GroupKeySource::GroupKeySource(const GroupKeySource& other)
  : suite(other.suite)
  , base_source(nullptr)
  , chains(other.chains)
{
  if (other.base_source != nullptr) {
    base_source.reset(other.base_source->dup());
  }
}

GroupKeySource&
GroupKeySource::operator=(const GroupKeySource& other)
{
  if (&other == this) {
    return *this;
  }

  suite = other.suite;
  if (other.base_source != nullptr) {
    base_source.reset(other.base_source->dup());
  } else {
    base_source.reset(nullptr);
  }
  chains = other.chains;
  return *this;
}

GroupKeySource::GroupKeySource(BaseKeySource* base_source_in)
  : suite(base_source_in->suite)
  , base_source(base_source_in)
{}

HashRatchet&
GroupKeySource::chain(LeafIndex sender)
{
  if (chains.count(sender) > 0) {
    return chains[sender];
  }

  auto base_secret = base_source->get(sender);
  chains.emplace(sender,
                 HashRatchet{ suite, NodeIndex{ sender }, base_secret });
  return chains[sender];
}

std::tuple<uint32_t, KeyAndNonce>
GroupKeySource::next(LeafIndex sender)
{
  return chain(sender).next();
}

KeyAndNonce
GroupKeySource::get(LeafIndex sender, uint32_t generation)
{
  return chain(sender).get(generation);
}

void
GroupKeySource::erase(LeafIndex sender, uint32_t generation)
{
  return chain(sender).erase(generation);
}

///
/// KeyScheduleEpoch
///

KeyScheduleEpoch
KeyScheduleEpoch::create(CipherSuite suite,
                         LeafCount size,
                         const bytes& epoch_secret,
                         const bytes& context)
{
  auto sender_data_secret =
    derive_secret(suite, epoch_secret, "sender data", context);
  auto handshake_secret =
    derive_secret(suite, epoch_secret, "handshake", context);
  auto application_secret = derive_secret(suite, epoch_secret, "app", context);
  auto confirmation_key =
    derive_secret(suite, epoch_secret, "confirm", context);
  auto init_secret = derive_secret(suite, epoch_secret, "init", context);

  auto key_size = suite.get().hpke.aead.key_size();
  auto sender_data_key =
    suite.expand_with_label(sender_data_secret, "sd key", {}, key_size);

  auto handshake_base =
    std::make_unique<NoFSBaseKeySource>(suite, handshake_secret);
  auto application_base =
    std::make_unique<TreeBaseKeySource>(suite, size, application_secret);

  return KeyScheduleEpoch{ suite,
                           epoch_secret,
                           sender_data_secret,
                           sender_data_key,
                           handshake_secret,
                           GroupKeySource{ handshake_base.release() },
                           application_secret,
                           GroupKeySource{ application_base.release() },
                           confirmation_key,
                           init_secret };
}

KeyScheduleEpoch
KeyScheduleEpoch::next(LeafCount size,
                       const bytes& update_secret,
                       const bytes& context) const
{
  auto new_epoch_secret =
    suite.get().hpke.kdf.extract(init_secret, update_secret);
  return KeyScheduleEpoch::create(suite, size, new_epoch_secret, context);
}

bool
operator==(const KeyScheduleEpoch& lhs, const KeyScheduleEpoch& rhs)
{
  // NB: Does not compare the GroupKeySource fields, since these are dynamically
  // generated as needed.  Rather, we check the roots from which they started.
  auto suite = (lhs.suite == rhs.suite);
  auto epoch_secret = (lhs.epoch_secret == rhs.epoch_secret);
  auto sender_data_secret = (lhs.sender_data_secret == rhs.sender_data_secret);
  auto sender_data_key = (lhs.sender_data_key == rhs.sender_data_key);
  auto handshake_secret = (lhs.handshake_secret == rhs.handshake_secret);
  auto application_secret = (lhs.application_secret == rhs.application_secret);
  auto confirmation_key = (lhs.confirmation_key == rhs.confirmation_key);
  auto init_secret = (lhs.init_secret == rhs.init_secret);

  return suite && epoch_secret && sender_data_secret && sender_data_key &&
         handshake_secret && application_secret && confirmation_key &&
         init_secret;
}

} // namespace mls
