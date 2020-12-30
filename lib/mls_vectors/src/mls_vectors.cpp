#include <mls/key_schedule.h>
#include <mls/state.h>
#include <mls/tree_math.h>
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

///
/// Assertions for verifying test vectors
///

std::ostream&
operator<<(std::ostream& str, const NodeIndex& obj)
{
  return str << obj.val;
}

std::ostream&
operator<<(std::ostream& str, const bytes& obj)
{
  return str << to_hex(obj);
}

std::ostream&
operator<<(std::ostream& str, const HPKEPublicKey& obj)
{
  return str << to_hex(tls::marshal(obj));
}

template<typename T>
static std::optional<std::string>
verify_equal(std::string label, const T& actual, const T& expected)
{
  if (actual == expected) {
    return std::nullopt;
  }

  auto ss = std::stringstream();
  ss << "Error: " << label << "  " << actual << " != " << expected;
  return ss.str();
}

#define VERIFY_EQUAL(label, actual, expected)                                  \
  if (auto eq = verify_equal(label, actual, expected); !eq) {                  \
    return eq;                                                                 \
  }

///
/// TreeMathTestVector
///
TreeMathTestVector::TreeMathTestVector(uint32_t n_leaves_in)
  : n_leaves(n_leaves_in)
  , root(n_leaves_in - 1)
  , left(NodeCount(n_leaves).val)
  , right(NodeCount(n_leaves).val)
  , parent(NodeCount(n_leaves).val)
  , sibling(NodeCount(n_leaves).val)
{
  // Root is special
  for (LeafCount n{ 1 }; n.val <= n_leaves_in; n.val++) {
    root[n.val - 1] = tree_math::root(n);
  }

  // Left, right, parent, sibling are relative
  auto w = NodeCount(n_leaves);
  for (NodeIndex x{ 0 }; x.val < w.val; x.val++) {
    left[x.val] = tree_math::left(x);
    right[x.val] = tree_math::right(x, n_leaves);
    parent[x.val] = tree_math::parent(x, n_leaves);
    sibling[x.val] = tree_math::sibling(x, n_leaves);
  }
}

std::optional<std::string>
TreeMathTestVector::verify() const
{
  auto ss = std::stringstream();
  for (LeafCount n{ 1 }; n.val <= n_leaves.val; n.val++) {
    VERIFY_EQUAL("root", root[n.val - 1], tree_math::root(n));
  }

  auto w = NodeCount(n_leaves);
  for (NodeIndex x{ 0 }; x.val < w.val; x.val++) {
    VERIFY_EQUAL("left", left[x.val], tree_math::left(x));
    VERIFY_EQUAL("right", right[x.val], tree_math::right(x, n_leaves));
    VERIFY_EQUAL("parent", parent[x.val], tree_math::parent(x, n_leaves));
    VERIFY_EQUAL("sibling", sibling[x.val], tree_math::sibling(x, n_leaves));
  }

  return std::nullopt;
}

///
/// EncryptionKeyTestVector
///

EncryptionKeyTestVector::EncryptionKeyTestVector(CipherSuite suite_in,
                                                 uint32_t n_leaves,
                                                 uint32_t n_generations)
  : suite(suite_in)
  , encryption_secret{ bytes(suite.secret_size(), 0xA0) }
{
  auto leaf_count = LeafCount{ n_leaves };
  auto src = GroupKeySource(suite, leaf_count, encryption_secret.data);

  auto handshake = GroupKeySource::RatchetType::handshake;
  auto application = GroupKeySource::RatchetType::application;
  handshake_keys.resize(n_leaves);
  application_keys.resize(n_leaves);
  for (uint32_t i = 0; i < n_leaves; i++) {
    handshake_keys[i].steps.resize(n_generations);
    application_keys[i].steps.resize(n_generations);

    for (uint32_t j = 0; j < n_generations; ++j) {
      auto hs_key_nonce = src.get(handshake, LeafIndex{ j }, j);
      handshake_keys[i].steps[j].key = { std::move(hs_key_nonce.key) };
      handshake_keys[i].steps[j].nonce = { std::move(hs_key_nonce.nonce) };

      auto app_key_nonce = src.get(application, LeafIndex{ j }, j);
      application_keys[i].steps[j].key = { std::move(app_key_nonce.key) };
      application_keys[i].steps[j].nonce = { std::move(app_key_nonce.nonce) };
    }
  }
}

std::optional<std::string>
EncryptionKeyTestVector::verify() const
{
  if (handshake_keys.size() != application_keys.size()) {
    return "Malformed test vector";
  }

  auto handshake = GroupKeySource::RatchetType::handshake;
  auto application = GroupKeySource::RatchetType::application;
  auto leaf_count = LeafCount{ static_cast<uint32_t>(handshake_keys.size()) };
  auto src = GroupKeySource(suite, leaf_count, encryption_secret.data);

  for (uint32_t i = 0; i < application_keys.size(); i++) {
    for (uint32_t j = 0; j < handshake_keys[i].steps.size(); j++) {
      const auto key_nonce = src.get(handshake, LeafIndex(i), j);
      const auto& key = handshake_keys[i].steps[j].key.data;
      const auto& nonce = handshake_keys[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  for (uint32_t i = 0; i < application_keys.size(); i++) {
    for (uint32_t j = 0; j < application_keys[i].steps.size(); j++) {
      const auto key_nonce = src.get(application, LeafIndex(i), j);
      const auto& key = application_keys[i].steps[j].key.data;
      const auto& nonce = application_keys[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  return std::nullopt;
}

///
/// KeyScheduleTestVector
///

KeyScheduleTestVector::KeyScheduleTestVector(CipherSuite suite_in,
                                             uint32_t n_epochs)
  : suite(suite_in)
  , group_id{ from_hex("00010203") }
  , initial_tree_hash{ random_bytes(suite.digest().hash_size) }
  , initial_init_secret{ random_bytes(suite.secret_size()) }
{
  auto group_context =
    GroupContext{ group_id.data, 0, initial_tree_hash.data, {}, {} };
  auto ctx = tls::marshal(group_context);
  auto epoch = KeyScheduleEpoch(suite, ctx, initial_init_secret.data);
  auto transcript_hash = TranscriptHash(suite);

  for (size_t i = 0; i < n_epochs; i++) {
    auto tree_hash = random_bytes(suite.digest().hash_size);
    auto commit = MLSPlaintext{
      group_id.data, group_context.epoch, { SenderType::member, 0 }, Commit{}
    };
    auto commit_secret = random_bytes(suite.secret_size());
    auto psk_secret = random_bytes(suite.secret_size());

    transcript_hash.update_confirmed(commit);

    group_context.epoch += 1;
    group_context.tree_hash = tree_hash;
    group_context.confirmed_transcript_hash = transcript_hash.confirmed;
    auto ctx = tls::marshal(group_context);
    auto next_epoch = epoch.next(commit_secret, psk_secret, ctx);

    commit.confirmation_tag = { next_epoch.confirmation_tag(
      transcript_hash.confirmed) };
    commit.membership_tag = { epoch.membership_tag(group_context, commit) };
    transcript_hash.update_interim(commit);
    epoch = next_epoch;

    auto welcome_secret =
      KeyScheduleEpoch::welcome_secret(suite, epoch.joiner_secret, psk_secret);

    epochs.push_back({
      commit,
      { tree_hash },
      { commit_secret },
      { psk_secret },

      { transcript_hash.confirmed },
      { transcript_hash.interim },
      { ctx },

      { epoch.joiner_secret },
      { welcome_secret },
      { epoch.epoch_secret },
      { epoch.init_secret },

      { epoch.sender_data_secret },
      { epoch.encryption_secret },
      { epoch.exporter_secret },
      { epoch.authentication_secret },
      { epoch.external_secret },
      { epoch.confirmation_key },
      { epoch.membership_key },
      { epoch.resumption_secret },

      epoch.external_priv.public_key,
    });
  }
}

std::optional<std::string>
KeyScheduleTestVector::verify() const
{
  auto group_context =
    GroupContext{ group_id.data, 0, initial_tree_hash.data, {}, {} };
  auto ctx = tls::marshal(group_context);
  auto epoch = KeyScheduleEpoch(suite, ctx, initial_init_secret.data);
  auto transcript_hash = TranscriptHash(suite);

  for (size_t i = 0; i < epochs.size(); i++) {
    const auto& tve = epochs[i];

    // Verify the membership tag on the commit
    auto actual_membership_tag =
      epoch.membership_tag(group_context, tve.commit);
    auto expected_membership_tag =
      opt::get(tve.commit.membership_tag).mac_value;
    VERIFY_EQUAL(
      "membership tag", actual_membership_tag, expected_membership_tag);

    // Update the transcript hash with the commit
    transcript_hash.update(epochs[i].commit);
    VERIFY_EQUAL("confirmed transcript hash",
                 transcript_hash.confirmed,
                 tve.confirmed_transcript_hash.data);
    VERIFY_EQUAL("interim transcript hash",
                 transcript_hash.interim,
                 tve.interim_transcript_hash.data);

    // Ratchet forward the key schedule
    group_context.epoch += 1;
    group_context.tree_hash = epochs[i].tree_hash.data;
    group_context.confirmed_transcript_hash = transcript_hash.confirmed;
    auto ctx = tls::marshal(group_context);
    VERIFY_EQUAL("context", ctx, tve.group_context.data);

    epoch = epoch.next(tve.commit_secret.data, tve.psk_secret.data, ctx);

    // Verify the confirmation tag on the Commit
    auto actual_confirmation_tag =
      epoch.confirmation_tag(transcript_hash.confirmed);
    auto expected_confirmation_tag =
      opt::get(tve.commit.confirmation_tag).mac_value;
    VERIFY_EQUAL(
      "confirmation tag", actual_confirmation_tag, expected_confirmation_tag);

    // Verify the rest of the epoch
    VERIFY_EQUAL("joiner secret", epoch.joiner_secret, tve.joiner_secret.data);
    VERIFY_EQUAL("epoch secret", epoch.epoch_secret, tve.epoch_secret.data);
    VERIFY_EQUAL("init secret", epoch.init_secret, tve.init_secret.data);

    auto welcome_secret = KeyScheduleEpoch::welcome_secret(
      suite, tve.joiner_secret.data, tve.psk_secret.data);
    VERIFY_EQUAL("welcome secret", welcome_secret, tve.welcome_secret.data);

    VERIFY_EQUAL("sender data secret",
                 epoch.sender_data_secret,
                 tve.sender_data_secret.data);
    VERIFY_EQUAL(
      "encryption secret", epoch.encryption_secret, tve.encryption_secret.data);
    VERIFY_EQUAL(
      "exporter secret", epoch.exporter_secret, tve.exporter_secret.data);
    VERIFY_EQUAL("authentication secret",
                 epoch.authentication_secret,
                 tve.authentication_secret.data);
    VERIFY_EQUAL(
      "external secret", epoch.external_secret, tve.external_secret.data);
    VERIFY_EQUAL(
      "confirmation key", epoch.confirmation_key, tve.confirmation_key.data);
    VERIFY_EQUAL(
      "membership key", epoch.membership_key, tve.membership_key.data);
    VERIFY_EQUAL(
      "resumption secret", epoch.resumption_secret, tve.resumption_secret.data);

    VERIFY_EQUAL(
      "external pub", epoch.external_priv.public_key, tve.external_pub);
  }

  return std::nullopt;
}

///
/// TreeHashingTestVector
///

TreeHashingTestVector::TreeHashingTestVector(CipherSuite /* suite */,
                                             uint32_t /* n_leaves */)
{}

std::optional<std::string>
TreeHashingTestVector::verify() const
{
  return std::nullopt;
}

///
/// MessagesTestVector
///

MessagesTestVector::MessagesTestVector() {}

std::optional<std::string>
MessagesTestVector::verify() const
{
  return std::nullopt;
}

} // namespace mls_vectors
