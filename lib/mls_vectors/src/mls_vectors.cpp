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

std::ostream&
operator<<(std::ostream& str, const TreeKEMPublicKey& /* obj */)
{
  return str << "[TreeKEMPublicKey]";
}

#define VERIFY(label, test)                                                    \
  if (!(test)) {                                                               \
    return std::string(label);                                                 \
  }

#define VERIFY_EQUAL(label, actual, expected)                                  \
  if (auto err = verify_equal(label, actual, expected)) {                      \
    return err;                                                                \
  }

#define VERIFY_TLS_RTT(label, Type, expected)                                  \
  if (auto err = verify_round_trip<Type>(label, expected)) {                   \
    return err;                                                                \
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

template<typename T>
static std::optional<std::string>
verify_round_trip(std::string label, const bytes& expected)
{
  auto obj = tls::get<T>(expected);
  auto actual = tls::marshal(obj);
  VERIFY_EQUAL(label, actual, expected);
  return std::nullopt;
}

///
/// TreeMathTestVector
///
TreeMathTestVector
TreeMathTestVector::create(uint32_t n_leaves)
{
  auto tv = TreeMathTestVector{};
  tv.n_leaves = LeafCount{n_leaves};
  tv.root.resize(n_leaves);

  auto width = NodeCount(tv.n_leaves).val;
  tv.left.resize(width);
  tv.right.resize(width);
  tv.parent.resize(width);
  tv.sibling.resize(width);


  // Root is special
  for (LeafCount n{ 1 }; n.val <= n_leaves; n.val++) {
    tv.root[n.val - 1] = tree_math::root(n);
  }

  // Left, right, parent, sibling are relative
  for (NodeIndex x{ 0 }; x.val < width; x.val++) {
    tv.left[x.val] = tree_math::left(x);
    tv.right[x.val] = tree_math::right(x, tv.n_leaves);
    tv.parent[x.val] = tree_math::parent(x, tv.n_leaves);
    tv.sibling[x.val] = tree_math::sibling(x, tv.n_leaves);
  }

  return tv;
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

EncryptionKeyTestVector
EncryptionKeyTestVector::create(CipherSuite suite,
                                                 uint32_t n_leaves,
                                                 uint32_t n_generations)
{
  auto tv = EncryptionKeyTestVector{};
  tv.suite = suite;
  tv.encryption_secret = { random_bytes(suite.secret_size()) };

  auto leaf_count = LeafCount{ n_leaves };
  auto src = GroupKeySource(suite, leaf_count, tv.encryption_secret.data);

  auto handshake = GroupKeySource::RatchetType::handshake;
  auto application = GroupKeySource::RatchetType::application;
  tv.handshake_keys.resize(n_leaves);
  tv.application_keys.resize(n_leaves);
  for (uint32_t i = 0; i < n_leaves; i++) {
    tv.handshake_keys[i].steps.resize(n_generations);
    tv.application_keys[i].steps.resize(n_generations);

    for (uint32_t j = 0; j < n_generations; ++j) {
      auto hs_key_nonce = src.get(handshake, LeafIndex{ i }, j);
      tv.handshake_keys[i].steps[j].key = { std::move(hs_key_nonce.key) };
      tv.handshake_keys[i].steps[j].nonce = { std::move(hs_key_nonce.nonce) };

      auto app_key_nonce = src.get(application, LeafIndex{ i }, j);
      tv.application_keys[i].steps[j].key = { std::move(app_key_nonce.key) };
      tv.application_keys[i].steps[j].nonce = { std::move(app_key_nonce.nonce) };
    }
  }

  return tv;
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
      const auto key_nonce = src.get(handshake, LeafIndex{ i }, j);
      const auto& key = handshake_keys[i].steps[j].key.data;
      const auto& nonce = handshake_keys[i].steps[j].nonce.data;
      VERIFY_EQUAL("key", key, key_nonce.key);
      VERIFY_EQUAL("nonce", nonce, key_nonce.nonce);
    }
  }

  for (uint32_t i = 0; i < application_keys.size(); i++) {
    for (uint32_t j = 0; j < application_keys[i].steps.size(); j++) {
      const auto key_nonce = src.get(application, LeafIndex{ i }, j);
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

KeyScheduleTestVector
KeyScheduleTestVector::create(CipherSuite suite,
                                             uint32_t n_epochs)
{
  auto tv = KeyScheduleTestVector{};
  tv.suite = suite;
  tv.group_id = { from_hex("00010203") };
  tv.initial_tree_hash = { random_bytes(suite.digest().hash_size) };
  tv.initial_init_secret = { random_bytes(suite.secret_size()) };

  auto group_context =
    GroupContext{ tv.group_id.data, 0, tv.initial_tree_hash.data, {}, {} };
  auto ctx = tls::marshal(group_context);
  auto epoch = KeyScheduleEpoch(suite, ctx, tv.initial_init_secret.data);
  auto transcript_hash = TranscriptHash(suite);

  for (size_t i = 0; i < n_epochs; i++) {
    auto tree_hash = random_bytes(suite.digest().hash_size);
    auto commit = MLSPlaintext{
      tv.group_id.data, group_context.epoch, { SenderType::member, 0 }, Commit{}
    };
    auto commit_secret = random_bytes(suite.secret_size());
    auto psk_secret = random_bytes(suite.secret_size());

    transcript_hash.update_confirmed(commit);

    auto prior_group_context = group_context;
    group_context.epoch += 1;
    group_context.tree_hash = tree_hash;
    group_context.confirmed_transcript_hash = transcript_hash.confirmed;
    auto ctx = tls::marshal(group_context);
    auto next_epoch = epoch.next(commit_secret, psk_secret, ctx);

    commit.confirmation_tag = { next_epoch.confirmation_tag(
      transcript_hash.confirmed) };
    commit.membership_tag = { epoch.membership_tag(prior_group_context,
                                                   commit) };
    transcript_hash.update_interim(commit);
    epoch = next_epoch;

    auto welcome_secret =
      KeyScheduleEpoch::welcome_secret(suite, epoch.joiner_secret, psk_secret);

    tv.epochs.push_back({
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

  return tv;
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
/// TreeKEMTestVector
///

static std::tuple<SignaturePrivateKey, KeyPackage>
new_key_package(CipherSuite suite)
{
  auto init_priv = HPKEPrivateKey::generate(suite);
  auto sig_priv = SignaturePrivateKey::generate(suite);
  auto cred = Credential::basic({ 0, 1, 2, 3 }, sig_priv.public_key);
  auto kp =
    KeyPackage{ suite, init_priv.public_key, cred, sig_priv, std::nullopt };
  return { sig_priv, kp };
}

TreeKEMTestVector
TreeKEMTestVector::create(CipherSuite suite, size_t n_leaves)
{
  auto tv = TreeKEMTestVector{};
  tv.suite = suite;

  // Make a plan
  tv.add_sender = LeafIndex{ 0 };
  tv.update_sender = LeafIndex{ 0 };
  auto my_index = std::optional<LeafIndex>();
  if (n_leaves > 4) {
    // Make things more interesting if we have space
    my_index = LeafIndex{ static_cast<uint32_t>(n_leaves / 2) };
    tv.add_sender.val = (n_leaves / 2) - 2;
    tv.update_sender.val = n_leaves - 2;
  }

  // Construct a full ratchet tree with the required number of leaves
  auto sig_privs = std::vector<SignaturePrivateKey>{};
  auto pub = TreeKEMPublicKey{ suite };
  for (size_t i = 0; i < n_leaves; i++) {
    auto [sig_priv, key_package] = new_key_package(suite);
    sig_privs.push_back(sig_priv);

    auto leaf_secret = random_bytes(suite.secret_size());
    auto added = pub.add_leaf(key_package);
    auto [new_adder_priv, path] =
      pub.encap(added, {}, leaf_secret, sig_priv, std::nullopt);
    silence_unused(new_adder_priv);
    pub.merge(added, path);
  }

  if (my_index) {
    pub.blank_path(opt::get(my_index));
  }

  // Add the test participant
  auto add_secret = random_bytes(suite.secret_size());
  auto [test_sig_priv, test_kp] = new_key_package(suite);
  auto test_index = pub.add_leaf(test_kp);
  auto [add_priv, add_path] = pub.encap(
    tv.add_sender, {}, add_secret, sig_privs[tv.add_sender.val], std::nullopt);
  auto [overlap, path_secret, ok] = add_priv.shared_path_secret(test_index);
  silence_unused(test_sig_priv);
  silence_unused(add_path);
  silence_unused(overlap);
  silence_unused(ok);

  pub.set_hash_all();

  tv.tree_before = pub;
  tv.tree_hash_before = { pub.root_hash() };
  tv.my_key_package = test_kp;
  tv.my_path_secret = { path_secret };

  // Do a second update that the test participant should be able to process
  auto update_secret = random_bytes(suite.secret_size());
  auto [update_priv, update_path_] = pub.encap(tv.update_sender,
                                               {},
                                               update_secret,
                                               sig_privs[tv.update_sender.val],
                                               std::nullopt);
  pub.merge(tv.update_sender, update_path_);
  pub.set_hash_all();

  tv.update_path = update_path_;
  tv.root_secret = { update_priv.update_secret };
  tv.tree_after = pub;
  tv.tree_hash_after = { pub.root_hash() };

  return tv;
}

void
TreeKEMTestVector::initialize_trees()
{
  tree_before.suite = suite;
  tree_before.set_hash_all();

  tree_after.suite = suite;
  tree_after.set_hash_all();
}

std::optional<std::string>
TreeKEMTestVector::verify() const
{
  // Verify that the trees provided are valid
  VERIFY_EQUAL(
    "tree hash before", tree_before.root_hash(), tree_hash_before.data);
  VERIFY("tree before parent hash valid", tree_before.parent_hash_valid());

  VERIFY("update path parent hash valid", update_path.parent_hash_valid(suite));

  VERIFY_EQUAL("tree hash after", tree_after.root_hash(), tree_hash_after.data);
  VERIFY("tree after parent hash valid", tree_after.parent_hash_valid());

  // Find ourselves in the tree
  auto maybe_index = tree_before.find(my_key_package);
  if (!maybe_index) {
    return "Error: key package not found in ratchet tree";
  }

  auto my_index = opt::get(maybe_index);
  auto ancestor = tree_math::ancestor(my_index, add_sender);

  // Establish a TreeKEMPrivate Key
  auto dummy_leaf_priv = HPKEPrivateKey::generate(suite);
  auto priv = TreeKEMPrivateKey::joiner(suite,
                                        tree_before.size(),
                                        my_index,
                                        dummy_leaf_priv,
                                        ancestor,
                                        my_path_secret.data);

  // Process the UpdatePath
  priv.decap(update_sender, tree_before, {}, update_path);

  auto my_tree_after = tree_before;
  my_tree_after.merge(update_sender, update_path);

  // Verify that we ended up in the right place
  VERIFY_EQUAL("root secret", priv.update_secret, root_secret.data);
  VERIFY_EQUAL("tree after", my_tree_after, tree_after);

  return std::nullopt;
}

///
/// MessagesTestVector
///

MessagesTestVector
MessagesTestVector::create()
{
  auto tv = MessagesTestVector{};



  return tv;
}

std::optional<std::string>
MessagesTestVector::verify() const
{
  auto dummy_ciphersuite = CipherSuite{ CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };

  VERIFY_TLS_RTT("KeyPackage", KeyPackage, key_package.data);
  VERIFY_TLS_RTT("Capabilities", CapabilitiesExtension, capabilities.data);
  VERIFY_TLS_RTT("RatchetTree", TreeKEMPublicKey, ratchet_tree.data);

  // GroupInfo is not default-constructible
  auto group_info_obj = tls::get<GroupInfo>(group_info.data, dummy_ciphersuite);
  auto group_info_actual = tls::marshal(group_info_obj);
  VERIFY_EQUAL("GroupInfo", group_info_actual, group_info.data);

  VERIFY_TLS_RTT("GroupSecrets", GroupSecrets, group_secrets.data);
  VERIFY_TLS_RTT("Welcome", Welcome, welcome.data);

  VERIFY_TLS_RTT("PublicGroupState", PublicGroupState, public_group_state.data);

  VERIFY_TLS_RTT("Add", Add, add_proposal.data);
  VERIFY_TLS_RTT("Update", Update, update_proposal.data);
  VERIFY_TLS_RTT("Remove", Remove, remove_proposal.data);
  // TODO VERIFY_TLS_RTT("PreSharedKey", PreSharedKey, pre_shared_key_proposal.data);
  // TODO VERIFY_TLS_RTT("ReInit", ReInit, re_init_proposal.data);
  // TODO VERIFY_TLS_RTT("ExternalInit", ExternalInit, external_init_proposal.data);
  // TODO VERIFY_TLS_RTT("AppAck", AppAck, app_ack_proposal.data);

  VERIFY_TLS_RTT("Commit", Commit, commit.data);

  VERIFY_TLS_RTT("MLSPlaintext/App", MLSPlaintext, mls_plaintext_application.data);
  VERIFY_TLS_RTT("MLSPlaintext/Proposal", MLSPlaintext, mls_plaintext_proposal.data);
  VERIFY_TLS_RTT("MLSPlaintext/Commit", MLSPlaintext, mls_plaintext_commit.data);
  VERIFY_TLS_RTT("MLSCiphertext", MLSCiphertext, mls_ciphertext.data);

  return std::nullopt;
}

} // namespace mls_vectors
