#include <mls/key_schedule.h>
#include <mls/state.h>
#include <mls/tree_math.h>
#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

///
/// Assertions for verifying test vectors
///

static std::ostream&
operator<<(std::ostream& str, const NodeIndex& obj)
{
  return str << obj.val;
}

static std::ostream&
operator<<(std::ostream& str, const NodeCount& obj)
{
  return str << obj.val;
}

template<typename T>
static std::ostream&
operator<<(std::ostream& str, const std::optional<T>& obj)
{
  if (!obj) {
    return str << "(nullopt)";
  }

  return str << opt::get(obj);
}

static std::ostream&
operator<<(std::ostream& str, const bytes& obj)
{
  return str << to_hex(obj);
}

static std::ostream&
operator<<(std::ostream& str, const HPKEPublicKey& obj)
{
  return str << to_hex(tls::marshal(obj));
}

static std::ostream&
operator<<(std::ostream& str, const MLSAuthenticatedContent& obj)
{
  return str << to_hex(tls::marshal(obj));
}

static std::ostream&
operator<<(std::ostream& str, const TreeKEMPublicKey& /* obj */)
{
  return str << "[TreeKEMPublicKey]";
}

template<typename T>
inline typename std::enable_if<T::_tls_serializable, std::ostream&>::type
operator<<(std::ostream& str, const T& obj)
{
  return str << to_hex(tls::marshal(obj));
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY(label, test)                                                    \
  if (!(test)) {                                                               \
    return std::string(label);                                                 \
  }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY_EQUAL(label, actual, expected)                                  \
  if (auto err = verify_equal(label, actual, expected)) {                      \
    return err;                                                                \
  }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY_TLS_RTT(label, Type, expected)                                  \
  if (auto err = verify_round_trip<Type>(label, expected)) {                   \
    return err;                                                                \
  }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERIFY_TLS_RTT_VAL(label, Type, expected, val)                         \
  if (auto err = verify_round_trip<Type>(label, expected, val)) {              \
    return err;                                                                \
  }

template<typename T, typename U>
static std::optional<std::string>
verify_equal(const std::string& label, const T& actual, const U& expected)
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
verify_round_trip(const std::string& label, const bytes& expected)
{
  auto noop = [](const auto& /* unused */) { return true; };
  return verify_round_trip<T>(label, expected, noop);
}

template<typename T, typename F>
static std::optional<std::string>
verify_round_trip(const std::string& label, const bytes& expected, const F& val)
{
  auto obj = T{};
  try {
    obj = tls::get<T>(expected);
  } catch (const std::exception& e) {
    auto ss = std::stringstream();
    ss << "Decode error: " << label << " " << e.what();
    return ss.str();
  }

  if (!val(obj)) {
    auto ss = std::stringstream();
    ss << "Validation error: " << label;
    return ss.str();
  }

  auto actual = tls::marshal(obj);
  VERIFY_EQUAL(label, actual, expected);
  return std::nullopt;
}

///
/// TreeMathTestVector
///

// XXX(RLB): This is a hack to get the tests working in the right format.  In
// reality, the tree math functions should be updated to be fallible.
static std::optional<mls::NodeIndex>
null_if_same(NodeIndex input, NodeIndex answer)
{
  if (input == answer) {
    return std::nullopt;
  }

  return answer;
}

TreeMathTestVector
TreeMathTestVector::create(uint32_t n_leaves)
{
  auto tv = TreeMathTestVector{};
  tv.n_leaves = LeafCount{ n_leaves };
  tv.n_nodes = NodeCount(tv.n_leaves);
  tv.root.resize(n_leaves);

  tv.n_nodes = NodeCount(tv.n_leaves);
  tv.left.resize(tv.n_nodes.val);
  tv.right.resize(tv.n_nodes.val);
  tv.parent.resize(tv.n_nodes.val);
  tv.sibling.resize(tv.n_nodes.val);

  // Root is special
  for (LeafCount n{ 1 }; n.val <= n_leaves; n.val++) {
    tv.root[n.val - 1] = NodeIndex::root(n);
  }

  // Left, right, parent, sibling are relative
  for (NodeIndex x{ 0 }; x.val < tv.n_nodes.val; x.val++) {
    tv.left[x.val] = null_if_same(x, x.left());
    tv.right[x.val] = null_if_same(x, x.right());
    tv.parent[x.val] = null_if_same(x, x.parent());
    tv.sibling[x.val] = null_if_same(x, x.sibling());
  }

  // Ancestor takes two leaf nodes
  tv.ancestor.resize(tv.n_leaves.val);
  for (LeafIndex x{ 0 }; x.val < tv.n_leaves.val; x.val++) {
    tv.ancestor[x.val].resize(tv.n_leaves.val);
    for (LeafIndex y{ 0 }; y.val < tv.n_leaves.val; y.val++) {
      tv.ancestor[x.val][y.val] = x.ancestor(y);
    }
  }

  return tv;
}

std::optional<std::string>
TreeMathTestVector::verify() const
{
  VERIFY_EQUAL("n_nodes", n_nodes, NodeCount(n_leaves));

  auto ss = std::stringstream();
  for (LeafCount n{ 1 }; n.val <= n_leaves.val; n.val++) {
    VERIFY_EQUAL("root", root[n.val - 1], NodeIndex::root(n));
  }

  for (NodeIndex x{ 0 }; x.val < n_nodes.val; x.val++) {
    VERIFY_EQUAL("left", left[x.val], null_if_same(x, x.left()));
    VERIFY_EQUAL("right", right[x.val], null_if_same(x, x.right()));
    VERIFY_EQUAL("parent", parent[x.val], null_if_same(x, x.parent()));
    VERIFY_EQUAL("sibling", sibling[x.val], null_if_same(x, x.sibling()));
  }

  for (LeafIndex x{ 0 }; x.val < n_leaves.val; x.val++) {
    for (LeafIndex y{ 0 }; y.val < n_leaves.val; y.val++) {
      VERIFY_EQUAL("ancestor", ancestor[x.val][y.val], x.ancestor(y));
    }
  }

  return std::nullopt;
}
///
/// EncryptionTestVector
///

EncryptionTestVector
EncryptionTestVector::create(CipherSuite suite,
                             uint32_t n_leaves,
                             uint32_t n_generations)
{
  auto tv = EncryptionTestVector{};
  tv.cipher_suite = suite;
  tv.encryption_secret = random_bytes(suite.secret_size());
  tv.sender_data_secret = random_bytes(suite.secret_size());
  tv.padding_size = 10;

  auto ciphertext = random_bytes(suite.secret_size());
  auto sender_data_key_nonce = KeyScheduleEpoch::sender_data_keys(
    suite, tv.sender_data_secret, ciphertext);
  tv.sender_data_info = {
    ciphertext,
    sender_data_key_nonce.key,
    sender_data_key_nonce.nonce,
  };

  auto sig_privs = std::vector<SignaturePrivateKey>{};
  auto tree = TreeKEMPublicKey(suite);
  for (uint32_t i = 0; i < n_leaves; i++) {
    auto leaf_priv = HPKEPrivateKey::generate(suite);
    auto sig_priv = SignaturePrivateKey::generate(suite);
    auto cred = Credential::basic({});
    auto leaf = LeafNode(suite,
                         leaf_priv.public_key,
                         sig_priv.public_key,
                         cred,
                         Capabilities::create_default(),
                         Lifetime::create_default(),
                         {},
                         sig_priv);

    sig_privs.emplace_back(std::move(sig_priv));
    tree.add_leaf(leaf);
  }
  tree.set_hash_all();
  tv.tree = tls::marshal(tree);

  auto src = GroupKeySource(suite, tree.size, tv.encryption_secret);

  auto group_id = bytes{ 0, 1, 2, 3 };
  auto epoch = epoch_t(0x0001020304050607);
  auto group_context =
    GroupContext{ suite, group_id, epoch, {}, tree.root_hash(), {} };
  auto proposal = Proposal{ GroupContextExtensions{} };
  auto app_data = ApplicationData{ random_bytes(suite.secret_size()) };
  auto authenticated_data = random_bytes(suite.secret_size());

  tv.leaves.resize(n_leaves);
  auto zero_reuse_guard = ReuseGuard{ 0, 0, 0, 0 };
  for (uint32_t i = 0; i < n_leaves; i++) {
    tv.leaves[i].generations = n_generations;
    tv.leaves[i].handshake.resize(n_generations);
    tv.leaves[i].application.resize(n_generations);

    auto N = LeafIndex{ i };
    auto sender = Sender{ MemberSender{ N } };

    auto hs_content =
      MLSContent{ group_id, epoch, sender, authenticated_data, proposal };
    auto hs_content_auth =
      MLSAuthenticatedContent::sign(WireFormat::mls_ciphertext,
                                    std::move(hs_content),
                                    suite,
                                    sig_privs[i],
                                    group_context);
    tv.leaves[i].handshake_content_auth = tls::marshal(hs_content_auth);

    auto app_content =
      MLSContent{ group_id, epoch, sender, authenticated_data, app_data };
    auto app_content_auth =
      MLSAuthenticatedContent::sign(WireFormat::mls_ciphertext,
                                    std::move(app_content),
                                    suite,
                                    sig_privs[i],
                                    group_context);
    tv.leaves[i].application_content_auth = tls::marshal(app_content_auth);

    for (uint32_t j = 0; j < n_generations; ++j) {
      // Handshake
      auto hs_ct = MLSCiphertext::protect(
        hs_content_auth, suite, N, src, tv.sender_data_secret, tv.padding_size);
      auto hs_key_nonce =
        src.get(ContentType::proposal, N, j, zero_reuse_guard);
      src.erase(ContentType::proposal, N, j);

      tv.leaves[i].handshake[j] = {
        std::move(hs_key_nonce.key),
        std::move(hs_key_nonce.nonce),
        tls::marshal(hs_ct),
      };

      // Application
      auto app_ct = MLSCiphertext::protect(app_content_auth,
                                           suite,
                                           N,
                                           src,
                                           tv.sender_data_secret,
                                           tv.padding_size);
      auto app_key_nonce =
        src.get(ContentType::application, N, j, zero_reuse_guard);
      src.erase(ContentType::application, N, j);

      tv.leaves[i].application[j] = {
        std::move(app_key_nonce.key),
        std::move(app_key_nonce.nonce),
        tls::marshal(app_ct),
      };
    }
  }

  return tv;
}

std::optional<std::string>
EncryptionTestVector::verify() const
{
  auto sender_data_key_nonce = KeyScheduleEpoch::sender_data_keys(
    cipher_suite, sender_data_secret, sender_data_info.ciphertext);
  VERIFY_EQUAL(
    "sender data key", sender_data_key_nonce.key, sender_data_info.key);
  VERIFY_EQUAL(
    "sender data nonce", sender_data_key_nonce.nonce, sender_data_info.nonce);

  auto ratchet_tree = tls::get<TreeKEMPublicKey>(tree);
  ratchet_tree.suite = cipher_suite;
  ratchet_tree.set_hash_all();
  auto n_leaves = ratchet_tree.size;

  auto src = GroupKeySource(cipher_suite, n_leaves, encryption_secret);
  auto zero_reuse_guard = ReuseGuard{ 0, 0, 0, 0 };
  for (uint32_t i = 0; i < leaves.size(); i++) {
    auto N = LeafIndex{ i };

    auto hs_content_auth =
      tls::get<MLSAuthenticatedContent>(leaves[i].handshake_content_auth);
    auto app_content_auth =
      tls::get<MLSAuthenticatedContent>(leaves[i].application_content_auth);

    for (uint32_t j = 0; j < leaves[i].generations; ++j) {
      // Handshake
      const auto& hs_step = leaves[i].handshake[j];
      auto hs_key_nonce =
        src.get(ContentType::proposal, N, j, zero_reuse_guard);
      VERIFY_EQUAL("hs key", hs_key_nonce.key, hs_step.key);
      VERIFY_EQUAL("hs nonce", hs_key_nonce.nonce, hs_step.nonce);

      auto hs_ct = tls::get<MLSCiphertext>(hs_step.ciphertext);
      auto hs_pt =
        hs_ct.unprotect(cipher_suite, ratchet_tree, src, sender_data_secret);
      VERIFY("hs pt ok", hs_pt);
      VERIFY_EQUAL("hs pt", opt::get(hs_pt), hs_content_auth);
      src.erase(ContentType::proposal, N, j);

      // Application
      const auto& app_step = leaves[i].application[j];
      auto app_key_nonce =
        src.get(ContentType::application, N, j, zero_reuse_guard);
      VERIFY_EQUAL("app key", app_key_nonce.key, app_step.key);
      VERIFY_EQUAL("app nonce", app_key_nonce.nonce, app_step.nonce);

      auto app_ct = tls::get<MLSCiphertext>(app_step.ciphertext);
      auto app_pt =
        app_ct.unprotect(cipher_suite, ratchet_tree, src, sender_data_secret);
      VERIFY("app pt ok", app_pt);
      VERIFY_EQUAL("app pt", opt::get(app_pt), app_content_auth);
      src.erase(ContentType::application, N, j);
    }
  }

  return std::nullopt;
}

///
/// KeyScheduleTestVector
///

KeyScheduleTestVector
KeyScheduleTestVector::create(CipherSuite suite,
                              uint32_t n_epochs,
                              uint32_t n_psks)
{
  auto tv = KeyScheduleTestVector{};
  tv.cipher_suite = suite;
  tv.group_id = from_hex("00010203");

  auto group_context = GroupContext{ suite, tv.group_id, 0, {}, {}, {} };
  auto epoch = KeyScheduleEpoch(suite, {}, random_bytes(suite.secret_size()));
  tv.initial_init_secret = epoch.init_secret;

  for (size_t i = 0; i < n_epochs; i++) {
    group_context.tree_hash = random_bytes(suite.digest().hash_size);
    group_context.confirmed_transcript_hash =
      random_bytes(suite.digest().hash_size);
    auto ctx = tls::marshal(group_context);

    auto psks = std::vector<PSKWithSecret>{};
    auto external_psks = std::vector<ExternalPSKInfo>{};
    for (size_t j = 0; j < n_psks; j++) {
      auto id = random_bytes(suite.secret_size());
      auto nonce = random_bytes(suite.secret_size());
      auto secret = random_bytes(suite.secret_size());

      psks.push_back({ PreSharedKeyID{ ExternalPSK{ id }, nonce }, secret });
      external_psks.push_back({ id, nonce, secret });
    }

    auto psk_nonce = bytes{};
    if (i > 0) {
      auto psk = epoch.resumption_psk(
        ResumptionPSKUsage::branch, tv.group_id, epoch_t(i - 1));
      psk_nonce = psk.id.psk_nonce;
      psks.push_back(psk);
    }

    auto commit_secret = random_bytes(suite.secret_size());
    // TODO(RLB) Add Test case for externally-driven epoch change
    epoch = epoch.next(commit_secret, psks, std::nullopt, ctx);

    auto welcome_secret =
      KeyScheduleEpoch::welcome_secret(suite, epoch.joiner_secret, psks);

    tv.epochs.push_back({
      group_context.tree_hash,
      commit_secret,
      group_context.confirmed_transcript_hash,
      external_psks,
      psk_nonce,

      ctx,

      epoch.psk_secret,
      epoch.joiner_secret,
      welcome_secret,
      epoch.init_secret,

      epoch.sender_data_secret,
      epoch.encryption_secret,
      epoch.exporter_secret,
      epoch.authentication_secret,
      epoch.external_secret,
      epoch.confirmation_key,
      epoch.membership_key,
      epoch.resumption_secret,

      epoch.external_priv.public_key,
    });

    group_context.epoch += 1;
  }

  return tv;
}

std::optional<std::string>
KeyScheduleTestVector::verify() const
{
  auto group_context = GroupContext{ cipher_suite, group_id, 0, {}, {}, {} };
  auto epoch = KeyScheduleEpoch(cipher_suite, {}, {});

  // Manually correct the init secret
  epoch.init_secret = initial_init_secret;

  auto epoch_n = epoch_t(0);
  for (const auto& tve : epochs) {
    // Ratchet forward the key schedule
    group_context.tree_hash = tve.tree_hash;
    group_context.confirmed_transcript_hash = tve.confirmed_transcript_hash;
    auto ctx = tls::marshal(group_context);
    VERIFY_EQUAL("group context", ctx, tve.group_context);

    auto psks = std::vector<PSKWithSecret>{};
    for (const auto& psk : tve.external_psks) {
      psks.push_back(
        { PreSharedKeyID{ ExternalPSK{ psk.id }, psk.nonce }, psk.secret });
    }

    if (epoch_n > 0) {
      auto psk =
        epoch.resumption_psk(ResumptionPSKUsage::branch, group_id, epoch_n - 1);
      psk.id.psk_nonce = tve.psk_nonce;
      psks.push_back(psk);
    }

    epoch_n += 1;
    epoch = epoch.next(tve.commit_secret, psks, std::nullopt, ctx);

    // Verify the rest of the epoch
    VERIFY_EQUAL("joiner secret", epoch.joiner_secret, tve.joiner_secret);

    auto welcome_secret =
      KeyScheduleEpoch::welcome_secret(cipher_suite, tve.joiner_secret, psks);
    VERIFY_EQUAL("welcome secret", welcome_secret, tve.welcome_secret);

    VERIFY_EQUAL(
      "sender data secret", epoch.sender_data_secret, tve.sender_data_secret);
    VERIFY_EQUAL(
      "encryption secret", epoch.encryption_secret, tve.encryption_secret);
    VERIFY_EQUAL("exporter secret", epoch.exporter_secret, tve.exporter_secret);
    VERIFY_EQUAL("authentication secret",
                 epoch.authentication_secret,
                 tve.authentication_secret);
    VERIFY_EQUAL("external secret", epoch.external_secret, tve.external_secret);
    VERIFY_EQUAL(
      "confirmation key", epoch.confirmation_key, tve.confirmation_key);
    VERIFY_EQUAL("membership key", epoch.membership_key, tve.membership_key);
    VERIFY_EQUAL(
      "resumption secret", epoch.resumption_secret, tve.resumption_secret);
    VERIFY_EQUAL("init secret", epoch.init_secret, tve.init_secret);

    VERIFY_EQUAL(
      "external pub", epoch.external_priv.public_key, tve.external_pub);

    group_context.epoch += 1;
  }

  return std::nullopt;
}

///
/// TranscriptTestVector
///
TranscriptTestVector
TranscriptTestVector::create(CipherSuite suite)
{
  auto group_id = bytes{ 0, 1, 2, 3 };
  auto epoch = epoch_t(0);
  auto tree_hash_before = random_bytes(suite.digest().hash_size);
  auto confirmed_transcript_hash_before =
    random_bytes(suite.digest().hash_size);
  auto interim_transcript_hash_before = random_bytes(suite.digest().hash_size);

  auto transcript = TranscriptHash(suite);
  transcript.interim = interim_transcript_hash_before;

  auto group_context = GroupContext{
    suite, group_id, epoch, tree_hash_before, confirmed_transcript_hash_before,
    {}
  };
  auto ctx = tls::marshal(group_context);

  auto init_secret = random_bytes(suite.secret_size());
  auto ks_epoch = KeyScheduleEpoch(suite, init_secret, ctx);

  auto sig_priv = SignaturePrivateKey::generate(suite);
  auto leaf_index = LeafIndex{ 0 };

  auto commit_content =
    MLSContent{ group_id, epoch, { MemberSender{ leaf_index } }, {}, Commit{} };
  auto commit_content_auth =
    MLSAuthenticatedContent::sign(WireFormat::mls_plaintext,
                                  std::move(commit_content),
                                  suite,
                                  sig_priv,
                                  group_context);

  transcript.update_confirmed(commit_content_auth);

  const auto confirmation_tag = ks_epoch.confirmation_tag(transcript.confirmed);
  commit_content_auth.set_confirmation_tag(confirmation_tag);

  transcript.update_interim(commit_content_auth);

  return {
    suite,

    group_id,
    epoch,
    tree_hash_before,
    confirmed_transcript_hash_before,
    interim_transcript_hash_before,

    ks_epoch.confirmation_key,
    sig_priv.public_key,
    commit_content_auth,

    ctx,
    transcript.confirmed,
    transcript.interim,
  };
}

std::optional<std::string>
TranscriptTestVector::verify() const
{
  auto group_context_obj = GroupContext{ cipher_suite,
                                         group_id,
                                         epoch,
                                         tree_hash_before,
                                         confirmed_transcript_hash_before,
                                         {} };
  auto ctx = tls::marshal(group_context_obj);
  VERIFY_EQUAL("group context", ctx, group_context);

  // Verify the transcript
  auto transcript = TranscriptHash(cipher_suite);
  transcript.interim = interim_transcript_hash_before;
  transcript.update(commit);
  VERIFY_EQUAL(
    "confirmed", transcript.confirmed, confirmed_transcript_hash_after);
  VERIFY_EQUAL("interim", transcript.interim, interim_transcript_hash_after);

  // Verify that the commit signature is valid
  auto commit_valid =
    commit.verify(cipher_suite, signature_key, group_context_obj);
  VERIFY("commit signature valid", commit_valid);

  // Verify the confirmation tag
  auto ks_epoch = KeyScheduleEpoch(cipher_suite, {}, ctx);
  ks_epoch.confirmation_key = confirmation_key;

  auto confirmation_tag = ks_epoch.confirmation_tag(transcript.confirmed);
  VERIFY("confirmation", commit.check_confirmation_tag(confirmation_tag));

  return std::nullopt;
}

///
/// TreeKEMTestVector
///

static std::tuple<bytes, SignaturePrivateKey, LeafNode>
new_leaf_node(CipherSuite suite)
{
  auto init_secret = random_bytes(suite.secret_size());
  auto leaf_node_secret = suite.derive_secret(init_secret, "node");
  auto leaf_priv = HPKEPrivateKey::derive(suite, leaf_node_secret);
  auto sig_priv = SignaturePrivateKey::generate(suite);
  auto cred = Credential::basic({ 0, 1, 2, 3 });
  auto leaf = LeafNode(suite,
                       leaf_priv.public_key,
                       sig_priv.public_key,
                       cred,
                       Capabilities::create_default(),
                       Lifetime::create_default(),
                       {},
                       sig_priv);
  return std::make_tuple(init_secret, sig_priv, leaf);
}

TreeKEMTestVector
TreeKEMTestVector::create(CipherSuite suite, size_t n_leaves)
{
  auto tv = TreeKEMTestVector{};
  tv.cipher_suite = suite;
  tv.group_id = bytes{ 0, 1, 2, 3 };

  // Make a plan
  tv.add_sender = LeafIndex{ 0 };
  tv.update_sender = LeafIndex{ 0 };
  auto my_index = std::optional<LeafIndex>();
  if (n_leaves > 4) {
    // Make things more interesting if we have space
    my_index = LeafIndex{ static_cast<uint32_t>(n_leaves / 2) };
    tv.add_sender.val = static_cast<uint32_t>(n_leaves / 2) - 2;
    tv.update_sender.val = static_cast<uint32_t>(n_leaves) - 2;
  }

  // Construct a full ratchet tree with the required number of leaves
  auto sig_privs = std::vector<SignaturePrivateKey>{};
  auto pub = TreeKEMPublicKey{ suite };
  for (size_t i = 0; i < n_leaves; i++) {
    auto [init_secret, sig_priv, leaf] = new_leaf_node(suite);
    silence_unused(init_secret);
    sig_privs.push_back(sig_priv);

    auto leaf_secret = random_bytes(suite.secret_size());
    auto added = pub.add_leaf(leaf);
    auto [new_adder_priv, path] =
      pub.encap(added, tv.group_id, {}, leaf_secret, sig_priv, {}, {});
    silence_unused(new_adder_priv);
    pub.merge(added, path);
  }

  if (my_index) {
    pub.blank_path(opt::get(my_index));
  }

  // Add the test participant
  auto add_secret = random_bytes(suite.secret_size());
  auto [test_init_secret, test_sig_priv, test_leaf] = new_leaf_node(suite);
  auto test_index = pub.add_leaf(test_leaf);
  auto [add_priv, add_path] = pub.encap(tv.add_sender,
                                        tv.group_id,
                                        {},
                                        add_secret,
                                        sig_privs[tv.add_sender.val],
                                        {},
                                        {});
  auto [overlap, path_secret, ok] = add_priv.shared_path_secret(test_index);
  silence_unused(test_sig_priv);
  silence_unused(add_path);
  silence_unused(overlap);
  silence_unused(ok);

  pub.set_hash_all();

  tv.ratchet_tree_before = pub;
  tv.tree_hash_before = pub.root_hash();
  tv.my_leaf_secret = test_init_secret;
  tv.my_leaf_node = test_leaf;
  tv.my_path_secret = path_secret;
  tv.root_secret_after_add = add_priv.update_secret;

  // Do a second update that the test participant should be able to process
  auto update_secret = random_bytes(suite.secret_size());
  auto update_context = random_bytes(suite.secret_size());
  auto [update_priv, update_path] = pub.encap(tv.update_sender,
                                              tv.group_id,
                                              update_context,
                                              update_secret,
                                              sig_privs[tv.update_sender.val],
                                              {},
                                              {});
  pub.merge(tv.update_sender, update_path);
  pub.set_hash_all();

  tv.update_path = update_path;
  tv.update_group_context = update_context;
  tv.root_secret_after_update = update_priv.update_secret;
  tv.ratchet_tree_after = pub;
  tv.tree_hash_after = { pub.root_hash() };

  return tv;
}

void
TreeKEMTestVector::initialize_trees()
{
  ratchet_tree_before.suite = cipher_suite;
  ratchet_tree_before.set_hash_all();

  ratchet_tree_after.suite = cipher_suite;
  ratchet_tree_after.set_hash_all();
}

std::optional<std::string>
TreeKEMTestVector::verify() const
{
  // Verify that the trees provided are valid
  VERIFY_EQUAL(
    "tree hash before", ratchet_tree_before.root_hash(), tree_hash_before);
  VERIFY("tree before parent hash valid",
         ratchet_tree_before.parent_hash_valid());

  VERIFY("update path parent hash valid",
         ratchet_tree_before.parent_hash_valid(update_sender, update_path));

  VERIFY_EQUAL(
    "tree hash after", ratchet_tree_after.root_hash(), tree_hash_after);
  VERIFY("tree after parent hash valid",
         ratchet_tree_after.parent_hash_valid());

  // Find ourselves in the tree
  auto maybe_index = ratchet_tree_before.find(my_leaf_node);
  if (!maybe_index) {
    return "Error: key package not found in ratchet tree";
  }

  auto my_index = opt::get(maybe_index);
  auto ancestor = my_index.ancestor(add_sender);

  // Establish a TreeKEMPrivate Key
  auto leaf_node_secret = cipher_suite.derive_secret(my_leaf_secret, "node");
  auto leaf_priv = HPKEPrivateKey::derive(cipher_suite, leaf_node_secret);
  auto priv =
    TreeKEMPrivateKey::joiner(ratchet_tree_before,
                              my_index,
                              leaf_priv,
                              ancestor,
                              static_cast<const bytes&>(my_path_secret));
  VERIFY("private key consistent with tree before",
         priv.consistent(ratchet_tree_before));
  VERIFY_EQUAL(
    "root secret after add", priv.update_secret, root_secret_after_add);

  // Process the UpdatePath
  priv.decap(
    update_sender, ratchet_tree_before, update_group_context, update_path, {});

  auto my_tree_after = ratchet_tree_before;
  my_tree_after.merge(update_sender, update_path);

  // Verify that we ended up in the right place
  VERIFY_EQUAL(
    "root secret after update", priv.update_secret, root_secret_after_update);
  VERIFY_EQUAL("tree after", my_tree_after, ratchet_tree_after);

  return std::nullopt;
}

///
/// MessagesTestVector
///

MessagesTestVector
MessagesTestVector::create()
{
  auto epoch = epoch_t(0xA0A1A2A3A4A5A6A7);
  auto index = LeafIndex{ 0xB0 };
  auto user_id = bytes(16, 0xD1);
  auto group_id = bytes(16, 0xD2);
  auto opaque = bytes(32, 0xD3);
  auto psk_id = ExternalPSK{ bytes(32, 0xD4) };
  auto mac = bytes(32, 0xD5);
  auto suite = CipherSuite{ CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };
  auto group_context =
    GroupContext{ suite, group_id, epoch, opaque, opaque, {} };

  auto version = ProtocolVersion::mls10;
  auto hpke_priv = HPKEPrivateKey::generate(suite);
  auto hpke_pub = hpke_priv.public_key;
  auto hpke_ct = HPKECiphertext{ opaque, opaque };
  auto sig_priv = SignaturePrivateKey::generate(suite);
  auto sig_pub = sig_priv.public_key;

  auto psk_nonce = random_bytes(suite.secret_size());

  // KeyPackage and extensions
  auto cred = Credential::basic(user_id);
  auto leaf_node = LeafNode{ suite,
                             hpke_pub,
                             sig_pub,
                             cred,
                             Capabilities::create_default(),
                             Lifetime::create_default(),
                             {},
                             sig_priv };
  auto key_package = KeyPackage{ suite, hpke_pub, leaf_node, {}, sig_priv };
  auto leaf_node_update =
    leaf_node.for_update(suite, opaque, hpke_pub, {}, sig_priv);
  auto leaf_node_commit =
    leaf_node.for_commit(suite, opaque, hpke_pub, opaque, {}, sig_priv);

  auto sender = Sender{ MemberSender{ index } };

  auto app_id_ext = ApplicationIDExtension{ opaque };

  auto ext_list = ExtensionList{};
  ext_list.add(app_id_ext);

  auto tree = TreeKEMPublicKey{ suite };
  tree.add_leaf(leaf_node);
  tree.add_leaf(leaf_node);
  auto ratchet_tree = RatchetTreeExtension{ tree };

  // Welcome and its substituents
  auto group_info = GroupInfo{
    { suite, group_id, epoch, opaque, opaque, ext_list }, ext_list, mac
  };
  auto group_secrets = GroupSecrets{ opaque,
                                     { { opaque } },
                                     PreSharedKeys{ {
                                       { psk_id, psk_nonce },
                                       { psk_id, psk_nonce },
                                     } } };
  auto welcome = Welcome{ suite, opaque, {}, group_info };
  welcome.encrypt(key_package, opaque);

  // Proposals
  auto add = Add{ key_package };
  auto update = Update{ leaf_node_update };
  auto remove = Remove{ index };
  auto pre_shared_key = PreSharedKey{ psk_id, psk_nonce };
  auto reinit = ReInit{ group_id, version, suite, {} };
  auto external_init = ExternalInit{ opaque };

  // Commit
  auto proposal_ref = ProposalRef{};
  proposal_ref.fill(0xa0);

  auto commit = Commit{ {
                          { proposal_ref },
                          { Proposal{ add } },
                        },
                        UpdatePath{
                          leaf_node_commit,
                          {
                            { hpke_pub, { hpke_ct, hpke_ct } },
                            { hpke_pub, { hpke_ct, hpke_ct, hpke_ct } },
                          },
                        } };

  // MLSAuthenticatedContent with Application / Proposal / Commit
  auto content_auth_app = MLSAuthenticatedContent::sign(
    WireFormat::mls_ciphertext,
    { group_id, epoch, sender, {}, ApplicationData{} },
    suite,
    sig_priv,
    group_context);

  auto content_auth_proposal = MLSAuthenticatedContent::sign(
    WireFormat::mls_plaintext,
    { group_id, epoch, sender, {}, Proposal{ remove } },
    suite,
    sig_priv,
    group_context);

  auto content_auth_commit =
    MLSAuthenticatedContent::sign(WireFormat::mls_plaintext,
                                  { group_id, epoch, sender, {}, commit },
                                  suite,
                                  sig_priv,
                                  group_context);
  content_auth_commit.set_confirmation_tag(opaque);

  // MLSMessage(MLSPlaintext)
  auto mls_plaintext = MLSMessage{ MLSPlaintext::protect(
    content_auth_proposal, suite, opaque, group_context) };

  // MLSMessage(MLSCiphertext)
  auto keys = GroupKeySource(suite, LeafCount{ index.val + 1 }, opaque);
  auto mls_ciphertext = MLSMessage{ MLSCiphertext::protect(
    content_auth_app, suite, index, keys, opaque, 10) };

  return MessagesTestVector{
    tls::marshal(key_package),
    tls::marshal(ratchet_tree),

    tls::marshal(group_info),
    tls::marshal(group_secrets),
    tls::marshal(welcome),

    tls::marshal(add),
    tls::marshal(update),
    tls::marshal(remove),
    tls::marshal(pre_shared_key),
    tls::marshal(reinit),
    tls::marshal(external_init),

    tls::marshal(commit),

    tls::marshal(content_auth_app),
    tls::marshal(content_auth_proposal),
    tls::marshal(content_auth_commit),
    tls::marshal(mls_plaintext),
    tls::marshal(mls_ciphertext),
  };
}

std::optional<std::string>
MessagesTestVector::verify() const
{
  VERIFY_TLS_RTT("KeyPackage", KeyPackage, key_package);
  VERIFY_TLS_RTT("RatchetTree", RatchetTreeExtension, ratchet_tree);

  VERIFY_TLS_RTT("GroupInfo", GroupInfo, group_info);
  VERIFY_TLS_RTT("GroupSecrets", GroupSecrets, group_secrets);
  VERIFY_TLS_RTT("Welcome", Welcome, welcome);

  VERIFY_TLS_RTT("Add", Add, add_proposal);
  VERIFY_TLS_RTT("Update", Update, update_proposal);
  VERIFY_TLS_RTT("Remove", Remove, remove_proposal);
  VERIFY_TLS_RTT("PreSharedKey", PreSharedKey, pre_shared_key_proposal);
  VERIFY_TLS_RTT("ReInit", ReInit, re_init_proposal);
  VERIFY_TLS_RTT("ExternalInit", ExternalInit, external_init_proposal);

  VERIFY_TLS_RTT("Commit", Commit, commit);

  VERIFY_TLS_RTT(
    "MLSAuthenticatedContent/App", MLSAuthenticatedContent, content_auth_app);
  VERIFY_TLS_RTT("MLSAuthenticatedContent/Proposal",
                 MLSAuthenticatedContent,
                 content_auth_proposal);
  VERIFY_TLS_RTT("MLSAuthenticatedContent/Commit",
                 MLSAuthenticatedContent,
                 content_auth_commit);

  auto require_pt = [](const MLSMessage& msg) {
    return msg.wire_format() == WireFormat::mls_plaintext;
  };
  auto require_ct = [](const MLSMessage& msg) {
    return msg.wire_format() == WireFormat::mls_ciphertext;
  };

  VERIFY_TLS_RTT_VAL(
    "MLSMessage/MLSPlaintext", MLSMessage, mls_plaintext, require_pt);
  VERIFY_TLS_RTT_VAL(
    "MLSMessage/MLSCiphertext", MLSMessage, mls_ciphertext, require_ct);

  return std::nullopt;
}

} // namespace mls_vectors
