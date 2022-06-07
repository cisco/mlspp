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
operator<<(std::ostream& str, const TreeKEMPublicKey& /* obj */)
{
  return str << "[TreeKEMPublicKey]";
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
    tv.root[n.val - 1] = tree_math::root(n);
  }

  // Left, right, parent, sibling are relative
  for (NodeIndex x{ 0 }; x.val < tv.n_nodes.val; x.val++) {
    tv.left[x.val] = null_if_same(x, tree_math::left(x));
    tv.right[x.val] = null_if_same(x, tree_math::right(x, tv.n_leaves));
    tv.parent[x.val] = null_if_same(x, tree_math::parent(x, tv.n_leaves));
    tv.sibling[x.val] = null_if_same(x, tree_math::sibling(x, tv.n_leaves));
  }

  return tv;
}

std::optional<std::string>
TreeMathTestVector::verify() const
{
  VERIFY_EQUAL("n_nodes", n_nodes, NodeCount(n_leaves));

  auto ss = std::stringstream();
  for (LeafCount n{ 1 }; n.val <= n_leaves.val; n.val++) {
    VERIFY_EQUAL("root", root[n.val - 1], tree_math::root(n));
  }

  for (NodeIndex x{ 0 }; x.val < n_nodes.val; x.val++) {
    VERIFY_EQUAL("left", left[x.val], null_if_same(x, tree_math::left(x)));
    VERIFY_EQUAL(
      "right", right[x.val], null_if_same(x, tree_math::right(x, n_leaves)));
    VERIFY_EQUAL(
      "parent", parent[x.val], null_if_same(x, tree_math::parent(x, n_leaves)));
    VERIFY_EQUAL("sibling",
                 sibling[x.val],
                 null_if_same(x, tree_math::sibling(x, n_leaves)));
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

  auto ciphertext = random_bytes(suite.secret_size());
  auto sender_data_key_nonce = KeyScheduleEpoch::sender_data_keys(
    suite, tv.sender_data_secret, ciphertext);
  tv.sender_data_info = {
    ciphertext,
    sender_data_key_nonce.key,
    sender_data_key_nonce.nonce,
  };

  auto tree = TreeKEMPublicKey(suite);
  for (uint32_t i = 0; i < n_leaves; i++) {
    auto leaf_priv = HPKEPrivateKey::generate(suite);
    auto sig_priv = SignaturePrivateKey::generate(suite);
    auto cred = Credential::basic({}, suite, sig_priv.public_key);
    auto leaf = LeafNode(suite,
                         leaf_priv.public_key,
                         cred,
                         Capabilities::create_default(),
                         Lifetime::create_default(),
                         {},
                         sig_priv);
    tree.add_leaf(leaf);
  }
  tv.tree = tls::marshal(tree);

  auto src = GroupKeySource(suite, tree.size(), tv.encryption_secret);

  auto group_id = bytes{ 0, 1, 2, 3 };
  auto epoch = epoch_t(0x0001020304050607);
  auto handshake_type = GroupKeySource::RatchetType::handshake;
  auto application_type = GroupKeySource::RatchetType::application;
  auto proposal = Proposal{ GroupContextExtensions{} };
  auto app_data = ApplicationData{ random_bytes(suite.secret_size()) };

  tv.leaves.resize(n_leaves);
  for (uint32_t i = 0; i < n_leaves; i++) {
    tv.leaves[i].generations = n_generations;
    tv.leaves[i].handshake.resize(n_generations);
    tv.leaves[i].application.resize(n_generations);

    auto N = LeafIndex{ i };
    auto sender_ref = opt::get(tree.leaf_node(LeafIndex{ i })).ref(suite);
    auto sender = Sender{ sender_ref };
    auto hs_pt = MLSPlaintext{ group_id, epoch, sender, proposal };
    hs_pt.wire_format = WireFormat::mls_ciphertext;

    auto app_pt = MLSPlaintext{ group_id, epoch, sender, app_data };
    app_pt.wire_format = WireFormat::mls_ciphertext;

    auto hs_pt_data = tls::marshal(hs_pt);
    auto app_pt_data = tls::marshal(app_pt);

    for (uint32_t j = 0; j < n_generations; ++j) {
      // Handshake
      auto hs_ct = src.encrypt(tree, N, tv.sender_data_secret, hs_pt);
      auto hs_key_nonce = src.get(handshake_type, N, j);
      src.erase(handshake_type, N, j);

      tv.leaves[i].handshake[j] = {
        std::move(hs_key_nonce.key),
        std::move(hs_key_nonce.nonce),
        hs_pt_data,
        tls::marshal(hs_ct),
      };

      // Application
      auto app_ct = src.encrypt(tree, N, tv.sender_data_secret, app_pt);
      auto app_key_nonce = src.get(application_type, N, j);
      src.erase(application_type, N, j);

      tv.leaves[i].application[j] = {
        std::move(app_key_nonce.key),
        std::move(app_key_nonce.nonce),
        app_pt_data,
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
  auto n_leaves = ratchet_tree.size();

  auto handshake_type = GroupKeySource::RatchetType::handshake;
  auto application_type = GroupKeySource::RatchetType::application;

  auto src = GroupKeySource(cipher_suite, n_leaves, encryption_secret);
  for (uint32_t i = 0; i < n_leaves.val; i++) {
    auto N = LeafIndex{ i };
    for (uint32_t j = 0; j < leaves[i].generations; ++j) {
      // Handshake
      const auto& hs_step = leaves[i].handshake[j];
      auto hs_key_nonce = src.get(handshake_type, N, j);
      VERIFY_EQUAL("hs key", hs_key_nonce.key, hs_step.key);
      VERIFY_EQUAL("hs nonce", hs_key_nonce.nonce, hs_step.nonce);

      auto hs_ct = tls::get<MLSCiphertext>(hs_step.ciphertext);
      auto hs_pt = src.decrypt(ratchet_tree, sender_data_secret, hs_ct);
      VERIFY_EQUAL("hs pt", tls::marshal(hs_pt), hs_step.plaintext);
      src.erase(handshake_type, N, j);

      // Application
      const auto& app_step = leaves[i].application[j];
      auto app_key_nonce = src.get(application_type, N, j);
      VERIFY_EQUAL("app key", app_key_nonce.key, app_step.key);
      VERIFY_EQUAL("app nonce", app_key_nonce.nonce, app_step.nonce);

      auto app_ct = tls::get<MLSCiphertext>(app_step.ciphertext);
      auto app_pt = src.decrypt(ratchet_tree, sender_data_secret, app_ct);
      VERIFY_EQUAL("app pt", tls::marshal(app_pt), app_step.plaintext);
      src.erase(application_type, N, j);
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

  auto group_context = GroupContext{ tv.group_id, 0, {}, {}, {} };
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

    auto branch_psk_nonce = bytes{};
    if (i > 0) {
      auto psk = epoch.branch_psk(tv.group_id, epoch_t(i - 1));
      branch_psk_nonce = psk.id.psk_nonce;
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
      branch_psk_nonce,

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
  auto group_context = GroupContext{ group_id, 0, {}, {}, {} };
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
      auto psk = epoch.branch_psk(group_id, epoch_n - 1);
      psk.id.psk_nonce = tve.branch_psk_nonce;
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
    group_id, epoch, tree_hash_before, confirmed_transcript_hash_before, {}
  };
  auto ctx = tls::marshal(group_context);

  auto init_secret = random_bytes(suite.secret_size());
  auto ks_epoch = KeyScheduleEpoch(suite, init_secret, ctx);

  auto sig_priv = SignaturePrivateKey::generate(suite);
  auto credential =
    Credential::basic({ 0, 1, 2, 3 }, suite, sig_priv.public_key);
  auto leaf_node_ref = LeafNodeRef{};
  leaf_node_ref.fill(0xa0);
  auto commit =
    MLSPlaintext{ group_id, epoch, Sender{ leaf_node_ref }, Commit{} };
  commit.sign(suite, group_context, sig_priv);

  transcript.update_confirmed(commit);
  commit.confirmation_tag = ks_epoch.confirmation_tag(transcript.confirmed);

  transcript.update_interim(commit);
  commit.membership_tag = ks_epoch.membership_tag(group_context, commit);

  return {
    suite,

    group_id,
    epoch,
    tree_hash_before,
    confirmed_transcript_hash_before,
    interim_transcript_hash_before,

    ks_epoch.membership_key,
    ks_epoch.confirmation_key,
    credential,
    commit,

    ctx,
    transcript.confirmed,
    transcript.interim,
  };
}

std::optional<std::string>
TranscriptTestVector::verify() const
{
  auto group_context_obj = GroupContext{
    group_id, epoch, tree_hash_before, confirmed_transcript_hash_before, {}
  };
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
    commit.verify(cipher_suite, group_context_obj, credential.public_key());
  VERIFY("commit signature valid", commit_valid);

  // Verify the Commit tags
  auto ks_epoch = KeyScheduleEpoch(cipher_suite, {}, ctx);
  ks_epoch.confirmation_key = confirmation_key;
  ks_epoch.membership_key = membership_key;

  auto confirmation_tag = ks_epoch.confirmation_tag(transcript.confirmed);
  VERIFY_EQUAL(
    "confirmation", confirmation_tag, opt::get(commit.confirmation_tag));

  auto membership_tag = ks_epoch.membership_tag(group_context_obj, commit);
  VERIFY_EQUAL("membership", membership_tag, opt::get(commit.membership_tag));

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
  auto cred = Credential::basic({ 0, 1, 2, 3 }, suite, sig_priv.public_key);
  auto leaf = LeafNode(suite,
                       leaf_priv.public_key,
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
  auto ancestor = tree_math::ancestor(my_index, add_sender);

  // Establish a TreeKEMPrivate Key
  auto leaf_node_secret = cipher_suite.derive_secret(my_leaf_secret, "node");
  auto leaf_priv = HPKEPrivateKey::derive(cipher_suite, leaf_node_secret);
  auto priv =
    TreeKEMPrivateKey::joiner(cipher_suite,
                              ratchet_tree_before.size(),
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
  auto index = LeafIndex{ 0xB0B1B2B3 };
  auto user_id = bytes(16, 0xD1);
  auto group_id = bytes(16, 0xD2);
  auto opaque = bytes(32, 0xD3);
  auto psk_id = ExternalPSK{ bytes(32, 0xD4) };
  auto mac = bytes(32, 0xD5);

  auto version = ProtocolVersion::mls10;
  auto suite = CipherSuite{ CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };
  auto hpke_priv = HPKEPrivateKey::generate(suite);
  auto hpke_pub = hpke_priv.public_key;
  auto hpke_ct = HPKECiphertext{ opaque, opaque };
  auto sig_priv = SignaturePrivateKey::generate(suite);

  auto psk_nonce = random_bytes(suite.secret_size());

  // KeyPackage and extensions
  auto cred = Credential::basic(user_id, suite, sig_priv.public_key);
  auto leaf_node = LeafNode{ suite,
                             hpke_pub,
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

  auto leaf_node_ref = leaf_node.ref(suite);
  auto sender = Sender{ leaf_node_ref };

  auto key_id_ext = ExternalKeyIDExtension{ opaque };

  auto ext_list = ExtensionList{};
  ext_list.add(key_id_ext);

  auto tree = TreeKEMPublicKey{ suite };
  tree.add_leaf(leaf_node);
  tree.add_leaf(leaf_node);
  auto ratchet_tree = RatchetTreeExtension{ tree };

  // Welcome and its substituents
  auto group_info = GroupInfo{ suite,  group_id, epoch,    opaque,
                               opaque, ext_list, ext_list, mac };
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
  auto remove = Remove{ leaf_node_ref };
  auto pre_shared_key = PreSharedKey{ psk_id, psk_nonce };
  auto reinit = ReInit{ group_id, version, suite, {} };
  auto external_init = ExternalInit{ opaque };
  auto app_ack = AppAck{ { { index.val, 0, 5 }, { index.val, 7, 10 } } };

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

  // MLSPlaintext and MLSCiphertext
  auto pt_application =
    MLSPlaintext{ group_id, epoch, sender, ApplicationData{} };
  pt_application.membership_tag = mac;

  auto pt_proposal =
    MLSPlaintext{ group_id, epoch, sender, Proposal{ remove } };
  pt_proposal.membership_tag = mac;

  auto pt_commit = MLSPlaintext{ group_id, epoch, sender, commit };
  pt_commit.confirmation_tag = mac;
  pt_commit.membership_tag = mac;

  auto ct = MLSCiphertext{
    WireFormat::mls_ciphertext,
    group_id,
    epoch,
    ContentType::application,
    opaque,
    opaque,
    opaque,
  };

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
    tls::marshal(app_ack),

    tls::marshal(commit),

    tls::marshal(pt_application),
    tls::marshal(pt_proposal),
    tls::marshal(pt_commit),
    tls::marshal(ct),
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
  VERIFY_TLS_RTT("AppAck", AppAck, app_ack_proposal);

  VERIFY_TLS_RTT("Commit", Commit, commit);

  auto require_pt = [](const auto& pt) {
    return pt.wire_format == WireFormat::mls_plaintext;
  };
  auto require_ct = [](const auto& pt) {
    return pt.wire_format == WireFormat::mls_ciphertext;
  };

  VERIFY_TLS_RTT_VAL(
    "MLSPlaintext/App", MLSPlaintext, mls_plaintext_application, require_pt);
  VERIFY_TLS_RTT_VAL(
    "MLSPlaintext/Proposal", MLSPlaintext, mls_plaintext_proposal, require_pt);
  VERIFY_TLS_RTT_VAL(
    "MLSPlaintext/Commit", MLSPlaintext, mls_plaintext_commit, require_pt);
  VERIFY_TLS_RTT_VAL(
    "MLSCiphertext", MLSCiphertext, mls_ciphertext, require_ct);

  return std::nullopt;
}

} // namespace mls_vectors
