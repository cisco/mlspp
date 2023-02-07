#include <mls/key_schedule.h>
#include <mls/state.h>
#include <mls/tree_math.h>
#include <mls_vectors/mls_vectors.h>

#include <iostream> // XXX

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
operator<<(std::ostream& str, const std::vector<uint8_t>& obj)
{
  return str << to_hex(obj);
}

static std::ostream&
operator<<(std::ostream& str, const HPKEPublicKey& obj)
{
  return str << to_hex(tls::marshal(obj));
}

static std::ostream&
operator<<(std::ostream& str, const MLSContent::RawContent& obj)
{
  return var::visit(
    overloaded{
      [&](const Proposal&) -> std::ostream& { return str << "[Proposal]"; },
      [&](const Commit&) -> std::ostream& { return str << "[Commit]"; },
      [&](const ApplicationData&) -> std::ostream& {
        return str << "[ApplicationData]";
      },
    },
    obj);
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
std::optional<mls::NodeIndex>
TreeMathTestVector::null_if_invalid(NodeIndex input, NodeIndex answer) const
{
  // For some invalid cases (e.g., leaf.left()), we currently return the node
  // itself instead of null
  if (input == answer) {
    return std::nullopt;
  }

  // NodeIndex::parent is irrespective of tree size, so we might step out of the
  // tree under consideration.
  if (answer.val >= n_nodes.val) {
    return std::nullopt;
  }

  return answer;
}

TreeMathTestVector::TreeMathTestVector(uint32_t n_leaves_in)
  : n_leaves(n_leaves_in)
  , n_nodes(n_leaves)
  , root(NodeIndex::root(n_leaves))
  , left(n_nodes.val)
  , right(n_nodes.val)
  , parent(n_nodes.val)
  , sibling(n_nodes.val)
{
  for (NodeIndex x{ 0 }; x.val < n_nodes.val; x.val++) {
    left[x.val] = null_if_invalid(x, x.left());
    right[x.val] = null_if_invalid(x, x.right());
    parent[x.val] = null_if_invalid(x, x.parent());
    sibling[x.val] = null_if_invalid(x, x.sibling());
  }
}

std::optional<std::string>
TreeMathTestVector::verify() const
{
  VERIFY_EQUAL("n_nodes", n_nodes, NodeCount(n_leaves));
  VERIFY_EQUAL("root", root, NodeIndex::root(n_leaves));

  for (NodeIndex x{ 0 }; x.val < n_nodes.val; x.val++) {
    VERIFY_EQUAL("left", null_if_invalid(x, x.left()), left[x.val]);
    VERIFY_EQUAL("right", null_if_invalid(x, x.right()), right[x.val]);
    VERIFY_EQUAL("parent", null_if_invalid(x, x.parent()), parent[x.val]);
    VERIFY_EQUAL("sibling", null_if_invalid(x, x.sibling()), sibling[x.val]);
  }

  return std::nullopt;
}

///
/// TreeMathTestVector
///

CryptoBasicsTestVector::RefHash::RefHash(CipherSuite suite)
  : label("RefHash")
  , value(random_bytes(suite.secret_size()))
  , out(suite.raw_ref(from_ascii(label), value))
{
}

std::optional<std::string>
CryptoBasicsTestVector::RefHash::verify(CipherSuite suite) const
{
  VERIFY_EQUAL("ref hash", out, suite.raw_ref(from_ascii(label), value));
  return std::nullopt;
}

CryptoBasicsTestVector::ExpandWithLabel::ExpandWithLabel(CipherSuite suite)
  : secret(random_bytes(suite.secret_size()))
  , label("ExpandWithLabel")
  , context(random_bytes(suite.secret_size()))
  , length(static_cast<uint16_t>(suite.key_size()))
  , out(suite.expand_with_label(secret, label, context, length))
{
}

std::optional<std::string>
CryptoBasicsTestVector::ExpandWithLabel::verify(CipherSuite suite) const
{
  VERIFY_EQUAL("expand with label",
               out,
               suite.expand_with_label(secret, label, context, length));
  return std::nullopt;
}

CryptoBasicsTestVector::DeriveSecret::DeriveSecret(CipherSuite suite)
  : secret(random_bytes(suite.secret_size()))
  , label("DeriveSecret")
  , out(suite.derive_secret(secret, label))
{
}

std::optional<std::string>
CryptoBasicsTestVector::DeriveSecret::verify(CipherSuite suite) const
{
  VERIFY_EQUAL("derive secret", out, suite.derive_secret(secret, label));
  return std::nullopt;
}

CryptoBasicsTestVector::SignWithLabel::SignWithLabel(CipherSuite suite)
  : priv(SignaturePrivateKey::generate(suite))
  , pub(priv.public_key)
  , content(random_bytes(suite.secret_size()))
  , label("SignWithLabel")
  , signature(priv.sign(suite, from_ascii(label), content))
{
}

std::optional<std::string>
CryptoBasicsTestVector::SignWithLabel::verify(CipherSuite suite) const
{
  auto ascii_label = from_ascii(label);
  VERIFY("verify with label",
         pub.verify(suite, ascii_label, content, signature));

  auto new_signature = priv.sign(suite, ascii_label, content);
  VERIFY("sign with label",
         pub.verify(suite, ascii_label, content, new_signature));

  return std::nullopt;
}

CryptoBasicsTestVector::EncryptWithLabel::EncryptWithLabel(CipherSuite suite)
  : priv(HPKEPrivateKey::generate(suite))
  , pub(priv.public_key)
  , label("EncryptWithLabel")
  , context(random_bytes(suite.secret_size()))
  , plaintext(random_bytes(suite.secret_size()))
{
  auto ct = pub.encrypt(suite, from_ascii(label), context, plaintext);
  kem_output = ct.kem_output;
  ciphertext = ct.ciphertext;
}

std::optional<std::string>
CryptoBasicsTestVector::EncryptWithLabel::verify(CipherSuite suite) const
{
  auto ascii_label = from_ascii(label);
  auto ct = HPKECiphertext{ kem_output, ciphertext };
  auto pt = priv.decrypt(suite, ascii_label, context, ct);
  VERIFY_EQUAL("decrypt with label", pt, plaintext);

  auto new_ct = pub.encrypt(suite, from_ascii(label), context, plaintext);
  auto new_pt = priv.decrypt(suite, ascii_label, context, new_ct);
  VERIFY_EQUAL("encrypt with label", new_pt, plaintext);

  return std::nullopt;
}

CryptoBasicsTestVector::CryptoBasicsTestVector(CipherSuite suite)
  : cipher_suite(suite)
  , ref_hash(suite)
  , expand_with_label(suite)
  , derive_secret(suite)
  , sign_with_label(suite)
  , encrypt_with_label(suite)
{
}

std::optional<std::string>
CryptoBasicsTestVector::verify() const
{
  auto result = ref_hash.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = expand_with_label.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = derive_secret.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = sign_with_label.verify(cipher_suite);
  if (result) {
    return result;
  }

  result = encrypt_with_label.verify(cipher_suite);
  if (result) {
    return result;
  }

  return std::nullopt;
}

///
/// SecretTreeTestVector
///

SecretTreeTestVector::SenderData::SenderData(mls::CipherSuite suite)
  : sender_data_secret(random_bytes(suite.secret_size()))
  , ciphertext(random_bytes(suite.secret_size()))
{
  auto key_and_nonce =
    KeyScheduleEpoch::sender_data_keys(suite, sender_data_secret, ciphertext);
  key = key_and_nonce.key;
  nonce = key_and_nonce.nonce;
}

std::optional<std::string>
SecretTreeTestVector::SenderData::verify(mls::CipherSuite suite) const
{
  auto key_and_nonce =
    KeyScheduleEpoch::sender_data_keys(suite, sender_data_secret, ciphertext);
  VERIFY_EQUAL("sender data key", key, key_and_nonce.key);
  VERIFY_EQUAL("sender data nonce", nonce, key_and_nonce.nonce);
  return std::nullopt;
}

SecretTreeTestVector::SecretTreeTestVector(
  mls::CipherSuite suite,
  uint32_t n_leaves,
  const std::vector<uint32_t>& generations)
  : cipher_suite(suite)
  , sender_data(suite)
  , encryption_secret(random_bytes(suite.secret_size()))
{
  auto src =
    GroupKeySource(cipher_suite, LeafCount{ n_leaves }, encryption_secret);
  leaves.resize(n_leaves);
  auto zero_reuse_guard = ReuseGuard{ 0, 0, 0, 0 };
  for (uint32_t i = 0; i < n_leaves; i++) {
    auto leaf = LeafIndex{ i };

    for (const auto generation : generations) {
      auto hs =
        src.get(ContentType::proposal, leaf, generation, zero_reuse_guard);
      auto app =
        src.get(ContentType::application, leaf, generation, zero_reuse_guard);

      leaves.at(i).push_back(
        RatchetStep{ generation, hs.key, hs.nonce, app.key, app.nonce });

      src.erase(ContentType::proposal, leaf, generation);
      src.erase(ContentType::application, leaf, generation);
    }
  }
}

std::optional<std::string>
SecretTreeTestVector::verify() const
{
  auto sender_data_error = sender_data.verify(cipher_suite);
  if (sender_data_error) {
    return sender_data_error;
  }

  auto n_leaves = static_cast<uint32_t>(leaves.size());
  auto src =
    GroupKeySource(cipher_suite, LeafCount{ n_leaves }, encryption_secret);
  auto zero_reuse_guard = ReuseGuard{ 0, 0, 0, 0 };
  for (uint32_t i = 0; i < n_leaves; i++) {
    auto leaf = LeafIndex{ i };

    for (const auto& step : leaves[i]) {
      auto generation = step.generation;

      auto hs =
        src.get(ContentType::proposal, leaf, generation, zero_reuse_guard);
      VERIFY_EQUAL("hs key", hs.key, step.handshake_key);
      VERIFY_EQUAL("hs nonce", hs.nonce, step.handshake_nonce);

      auto app =
        src.get(ContentType::application, leaf, generation, zero_reuse_guard);
      VERIFY_EQUAL("app key", app.key, step.application_key);
      VERIFY_EQUAL("app nonce", app.nonce, step.application_nonce);
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
/// MessageProtectionTestVector
///

MessageProtectionTestVector::MessageProtectionTestVector(CipherSuite suite)
  : cipher_suite(suite)
  , group_id(random_bytes(suite.secret_size()))
  , epoch(0xA0A0A0A0A0A0A0A0)
  , tree_hash(random_bytes(suite.secret_size()))
  , confirmed_transcript_hash(random_bytes(suite.secret_size()))
  , n_leaves(2)
  , signature_priv(SignaturePrivateKey::generate(suite))
  , signature_pub(signature_priv.public_key)
  , encryption_secret(random_bytes(suite.secret_size()))
  , sender_data_secret(random_bytes(suite.secret_size()))
  , membership_key(random_bytes(suite.secret_size()))
  , confirmation_tag(random_bytes(suite.secret_size()))
  , proposal{ GroupContextExtensions{} }
  , commit{ /* XXX(RLB) this is technically invalid, empty w/o path */ }
  , application{ random_bytes(suite.secret_size()) }
  , group_context{ cipher_suite,
                   group_id,
                   epoch,
                   tree_hash,
                   confirmed_transcript_hash,
                   {} }
  , keys(cipher_suite, n_leaves, encryption_secret)
{
  proposal_pub = protect_pub(proposal);
  proposal_priv = protect_priv(proposal);

  commit_pub = protect_pub(commit);
  commit_priv = protect_priv(commit);

  application_priv = protect_priv(application);
}

std::optional<std::string>
MessageProtectionTestVector::verify()
{
  // Initialize fields that don't get set from JSON
  group_context = GroupContext{
    cipher_suite, group_id, epoch, tree_hash, confirmed_transcript_hash, {}
  };

  keys = GroupKeySource(cipher_suite, n_leaves, encryption_secret);

  signature_priv.set_public_key(cipher_suite);

  // Sanity check the key pairs
  VERIFY_EQUAL("sig kp", signature_priv.public_key, signature_pub);

  // Verify proposal unprotect as PublicMessage
  auto proposal_pub_unprotected = unprotect(proposal_pub);
  VERIFY("proposal pub unprotect auth", proposal_pub_unprotected);
  VERIFY_EQUAL("proposal pub unprotect",
               opt::get(proposal_pub_unprotected).content,
               proposal);

  // Verify proposal unprotect as PrivateMessage
  auto proposal_priv_unprotected = unprotect(proposal_priv);
  VERIFY("proposal priv unprotect auth", proposal_priv_unprotected);
  VERIFY_EQUAL("proposal priv unprotect",
               opt::get(proposal_priv_unprotected).content,
               proposal);

  // Verify commit unprotect as PublicMessage
  auto commit_pub_unprotected = unprotect(commit_pub);
  VERIFY("commit pub unprotect auth", commit_pub_unprotected);
  VERIFY_EQUAL(
    "commit pub unprotect", opt::get(commit_pub_unprotected).content, commit);

  // Verify commit unprotect as PrivateMessage
  auto commit_priv_unprotected = unprotect(commit_priv);
  VERIFY("commit priv unprotect auth", commit_priv_unprotected);
  VERIFY_EQUAL(
    "commit priv unprotect", opt::get(commit_priv_unprotected).content, commit);

  // Verify application data unprotect as PrivateMessage
  auto app_unprotected = unprotect(application_priv);
  VERIFY("app priv unprotect auth", app_unprotected);
  VERIFY_EQUAL(
    "app priv unprotect", opt::get(app_unprotected).content, application);

  // Verify protect/unprotect round-trips
  // XXX(RLB): Note that because (a) unprotect() deletes keys from the ratchet
  // and (b) we are using the same ratchet to send and receive, we need to do
  // these round-trip tests after all the unprotect tests are done.  Otherwise
  // the protect() calls here will re-use generations used the test vector, and
  // then unprotect() will delete the keys, then when you go to decrypt the test
  // vector object, you'll get "expired key".  It might be good to have better
  // safeguards around such reuse.
  auto proposal_pub_protected = protect_pub(proposal);
  auto proposal_pub_protected_unprotected = unprotect(proposal_pub_protected);
  VERIFY("proposal pub protect/unprotect auth",
         proposal_pub_protected_unprotected);
  VERIFY_EQUAL("proposal pub protect/unprotect",
               opt::get(proposal_pub_protected_unprotected).content,
               proposal);

  auto proposal_priv_protected = protect_priv(proposal);
  auto proposal_priv_protected_unprotected = unprotect(proposal_priv_protected);
  VERIFY("proposal priv protect/unprotect auth",
         proposal_priv_protected_unprotected);
  VERIFY_EQUAL("proposal priv protect/unprotect",
               opt::get(proposal_priv_protected_unprotected).content,
               proposal);

  auto commit_pub_protected = protect_pub(commit);
  auto commit_pub_protected_unprotected = unprotect(commit_pub_protected);
  VERIFY("commit pub protect/unprotect auth", commit_pub_protected_unprotected);
  VERIFY_EQUAL("commit pub protect/unprotect",
               opt::get(commit_pub_protected_unprotected).content,
               commit);

  auto commit_priv_protected = protect_priv(commit);
  auto commit_priv_protected_unprotected = unprotect(commit_priv_protected);
  VERIFY("commit priv protect/unprotect auth",
         commit_priv_protected_unprotected);
  VERIFY_EQUAL("commit priv protect/unprotect",
               opt::get(commit_priv_protected_unprotected).content,
               commit);

  auto app_protected = protect_priv(application);
  auto app_protected_unprotected = unprotect(app_protected);
  VERIFY("app priv protect/unprotect auth", app_protected_unprotected);
  VERIFY_EQUAL("app priv protect/unprotect",
               opt::get(app_protected_unprotected).content,
               application);

  return std::nullopt;
}

MLSMessage
MessageProtectionTestVector::protect_pub(
  const mls::MLSContent::RawContent& raw_content) const
{
  auto sender = Sender{ MemberSender{ LeafIndex{ 0 } } };
  auto authenticated_data = bytes{};

  auto content =
    MLSContent{ group_id, epoch, sender, authenticated_data, raw_content };

  auto auth_content = MLSAuthenticatedContent::sign(WireFormat::mls_plaintext,
                                                    content,
                                                    cipher_suite,
                                                    signature_priv,
                                                    group_context);
  if (content.content_type() == ContentType::commit) {
    auth_content.set_confirmation_tag(confirmation_tag);
  }

  return MLSPlaintext::protect(
    auth_content, cipher_suite, membership_key, group_context);
}

MLSMessage
MessageProtectionTestVector::protect_priv(
  const mls::MLSContent::RawContent& raw_content)
{
  auto sender = Sender{ MemberSender{ LeafIndex{ 0 } } };
  auto authenticated_data = bytes{};
  auto padding_size = size_t(0);

  auto content =
    MLSContent{ group_id, epoch, sender, authenticated_data, raw_content };

  auto auth_content = MLSAuthenticatedContent::sign(WireFormat::mls_ciphertext,
                                                    content,
                                                    cipher_suite,
                                                    signature_priv,
                                                    group_context);
  if (content.content_type() == ContentType::commit) {
    auth_content.set_confirmation_tag(confirmation_tag);
  }

  return MLSCiphertext::protect(
    auth_content, cipher_suite, keys, sender_data_secret, padding_size);
}

std::optional<MLSContent>
MessageProtectionTestVector::unprotect(const MLSMessage& message)
{
  auto do_unprotect = overloaded{
    [&](const MLSPlaintext& pt) {
      return pt.unprotect(cipher_suite, membership_key, group_context);
    },
    [&](const MLSCiphertext& ct) {
      return ct.unprotect(cipher_suite, keys, sender_data_secret);
    },
    [](const auto& /* other */) -> std::optional<MLSAuthenticatedContent> {
      return std::nullopt;
    }
  };

  auto maybe_auth_content = var::visit(do_unprotect, message.message);
  if (!maybe_auth_content) {
    return std::nullopt;
  }

  auto auth_content = opt::get(maybe_auth_content);
  if (!auth_content.verify(cipher_suite, signature_pub, group_context)) {
    return std::nullopt;
  }

  return auth_content.content;
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
  pub.set_hash_all();
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
  auto proposal_ref = ProposalRef{ 32, 0xa0 };

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
    content_auth_app, suite, keys, opaque, 10) };

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
