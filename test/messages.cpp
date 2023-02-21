#include <doctest/doctest.h>
#include <mls/messages.h>
#include <mls/state.h>
#include <mls_vectors/mls_vectors.h>
#include <tls/tls_syntax.h>

using namespace mls;
using namespace mls_vectors;

TEST_CASE("Extensions")
{
  auto kid0 = ApplicationIDExtension{ { 0, 1, 2, 3 } };
  auto tree0 = RatchetTreeExtension{};

  ExtensionList exts;
  exts.add(kid0);
  exts.add(tree0);

  auto kid1 = exts.find<ApplicationIDExtension>();
  auto tree1 = exts.find<RatchetTreeExtension>();

  REQUIRE(kid0 == kid1);
  REQUIRE(tree0 == tree1);
}

// TODO(RLB) Verify sign/verify on:
// * KeyPackage
// * GroupInfo
// * PublicGroupState

class MLSMessageTest
{
public:
  MLSMessageTest()
  {
    auto hpke_priv = HPKEPrivateKey::generate(suite);
    auto leaf_node = LeafNode{
      suite,
      hpke_priv.public_key,
      sig_priv.public_key,
      Credential::basic({}),
      Capabilities::create_default(),
      Lifetime::create_default(),
      {},
      sig_priv,
    };

    tree.add_leaf(leaf_node);

    keys = GroupKeySource{ suite,
                           LeafCount{ 1 },
                           random_bytes(suite.secret_size()) };

    application_content = GroupContent{
      group_id,         epoch, { MemberSender{ index } }, authenticated_data,
      application_data,
    };

    proposal_content = GroupContent{
      group_id,
      epoch,
      { MemberSender{ index } },
      authenticated_data,
      Proposal{ GroupContextExtensions{} },
    };
  }

protected:
  const bytes group_id = from_ascii("group_id");
  const epoch_t epoch = 0xA0A0A0A0A0A0A0A0;
  const bytes authenticated_data = from_ascii("authenticated_data");
  const ApplicationData application_data{ from_ascii("application_data") };
  const Proposal proposal{ GroupContextExtensions{} };

  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };
  const SignaturePrivateKey sig_priv = SignaturePrivateKey::generate(suite);
  const GroupContext context{
    suite,
    group_id,
    epoch,
    random_bytes(suite.secret_size()),
    random_bytes(suite.secret_size()),
    {},
  };
  const bytes membership_key = from_ascii("membership_key");
  const bytes sender_data_secret = from_ascii("sender_data_secret");

  const LeafIndex index{ 0 };
  const size_t padding_size = 1024;

  TreeKEMPublicKey tree{ suite };
  GroupKeySource keys;

  GroupContent application_content;
  GroupContent proposal_content;
};

TEST_CASE_FIXTURE(MLSMessageTest, "AuthenticatedContent Sign/Verify")
{
  // Verify that a sign / verify round-trip works
  auto content_auth = AuthenticatedContent::sign(
    WireFormat::mls_ciphertext, application_content, suite, sig_priv, context);

  REQUIRE(content_auth.verify(suite, sig_priv.public_key, context));
  REQUIRE(content_auth.content == application_content);

  // Verify that `mls_plaintext` is forbidden for ApplicationData
  // NOLINTNEXTLINE(llvm-else-after-return, readability-else-after-return)
  REQUIRE_THROWS(AuthenticatedContent::sign(
    WireFormat::mls_plaintext, application_content, suite, sig_priv, context));
}

TEST_CASE_FIXTURE(MLSMessageTest, "PublicMessage Protect/Unprotect")
{
  auto content = proposal_content;
  auto content_auth_original = AuthenticatedContent::sign(
    WireFormat::mls_plaintext, std::move(content), suite, sig_priv, context);

  auto pt = PublicMessage::protect(
    content_auth_original, suite, membership_key, context);
  auto content_auth_unprotected = pt.unprotect(suite, membership_key, context);
  REQUIRE(content_auth_unprotected == content_auth_original);
}

TEST_CASE_FIXTURE(MLSMessageTest, "PrivateMessage Protect/Unprotect")
{
  auto content = proposal_content;
  auto content_auth_original = AuthenticatedContent::sign(
    WireFormat::mls_ciphertext, std::move(content), suite, sig_priv, context);

  auto ct = PrivateMessage::protect(
    content_auth_original, suite, keys, sender_data_secret, padding_size);
  auto content_auth_unprotected = ct.unprotect(suite, keys, sender_data_secret);
  REQUIRE(content_auth_unprotected == content_auth_original);
}

TEST_CASE("Messages Interop")
{
  auto tv = MessagesTestVector();
  auto result = tv.verify();
  REQUIRE(result == std::nullopt);
}

TEST_CASE("Message Protection Interop")
{
  for (auto suite : all_supported_suites) {
    auto tv = MessageProtectionTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}
