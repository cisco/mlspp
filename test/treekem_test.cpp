#include "common.h"
#include "treekem.h"

#include <gtest/gtest.h>

using namespace mls;

TEST(TreeKEMTest, ParentNodeEquals)
{
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  auto initA = HPKEPrivateKey::generate(suite);
  auto initB = HPKEPrivateKey::generate(suite);

  auto nodeA =
    ParentNode{ initA.public_key(), { LeafIndex(1), LeafIndex(2) }, { 3, 4 } };
  auto nodeB =
    ParentNode{ initB.public_key(), { LeafIndex(5), LeafIndex(6) }, { 7, 8 } };

  ASSERT_EQ(nodeA, nodeA);
  ASSERT_EQ(nodeB, nodeB);
  ASSERT_NE(nodeA, nodeB);
}

TEST(TreeKEMTest, NodePublicKey)
{
  const CipherSuite suite = CipherSuite::P256_SHA256_AES128GCM;
  auto initA = HPKEPrivateKey::generate(suite);
  auto initB = HPKEPrivateKey::generate(suite);

  auto parent = Node{ ParentNode{ initA.public_key(), {}, {} } };
  ASSERT_EQ(parent.public_key(), initA.public_key());

  const SignatureScheme scheme = SignatureScheme::Ed25519;
  auto identity_priv = SignaturePrivateKey::generate(scheme);
  auto cred = Credential::basic({ 0, 1, 2, 3 }, identity_priv.public_key());
  auto leaf =
    Node{ KeyPackage{ suite, initB.public_key(), identity_priv, cred } };
  ASSERT_EQ(leaf.public_key(), initB.public_key());
}

TEST(TreeKEMTest, OptionalNodeHashes)
{
  // Hash a leaf node
  // Hash a parent node
}
