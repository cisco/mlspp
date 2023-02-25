#include <doctest/doctest.h>
#include <hpke/random.h>
#include <mls/common.h>
#include <mls/treekem.h>
#include <mls_vectors/mls_vectors.h>

using namespace mls;
using namespace mls_vectors;

class TreeKEMTest
{
protected:
  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  std::tuple<HPKEPrivateKey, SignaturePrivateKey, LeafNode> new_leaf_node()
  {
    auto leaf_priv = HPKEPrivateKey::generate(suite);
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
    return std::make_tuple(leaf_priv, sig_priv, leaf);
  }
};

TEST_CASE_FIXTURE(TreeKEMTest, "ParentNode Equality")
{
  auto initA = HPKEPrivateKey::generate(suite);
  auto initB = HPKEPrivateKey::generate(suite);

  auto nodeA =
    ParentNode{ initA.public_key, { 3, 4 }, { LeafIndex(1), LeafIndex(2) } };
  auto nodeB =
    ParentNode{ initB.public_key, { 7, 8 }, { LeafIndex(5), LeafIndex(6) } };

  REQUIRE(nodeA == nodeA);
  REQUIRE(nodeB == nodeB);
  REQUIRE(nodeA != nodeB);
}

TEST_CASE_FIXTURE(TreeKEMTest, "Node public key")
{
  auto parent_priv = HPKEPrivateKey::generate(suite);
  auto parent = Node{ ParentNode{ parent_priv.public_key, {}, {} } };
  REQUIRE(parent.public_key() == parent_priv.public_key);

  auto [leaf_priv_, sig_priv, leaf] = new_leaf_node();
  auto leaf_priv = leaf_priv_;
  silence_unused(sig_priv);

  auto leaf_node = Node{ leaf };
  REQUIRE(leaf_node.public_key() == leaf_priv.public_key);
}

TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM Private Key")
{
  const auto size = LeafCount{ 5 };
  const auto index = LeafIndex{ 2 };
  const auto intersect = NodeIndex{ 3 };
  const auto random = random_bytes(32);
  const auto priv = HPKEPrivateKey::derive(suite, random);
  const auto priv2 = HPKEPrivateKey::generate(suite);
  const auto hash_size = suite.digest().hash_size;

  // Create a tree with N blank leaves
  auto [_leaf_priv, _sig_priv, leaf_node] = new_leaf_node();
  auto pub = TreeKEMPublicKey(suite);
  for (auto i = uint32_t(0); i < size.val; i++) {
    pub.add_leaf(leaf_node);
  }

  // create() populates the direct path
  auto priv_create = TreeKEMPrivateKey::create(pub, index, random);
  REQUIRE(priv_create.path_secrets.find(NodeIndex(4)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.path_secrets.find(NodeIndex(5)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.path_secrets.find(NodeIndex(3)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.path_secrets.find(NodeIndex(7)) !=
          priv_create.path_secrets.end());
  REQUIRE(priv_create.update_secret.size() == hash_size);

  // joiner() populates the leaf and the path above the ancestor,
  // but not the direct path in the middle
  auto priv_joiner =
    TreeKEMPrivateKey::joiner(pub, index, priv, intersect, random);
  REQUIRE(priv_joiner.private_key(NodeIndex(4)));
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(3)) !=
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(7)) !=
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.path_secrets.find(NodeIndex(5)) ==
          priv_joiner.path_secrets.end());
  REQUIRE(priv_joiner.update_secret.size() == hash_size);
  auto last_update_secret = priv_joiner.update_secret;

  // set_leaf_priv() properly sets the leaf secret
  priv_joiner.set_leaf_priv(priv2);
  REQUIRE(priv_joiner.private_key(NodeIndex(index)) == priv2);
  REQUIRE(priv_joiner.update_secret.size() == hash_size);
  REQUIRE(priv_joiner.update_secret == last_update_secret);

  // shared_path_secret() finds the correct ancestor
  auto [overlap_, overlap_secret_, found_] =
    priv_joiner.shared_path_secret(LeafIndex(0));
  auto overlap = overlap_;
  auto overlap_secret = overlap_secret_;
  auto found = found_;
  REQUIRE(found);
  REQUIRE(overlap == NodeIndex(3));
  REQUIRE(overlap_secret == priv_joiner.path_secrets[overlap]);

  // private_key() generates and caches a private key where a path secret
  // exists, and returns nullopt where one doesn't
  auto priv_yes = priv_joiner.private_key(NodeIndex(3));
  REQUIRE(priv_yes);
  REQUIRE(priv_joiner.private_key_cache.find(NodeIndex(3)) !=
          priv_joiner.private_key_cache.end());

  auto priv_no = priv_joiner.private_key(NodeIndex(1));
  REQUIRE_FALSE(priv_no);
}

//        _
//    _       _
//  X   _   _   _
// X X _ X X _ _ _
// 0123456789abcde
TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM Public Key")
{
  const auto size = LeafCount{ 5 };
  const auto removed = LeafIndex{ 2 };
  const auto root_resolution =
    std::vector<NodeIndex>{ NodeIndex{ 1 }, NodeIndex{ 6 }, NodeIndex{ 8 } };

  // Construct a full tree using add_leaf and merge
  auto pub = TreeKEMPublicKey{ suite };
  for (uint32_t i = 0; i < size.val; i++) {
    // Add a leaf
    auto [init_priv, sig_priv, leaf_before_] = new_leaf_node();
    auto leaf_before = leaf_before_;
    silence_unused(init_priv);

    auto index = LeafIndex(i);

    auto add_index = pub.add_leaf(leaf_before);
    REQUIRE(add_index == index);

    auto found = pub.find(leaf_before);
    REQUIRE(found);
    REQUIRE(found == index);

    auto found_leaf = pub.leaf_node(index);
    REQUIRE(found_leaf);
    REQUIRE(found_leaf == leaf_before);

    // Manually construct a direct path to populate nodes above the new leaf
    auto path = UpdatePath{ leaf_before, {} };
    auto dp = pub.filtered_direct_path(NodeIndex(index));
    while (path.nodes.size() < dp.size()) {
      auto node_pub = HPKEPrivateKey::generate(suite).public_key;
      path.nodes.push_back({ node_pub, {} });
    }

    path.leaf_node.sign(suite, sig_priv, std::nullopt);

    // Merge the direct path (ignoring parent hash validity)
    pub.merge(index, path);

    auto leaf_after = path.leaf_node;
    found = pub.find(leaf_after);
    REQUIRE(found);
    REQUIRE(found == index);
    for (const auto& [n_, _res] : dp) {
      auto n = n_;
      REQUIRE(pub.node_at(n).node);
    }

    found_leaf = pub.leaf_node(index);
    REQUIRE(found_leaf);
    REQUIRE(found_leaf == leaf_after);
  }

  // Remove a node and verify that the resolution comes out right
  pub.blank_path(removed);
  REQUIRE_FALSE(pub.leaf_node(removed));
  REQUIRE(root_resolution == pub.resolve(NodeIndex::root(size)));
}

TEST_CASE_FIXTURE(TreeKEMTest, "TreeKEM encap/decap")
{
  const auto size = LeafCount{ 10 };

  auto privs = std::vector<TreeKEMPrivateKey>{};
  auto pubs = std::vector<TreeKEMPublicKey>{};
  auto sig_privs = std::vector<SignaturePrivateKey>{};

  // Add the first member
  auto [init_priv_0, sig_priv_0, leaf0] = new_leaf_node();
  sig_privs.push_back(sig_priv_0);

  auto pub = TreeKEMPublicKey{ suite };
  auto index_0 = pub.add_leaf(leaf0);
  pubs.push_back(pub);
  REQUIRE(index_0 == LeafIndex{ 0 });

  auto priv = TreeKEMPrivateKey::solo(suite, index_0, init_priv_0);
  privs.push_back(priv);
  REQUIRE(priv.consistent(pub));

  auto group_id = from_ascii("group");
  for (uint32_t i = 0; i < size.val - 2; i++) {
    auto adder = LeafIndex{ i };
    auto joiner = LeafIndex{ i + 1 };
    auto context = bytes{ uint8_t(i) };
    auto [init_priv, sig_priv, leaf] = new_leaf_node();
    sig_privs.push_back(sig_priv);

    // Add the new joiner
    auto index = pubs[i].add_leaf(leaf);
    REQUIRE(index == joiner);

    auto leaf_secret = random_bytes(32);
    pubs[i].set_hash_all();
    privs[i] = pubs[i].update(adder, leaf_secret, group_id, sig_privs[i], {});
    auto path = pubs[i].encap(privs[i], context, {});
    REQUIRE(pubs[i].parent_hash_valid(adder, path));

    auto [overlap, path_secret, ok_] = privs[i].shared_path_secret(joiner);
    auto ok = ok_;
    REQUIRE(ok);

    pubs[i].merge(adder, path);
    REQUIRE(privs[i].consistent(pubs[i]));

    // New joiner initializes their private key
    auto joiner_priv = TreeKEMPrivateKey::joiner(
      pubs[i], joiner, init_priv, overlap, path_secret);
    privs.push_back(joiner_priv);
    pubs.push_back(pubs[i]);
    REQUIRE(privs[i + 1].consistent(privs[i]));
    REQUIRE(privs[i + 1].consistent(pubs[i + 1]));

    // Other members update via decap()
    for (uint32_t j = 0; j < i; j++) {
      pubs[j].add_leaf(leaf);
      pubs[j].set_hash_all();
      privs[j].decap(adder, pubs[j], context, path, {});
      pubs[j].merge(adder, path);

      REQUIRE(privs[j].consistent(privs[i]));
      REQUIRE(privs[j].consistent(pubs[j]));
    }
  }
}

TEST_CASE("TreeKEM Interop")
{
  for (auto suite : all_supported_suites) {
    for (auto structure : treekem_test_tree_structures) {
      auto tv = TreeKEMTestVector{ suite, structure };
      REQUIRE(tv.verify() == std::nullopt);
    }
  }
}
