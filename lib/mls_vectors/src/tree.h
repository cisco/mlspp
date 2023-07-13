#include <mls_vectors/mls_vectors.h>

namespace mls_vectors {

using namespace mls;

extern std::array<TreeStructure, 14> all_tree_structures;
extern std::array<TreeStructure, 11> treekem_test_tree_structures;

struct TreeTestCase
{
  CipherSuite suite;
  PseudoRandom::Generator prg;

  bytes group_id;
  uint32_t leaf_counter = 0;
  uint32_t path_counter = 0;

  struct PrivateState
  {
    SignaturePrivateKey sig_priv;
    TreeKEMPrivateKey priv;
    std::vector<LeafIndex> senders;
  };

  std::map<LeafIndex, PrivateState> privs;
  TreeKEMPublicKey pub;

  TreeTestCase(CipherSuite suite_in, PseudoRandom::Generator&& prg_in);

  std::tuple<LeafIndex, HPKEPrivateKey, SignaturePrivateKey> add_leaf();

  void commit(LeafIndex from,
              const std::vector<LeafIndex>& remove,
              bool add,
              std::optional<bytes> maybe_context);

  static TreeTestCase full(CipherSuite suite,
                           const PseudoRandom::Generator& prg,
                           LeafCount leaves,
                           const std::string& label);

  static TreeTestCase with_structure(CipherSuite suite,
                                     const PseudoRandom::Generator& prg,
                                     TreeStructure tree_structure);
};

} // namespace mls_vectors
