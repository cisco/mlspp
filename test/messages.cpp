#include <doctest/doctest.h>
#include <mls/messages.h>
#include <mls_vectors/mls_vectors.h>
#include <tls/tls_syntax.h>

#include <iostream>

using namespace mls;
using namespace mls_vectors;

TEST_CASE("Extensions")
{
  auto kid0 = ExternalKeyIDExtension{ { 0, 1, 2, 3 } };
  auto tree0 = RatchetTreeExtension{};

  ExtensionList exts;
  exts.add(kid0);
  exts.add(tree0);

  auto kid1 = exts.find<ExternalKeyIDExtension>();
  auto tree1 = exts.find<RatchetTreeExtension>();

  REQUIRE(kid0 == kid1);
  REQUIRE(tree0 == tree1);
}

// TODO(RLB) Verify sign/verify on:
// * KeyPackage
// * GroupInfo
// * PublicGroupState

TEST_CASE("Messages Interop")
{
  auto tv = MessagesTestVector::create();

  auto result = tv.verify();
  if (result) {
    std::cout << opt::get(result) << std::endl;
  }
  REQUIRE(result == std::nullopt);
}
