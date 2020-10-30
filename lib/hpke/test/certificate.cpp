#include <doctest/doctest.h>
#include <hpke/certificate.h>

#include "common.h"

#include <fstream>

TEST_CASE("Certificate Known-Answer depth 2")
{
  // TODO(suhas) Do this for each supported signature algorithm
  //      ... maybe including a case where parent and child have different
  //      algorithms
  // TODO(suhas) create different cert chains based on depth and algo

  // Chain is of depth 2
  const auto root_der = from_hex(
    "3081e1308194a0030201020211008179775d36e2bddb73377b766afdadfd300506032b6570"
    "3000301e170d3230303932333034353632375a170d3230303932343034353632375a300030"
    "2a300506032b6570032100b3dd38c6f04ffb8d1dba95efd59098298cdbd95ab20a237851f6"
    "cf1d5b697041a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff04"
    "0530030101ff300506032b65700341003a8d8fdc2e4e86c7c5ff383c61cb9bd0db4ad07757"
    "74915a1cd2bb8fd6f2f757957dfcc268e9ab329c53a7cca1d5822d5d57899c5c41eef4e27e"
    "6f6fa3fdcd04");
  const auto issuing_der = from_hex(
    "3081e0308193a003020102021043694a3a0ac4d2f55ca765340f5e3893300506032b657030"
    "00301e170d3230303932333034353632375a170d3230303932343034353632375a3000302a"
    "300506032b657003210088c425c3ef49b8624f6bbf4332931b87b06f7300845b24049ff1c4"
    "824353d385a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff300506032b6570034100898a5cd71e8236ecfb8abc32d45b4aed3a9daff2c290"
    "cfc8f23546cbf83b87f455ce8ba5e8ddbc4f3b18cde351bcca2f73417e2a0e6c8ca9d723ab"
    "eb0bd9fb06");
  const auto leaf_der =
    from_hex("3081de308191a0030201020211008ab6ec20f45f128ecf9e05d912b5296d30050"
             "6032b65703000301e170d3230303932333034353632375a170d32303039323430"
             "34353632375a3000302a300506032b6570032100fa09d9259d7402e96146229a0"
             "acbba85fd3f9d025981bce36a2e8d0e7d2302bba320301e300e0603551d0f0101"
             "ff0404030202a4300c0603551d130101ff04023000300506032b6570034100305"
             "a1a8c9a1eb85eaf36326ce66aab57bfe62713d2387e00f6af91fe86dffa6fefda"
             "89868e0c280163e33876260a5e8524c39ee592427cad3e99a5539ceae903");

  auto root = Certificate{ root_der };
  auto issuing = Certificate{ issuing_der };
  auto leaf = Certificate{ leaf_der };

  CHECK(root.raw == root_der);
  CHECK(issuing.raw == issuing_der);
  CHECK(leaf.raw == leaf_der);

  CHECK(leaf.valid_from(issuing));
  CHECK(issuing.valid_from(root));
  CHECK(root.valid_from(root));

  // negative tests
  CHECK_FALSE(issuing.valid_from(leaf));
  CHECK_FALSE(root.valid_from(issuing));
  CHECK_FALSE(root.valid_from(leaf));
}
