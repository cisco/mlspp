#include <doctest/doctest.h>
#include <hpke/certificate.h>

#include "common.h"

#include <fstream>
#include <iostream>
#include <vector>

TEST_CASE("Certificate Known-Answer depth 2")
{
  // TODO(suhas) Do this for each supported signature algorithm
  //      ... maybe including a case where parent and child have different
  //      algorithms
  // TODO(suhas) create different cert chains based on depth and algo

  // Chain is of depth 2
  const auto root_der = from_hex(
    "3081ff3081b2a00302010202101025963d9aefe2cdaf9c8017b9836b9b300506032b657030"
    "00301e170d3230313132353232333135365a170d3230313132363232333135365a3000302a"
    "300506032b65700321006fd52c993c4554c550c6f57a8c9b44834a99889c882e597d78e952"
    "afdbde748ea3423040300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff301d0603551d110101ff04133011810f7573657240646f6d61696e2e636f6d30"
    "0506032b6570034100accb5e7e05e607ca0c5a9103e962e360ea0b95ab8c876993af2660ef"
    "7e22ae6714f3d7b6b9594ac3eaaeeef263f764bc4939c84005db311ac4740b665694b004");
  const auto issuing_der = from_hex(
    "3081ff3081b2a0030201020210277bfa0157eaa84f1dc14c07ade455dd300506032b657030"
    "00301e170d3230313132353232333135365a170d3230313132363232333135365a3000302a"
    "300506032b65700321005ddafa25a2313f8dd19be29736825207a67282c2c6e327b8ac5127"
    "102e0d4eeda3423040300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff301d0603551d110101ff04133011810f7573657240646f6d61696e2e636f6d30"
    "0506032b6570034100eea828a18197fd4bd5751959318a7def21ce0c588b4107dc51ab6eb3"
    "e1a0a7c440cc019c186fbdbe227c0f368ab993c8a5af5c9681e11583d0442cafcaf01300");
  const auto leaf_der = from_hex(
    "3081fd3081b0a003020102021100af5442db77d60c749fffe8eebf193afa300506032b6570"
    "3000301e170d3230313132353232333135365a170d3230313132363232333135365a300030"
    "2a300506032b6570032100885cc6836723e204b54275c97928481c55b149e1ed0e22b30d2f"
    "1a89aa24e2d1a33f303d300e0603551d0f0101ff0404030202a4300c0603551d130101ff04"
    "023000301d0603551d110101ff04133011810f7573657240646f6d61696e2e636f6d300506"
    "032b65700341002cc5b3f1a8954ccc872ecddf5779fb007c08ebc869227dec09cfba8fd977"
    "ea49a182a2e51b67d4440d42248f6951f4c765e9e72e301225c953e89b2747129a0c");

  auto root = Certificate{ root_der };
  auto issuing = Certificate{ issuing_der };
  auto leaf = Certificate{ leaf_der };

  CHECK(root.raw == root_der);
  CHECK(issuing.raw == issuing_der);
  CHECK(leaf.raw == leaf_der);

  CHECK(leaf.valid_from(issuing));
  CHECK(issuing.valid_from(root));
  CHECK(root.valid_from(root));

  CHECK(!leaf.is_ca());
  CHECK(issuing.is_ca());
  CHECK(root.is_ca());

  CHECK_EQ(leaf.email_addresses().at(0), "user@domain.com");

  // negative tests
  CHECK_FALSE(issuing.valid_from(leaf));
  CHECK_FALSE(root.valid_from(issuing));
  CHECK_FALSE(root.valid_from(leaf));
}
