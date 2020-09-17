#include <doctest/doctest.h>
#include <hpke/certificate.h>

#include "common.h"

#include <vector>

TEST_CASE("Certificate Known-Answer")
{
  // TODO Take a known hex-encoded certs in a chain
  //      ... instantiate them as Certificate objects
  //      ... verify that they agree that they're in a sequence
  // TODO Add a Go script under /scripts/ to generate test data
  // TODO Do this for each supported signature algorithm
  //      ... maybe including a case where parent and child have different algorithms
  /*
  auto root_der = from_hex("...");
  auto issuing_der = from_hex("...");
  auto leaf_der = from_hex("...");

  auto root = Certificate::parse(root_der);
  auto issuing = Certificate::parse(root_der);
  auto leaf = Certificate::parse(root_der);

  CHECK(root.raw == root_der)
  CHECK(issuing.raw == issuing_der)
  CHECK(leaf.raw == leaf_der)

  CHECK(issuing.valid_from(root));
  CHECK(leaf.valid_from(issuing));
  */


  const auto cert {bytes{}};
  //CHECK(cert.value() == 1);

  auto certs = std::vector<Certificate>();
  certs.emplace_back(bytes{});
  //for (int i = 0; i < int(certs.size()); i++) {
  //  CHECK(certs[i].value() == i + 2);
  //}
}
