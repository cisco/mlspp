#include <doctest/doctest.h>
#include <hpke/certificate.h>

#include "common.h"

#include <fstream>
#include <iostream>
#include <vector>

///
/// File Handling
///

std::vector<std::string>
read_file(const std::string& filename)
{
  std::ifstream f(filename, std::ios::in);
  std::vector<std::string> lines;
  if (f.is_open()) {
    std::string l;
    while (getline(f, l)) {
      lines.push_back(l);
    }
    f.close();
  } else {
    throw std::system_error(
      errno, std::system_category(), "failed to open " + filename);
  }
  return lines;
}

TEST_CASE("Certificate Known-Answer depth 1")
{
  // TODO Take a known hex-encoded certs in a chain
  //      ... instantiate them as Certificate objects
  //      ... verify that they agree that they're in a sequence
  // TODO Add a Go script under /scripts/ to generate test data
  // TODO Do this for each supported signature algorithm
  //      ... maybe including a case where parent and child have different
  //      algorithms
  // TODO create different cert chains based on depth and algo

  // Chain is of depth 2
  const std::string cert_bundle = "../../../../scripts/cert_bundle.bin";
  const std::string root_cert = "../../../../scripts/ca_cert.bin";
  auto certs = read_file(cert_bundle);
  CHECK(certs.size() > 0);

  auto root_hex = read_file(root_cert);
  CHECK(root_hex.size() == 1);

  auto leaf_der = from_hex(certs[0]);
  auto leaf = Certificate{ leaf_der };

	auto issuing_der = from_hex(certs[1]);
	auto issuing = Certificate{ issuing_der };

	auto root_der = from_hex(root_hex[0]);
  auto root = Certificate{ root_der };

  CHECK(root.raw == root_der);
  CHECK(issuing.raw == issuing_der);
  CHECK(leaf.raw == leaf_der);

  // TODO fix this one valid_from is implemented.
  // CHECK_FALSE(leaf.valid_from(root));
}
