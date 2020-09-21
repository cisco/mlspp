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
    throw std::system_error(errno, std::system_category(), "failed to open " + filename);
  }
  return lines;
}

TEST_CASE("Certificate Known-Answer depth 2")
{
  // TODO Do this for each supported signature algorithm
  //      ... maybe including a case where parent and child have different
  //      algorithms
  // TODO create different cert chains based on depth and algo

  // Chain is of depth 2
  const auto root_der = from_hex("3081e1308194a0030201020211009aa08f97d6a086c76e3e14e96a6b4a77300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b6570032100fa4e1015f305460917b1ab006f84633c85c1682327de59c76326050b0594a310a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff040530030101ff300506032b65700341004ed66c26b2b91c8d87897205dba8999652e49d5b2251d8e28b08cb4404ff7c1c7fe8aff2d3a13089e4b5624084a54b78df771bae22166787750707c7eb6f5705");
  const auto leaf_der = from_hex("3081de308191a00302010202110089f2d252744135d5f3f005f1edc609d2300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b65700321009d28cb0fdb2da572066ba1c90dedbf8010ba85fba4bffa8fffe67e26d5515252a320301e300e0603551d0f0101ff0404030202a4300c0603551d130101ff04023000300506032b6570034100b59e47d1f9de4d595ca2d0a2a1dbc6a59eacfa3e5958d315d3809d6f7abba0474643a620e81b91ec987b30214a30818f97e47f21ad15d3b304a6ebf142b36105");
  const auto issuing_der = from_hex("3081e1308194a003020102021100d9443a777704afc9df1ef0dabd328e6e300506032b65703000301e170d3230303932313036333230345a170d3230303932323036333230345a3000302a300506032b65700321009f3fea85d329dd340cba5f7b9655b79af89784a658509a50c2eec63a3e3c3a3ba3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff040530030101ff300506032b657003410059fe72402a0431fdcf97cb0cd72bbb902c5cb0f1f0ad6b14c1cb6127bf2c55a27bf929113bbfb18162cecad5b511eae910e22fedf7756726f03cf6f9382fef0e");

	auto root = Certificate{ root_der };
	auto leaf = Certificate{ leaf_der };
  auto issuing = Certificate{ issuing_der };


  CHECK(root.raw == root_der);
  CHECK(issuing.raw == issuing_der);
  CHECK(leaf.raw == leaf_der);

  // TODO fix this one valid_from is implemented.
  // CHECK_FALSE(leaf.valid_from(root));
}
