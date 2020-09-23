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

TEST_CASE("Certificate Known-Answer depth 2")
{
  // TODO Do this for each supported signature algorithm
  //      ... maybe including a case where parent and child have different
  //      algorithms
  // TODO create different cert chains based on depth and algo

  // Chain is of depth 2
  const auto root_der = from_hex(
    "3081e1308194a003020102021100e8b4888bc9e6ac9f0b256c0ee0d02781300506032b6570"
    "3000301e170d3230303932333033303534375a170d3230303932343033303534375a300030"
    "2a300506032b65700321009486e63b6d0d763c90d888aecd5b30d5f98e055696274fa6e452"
    "be0996eb93dca3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff04"
    "0530030101ff300506032b6570034100bc9504aa4fbab2855ebcf3e36ca23e60c26a3a4374"
    "396e51fd36191d6adefc6aa0debf1f9dd126f8387f40491abcee6fb7b22a9898864ef13e53"
    "fa068295020b");
  const auto issuing_der = from_hex(
    "3081e0308193a00302010202104e40e3b53d3695ab1df21eb08aaaace3300506032b657030"
    "00301e170d3230303932333033303534375a170d3230303932343033303534375a3000302a"
    "300506032b65700321009dc8a19da109e107b76f1c54b76ea2cc21919432507b0a2e012794"
    "5c2e300cb0a3233021300e0603551d0f0101ff0404030202a4300f0603551d130101ff0405"
    "30030101ff300506032b657003410026c17789ceed8e07241a9327a5259dca1caa911a1d26"
    "cf34a0ce4f4723ac6bf0c2777bfceea8288b96232d43dfb3c05dd4cf635d047a5b91ac0310"
    "f85fcf0c0c");
  const auto leaf_der =
    from_hex("3081dd308190a003020102021048d9ffea4d04c0834f07aa7be4388b6e3005060"
             "32b65703000301e170d3230303932333033303534375a170d3230303932343033"
             "303534375a3000302a300506032b657003210071c4972a8780b60044fc04cfa1c"
             "69c35ae0bcf76b76038b486322de0164ac9cfa320301e300e0603551d0f0101ff"
             "0404030202a4300c0603551d130101ff04023000300506032b6570034100eb74f"
             "f02899f2c3bd9dd7a14cdfb0921aa3cdcf57aca4012f5d26158fc4448e1ca7f79"
             "c49908449ee2adf344ad2ebb140bc5f56dea1c34a427a330dcbe512607");

  auto root = Certificate{ root_der };
  auto issuing = Certificate{ issuing_der };
  auto leaf = Certificate{ leaf_der };

  CHECK(root.raw == root_der);
  CHECK(issuing.raw == issuing_der);
  CHECK(leaf.raw == leaf_der);

  // TODO fix this one valid_from is implemented.
  // CHECK_FALSE(leaf.valid_from(root));
}