
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>
#include <mls_vectors/mls_vectors.h>

#include "json_details.h"
#include "mls_client_impl.h"

using grpc::Server;
using grpc::ServerBuilder;
using nlohmann::json;
using namespace mls_client;
using namespace mls_vectors;

static constexpr uint64_t CRYPTO_BASICS = 10;
static constexpr uint64_t SECRET_TREE = 11;
static constexpr uint64_t MESSAGE_PROTECTION = 12;

// XXX(RLB): This function currently produces only one example of each type, as
// a top-level object, not a top-level array.  We should produce a more
// comprehensive matrix.
static json
make_test_vector(uint64_t type)
{
  // TODO read parameters from the command line
  auto suite = mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519;
  auto n = uint32_t(5);
  switch (type) {
    case TestVectorType::TREE_MATH:
      return TreeMathTestVector{ n };

    case TestVectorType::KEY_SCHEDULE:
      return KeyScheduleTestVector{ suite, n, n };

    case TestVectorType::TRANSCRIPT:
      return TranscriptTestVector{ suite };

    case TestVectorType::TREEKEM:
      return TreeKEMTestVector{ suite, n };

    case TestVectorType::MESSAGES:
      return MessagesTestVector();

    case CRYPTO_BASICS: {
      auto cases = std::vector<CryptoBasicsTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite);
      }

      return cases;
    }

    case SECRET_TREE: {
      auto cases = std::vector<SecretTreeTestVector>();
      auto generations = std::vector<uint32_t>{ 1, 15 };

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite, 15, generations);
      }

      return cases;
    }

    case MESSAGE_PROTECTION: {
      auto cases = std::vector<MessageProtectionTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite);
      }

      return cases;
    }

    default:
      return nullptr;
  }
}

static void
generate_test_vector(uint64_t type)
{
  auto j = make_test_vector(type);
  if (j.is_null()) {
    std::cout << "Invalid test vector type" << std::endl;
    return;
  }

  std::cout << j.dump(2) << std::endl;
}

template<typename T>
static std::optional<std::string>
verify_test_vector(const json& j)
{
  auto cases = j.get<std::vector<T>>();
  for (auto& tc : cases) {
    auto result = tc.verify();
    if (result) {
      return result;
    }
  }

  return std::nullopt;
}

static std::optional<std::string>
verify_test_vector(uint64_t type)
{
  auto j = json::parse(std::cin);
  switch (type) {
    case TestVectorType::TREE_MATH:
      return verify_test_vector<TreeMathTestVector>(j);

    case TestVectorType::KEY_SCHEDULE:
      return j.get<KeyScheduleTestVector>().verify();

    case TestVectorType::TRANSCRIPT:
      return j.get<TranscriptTestVector>().verify();

    case TestVectorType::TREEKEM:
      return j.get<TreeKEMTestVector>().verify();

    case TestVectorType::MESSAGES:
      return j.get<MessagesTestVector>().verify();

    case CRYPTO_BASICS:
      return verify_test_vector<CryptoBasicsTestVector>(j);

    case SECRET_TREE:
      return verify_test_vector<SecretTreeTestVector>(j);

    case MESSAGE_PROTECTION:
      return verify_test_vector<MessageProtectionTestVector>(j);

    default:
      return "Invalid test vector type";
  }
}

#define NO_SAMPLE 0xffffffffffffffff
DEFINE_uint64(sample, NO_SAMPLE, "Generate a sample JSON file (by enum value)");
DEFINE_uint64(port, 50001, "Listen for gRPC on this port");

#define NO_U64 0xffffffffffffffff
DEFINE_uint64(gen, NO_U64, "Generate test vectors of a given type");
DEFINE_uint64(ver, NO_U64, "Verify test vectors of a given type");
DEFINE_uint64(live,
              NO_U64,
              "Run a gRPC live-testing server on the specified port");

int
main(int argc, char* argv[])
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  gflags::SetUsageMessage("MLSpp interop harness");

  auto do_gen = (FLAGS_gen != NO_U64);
  auto do_ver = (FLAGS_ver != NO_U64);
  auto do_live = (FLAGS_live != NO_U64);

  // Need some action to do
  if (!do_gen && !do_ver && !do_live) {
    gflags::ShowUsageWithFlags(nullptr);
    return 1;
  }

  // Can only do one action per run
  if ((do_gen && do_ver) || (do_ver && do_live) || (do_gen && do_live)) {
    std::cout << "Please choose exactly one action" << std::endl;
    gflags::ShowUsageWithFlags(nullptr);
    return 1;
  }

  // Test vector generation
  if (do_gen) {
    generate_test_vector(FLAGS_gen);
    return 0;
  }

  // Test vector verification
  if (do_ver) {
    auto error = verify_test_vector(FLAGS_ver);

    std::cout << "Verify result: ";
    if (error) {
      std::cout << "FAIL " << error.value();
    } else {
      std::cout << "PASS";
    }
    std::cout << std::endl;

    return error ? 1 : 0;
  }

  // Live testing
  if (do_live) {
    auto service = MLSClientImpl{};
    auto addr_stream = std::stringstream{};
    addr_stream << "0.0.0.0:" << FLAGS_port;
    auto server_address = addr_stream.str();

    grpc::EnableDefaultHealthCheckService(true);
    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::cout << "Listening on " << server_address << std::endl;
    std::unique_ptr<Server> server(builder.BuildAndStart());
    server->Wait();
  }

  return 0;
}
