
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

// Values used on the command line to indicate the type of test vector to be
// generated / verified
enum struct TestVectorClass
{
  tree_math = 1,
  crypto_basics = 2,
  secret_tree = 3,
  message_protection = 4,
  key_schedule = 5,
  pre_shared_keys = 6,
  tree_validation = 7,
  transcript_hash = 8,
  welcome = 9,
  tree_modifications = 10,
  treekem = 11,
  messages = 12,
  passive_client_scenarios = 13,
};

static json
make_test_vector(uint64_t type)
{
  auto n = uint32_t(5);
  auto tv_class = static_cast<TestVectorClass>(type);
  switch (tv_class) {
    case TestVectorClass::tree_math:
      return std::vector<TreeMathTestVector>{ { n } };

    case TestVectorClass::crypto_basics: {
      auto cases = std::vector<CryptoBasicsTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite);
      }

      return cases;
    }

    case TestVectorClass::secret_tree: {
      auto cases = std::vector<SecretTreeTestVector>();
      auto generations = std::vector<uint32_t>{ 1, 15 };

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite, 15, generations);
      }

      return cases;
    }

    case TestVectorClass::message_protection: {
      auto cases = std::vector<MessageProtectionTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite);
      }

      return cases;
    }

    case TestVectorClass::key_schedule: {
      auto cases = std::vector<KeyScheduleTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite, n);
      }

      return cases;
    }

    case TestVectorClass::pre_shared_keys: {
      auto cases = std::vector<PSKSecretTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite, 5);
      }

      return cases;
    }

    case TestVectorClass::tree_validation: {
      auto cases = std::vector<TreeHashTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        for (const auto& tree_structure : all_tree_structures) {
          cases.emplace_back(suite, tree_structure);
        }
      }

      return cases;
    }

    case TestVectorClass::transcript_hash: {
      auto cases = std::vector<TranscriptTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite);
      }

      return cases;
    }

    case TestVectorClass::welcome: {
      auto cases = std::vector<WelcomeTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        cases.emplace_back(suite);
      }

      return cases;
    }

    case TestVectorClass::tree_modifications: {
      auto cases = std::vector<TreeOperationsTestVector>();

      auto suite = mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519;
      for (auto scenario : TreeOperationsTestVector::all_scenarios) {
        cases.emplace_back(suite, scenario);
      }

      return cases;
    }

    case TestVectorClass::treekem: {
      auto cases = std::vector<TreeKEMTestVector>();

      for (const auto& suite : mls::all_supported_suites) {
        for (const auto& tree_structure : treekem_test_tree_structures) {
          cases.emplace_back(suite, tree_structure);
        }
      }

      return cases;
    }

    case TestVectorClass::messages:
      return std::vector<MessagesTestVector>{
        MessagesTestVector(),
      };

      // TODO(RLB) TestVectorClass::passive_client_scenarios

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
  auto tv_class = static_cast<TestVectorClass>(type);
  switch (tv_class) {
    case TestVectorClass::tree_math:
      return verify_test_vector<TreeMathTestVector>(j);

    case TestVectorClass::crypto_basics:
      return verify_test_vector<CryptoBasicsTestVector>(j);

    case TestVectorClass::secret_tree:
      return verify_test_vector<SecretTreeTestVector>(j);

    case TestVectorClass::message_protection:
      return verify_test_vector<MessageProtectionTestVector>(j);

    case TestVectorClass::key_schedule:
      return verify_test_vector<KeyScheduleTestVector>(j);

    case TestVectorClass::pre_shared_keys:
      return verify_test_vector<PSKSecretTestVector>(j);

    case TestVectorClass::tree_validation:
      return verify_test_vector<TreeHashTestVector>(j);

    case TestVectorClass::transcript_hash:
      return verify_test_vector<TranscriptTestVector>(j);

    case TestVectorClass::welcome:
      return verify_test_vector<WelcomeTestVector>(j);

    case TestVectorClass::tree_modifications:
      return verify_test_vector<TreeOperationsTestVector>(j);

    case TestVectorClass::treekem:
      return verify_test_vector<TreeKEMTestVector>(j);

    case TestVectorClass::messages:
      return verify_test_vector<MessagesTestVector>(j);

    case TestVectorClass::passive_client_scenarios:
      return verify_test_vector<PassiveClientTestVector>(j);

    default:
      return "Invalid test vector type";
  }
}

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
    gflags::ShowUsageWithFlags(argv[0]);
    return 1;
  }

  // Can only do one action per run
  if ((do_gen && do_ver) || (do_ver && do_live) || (do_gen && do_live)) {
    std::cout << "Please choose exactly one action" << std::endl;
    gflags::ShowUsageWithFlags(argv[0]);
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
    addr_stream << "0.0.0.0:" << FLAGS_live;
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
