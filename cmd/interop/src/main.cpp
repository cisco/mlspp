
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

static json
make_sample(uint64_t type)
{
  auto suite = mls::CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519;
  auto n = 5;
  switch (type) {
    case TestVectorType::TREE_MATH:
      return mls_vectors::TreeMathTestVector::create(n);

    case TestVectorType::ENCRYPTION:
      return mls_vectors::EncryptionTestVector::create(suite, n, n);

    case TestVectorType::KEY_SCHEDULE:
      return mls_vectors::KeyScheduleTestVector::create(suite, n, n);

    case TestVectorType::TRANSCRIPT:
      return mls_vectors::TranscriptTestVector::create(suite);

    case TestVectorType::TREEKEM:
      return mls_vectors::TreeKEMTestVector::create(suite, n);

    case TestVectorType::MESSAGES:
      return mls_vectors::MessagesTestVector::create();

    default:
      return nullptr;
  }
}

static void
print_sample(uint64_t type)
{
  auto j = make_sample(type);
  if (j.is_null()) {
    std::cout << "Invalid test vector type" << std::endl;
    return;
  }

  std::cout << j.dump(2) << std::endl;
}

#define NO_SAMPLE 0xffffffffffffffff
DEFINE_uint64(sample, NO_SAMPLE, "Generate a sample JSON file (by enum value)");
DEFINE_uint64(port, 50001, "Listen for gRPC on this port");

int
main(int argc, char* argv[])
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  if (FLAGS_sample != NO_SAMPLE) {
    print_sample(FLAGS_sample);
    return 0;
  }

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

  return 0;
}
