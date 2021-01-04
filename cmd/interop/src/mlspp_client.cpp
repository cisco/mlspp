#include <memory>
#include <string>
#include <sstream>
#include <iostream>

#include <gflags/gflags.h>
#include <grpcpp/grpcpp.h>

#include <tls/tls_syntax.h>
#include <mls/crypto.h>
#include <mls_vectors/mls_vectors.h>

#include "mls_client.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using namespace mls_client;

static constexpr char implementation_name[] = "mlspp";

static std::string
bytes_to_string(const std::vector<uint8_t>& data) {
  return {data.begin(), data.end()};
}

static std::vector<uint8_t>
string_to_bytes(const std::string& str) {
  return {str.begin(), str.end()};
}

class MLSClientImpl final : public MLSClient::Service
{
  Status Name(ServerContext* /* context */,
              const NameRequest* /* request */,
              NameResponse* reply) override
  {
    reply->set_name(implementation_name);
    return Status::OK;
  }

  Status SupportedCiphersuites(ServerContext* /* context */,
              const SupportedCiphersuitesRequest* /* request */,
              SupportedCiphersuitesResponse* reply) override
  {
    reply->clear_ciphersuites();
    for (const auto suite : mls::all_supported_suites) {
      reply->add_ciphersuites(static_cast<uint32_t>(suite));
    }
    return Status::OK;
  }

  Status GenerateTestVector(ServerContext* /* context */,
              const GenerateTestVectorRequest* request,
              GenerateTestVectorResponse* reply) override
  {
    std::vector<uint8_t> tv_data;
    switch (request->test_vector_type()) {
      case TestVectorType::TREE_MATH: {
          auto tv = mls_vectors::TreeMathTestVector::create(request->n_leaves());
          tv_data = tls::marshal(tv);
          break;
      }

      default:
        return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector type");
    }

    reply->set_test_vector(bytes_to_string(tv_data));
    return Status::OK;
  }

  Status VerifyTestVector(ServerContext* /* context */,
              const VerifyTestVectorRequest* request,
              VerifyTestVectorResponse* /* reply */) override
  {
    auto tv_data = string_to_bytes(request->test_vector());
    auto error = std::optional<std::string>();
    switch (request->test_vector_type()) {
      case TestVectorType::TREE_MATH: {
          error = tls::get<mls_vectors::TreeMathTestVector>(tv_data).verify();
          break;
      }

      default:
        return Status(StatusCode::INVALID_ARGUMENT, "Invalid test vector type");
    }

    if (error) {
      return Status(StatusCode::INVALID_ARGUMENT, error.value());
    }

    return Status::OK;
  }

};

DEFINE_uint64(port, 50051, "Port to listen on");

int
main(int argc, char *argv[])
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  auto service = MLSClientImpl{};
  auto server_address = (std::stringstream{} << "0.0.0.0:" << FLAGS_port).str();

  grpc::EnableDefaultHealthCheckService(true);
  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::cout << "Listening on " << server_address << std::endl;
  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();

  return 0;
}
