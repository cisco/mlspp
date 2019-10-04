/*

TODO: Add-in-place
TODO: Streamable input?
TODO: Metrics output (streamable?)

Input format:

{
  "initial_size": n,
  "steps": [
    {"action": "add"}
    {"action": "update", "by": n},
    {"action": "remove", "by": n, "of": b},
  ]
}

*/

#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "crypto.h"
#include "session.h"

#include "json.hpp"

using nlohmann::json;

const std::string kActionAdd = "add";
const std::string kActionUpdate = "update";
const std::string kActionRemove = "remove";

enum struct Action
{
  add,
  update,
  remove
};

void
from_json(const json& j, Action& obj)
{
  const auto& action = j.get<std::string>();
  if (action == kActionAdd) {
    obj = Action::add;
  } else if (action == kActionUpdate) {
    obj = Action::update;
  } else if (action == kActionRemove) {
    obj = Action::remove;
  }

  std::runtime_error("Invalid action type: " + action);
}

struct Step
{
  Action action;
  uint32_t by;
  uint32_t of;
};

void
from_json(const json& j, Step& obj)
{
  obj.action = j.at("action").get<Action>();

  obj.by = 0;
  if (j.find("by") != j.end()) {
    obj.by = j.at("by").get<uint32_t>();
  }

  obj.of = 0;
  if (j.find("of") != j.end()) {
    obj.of = j.at("of").get<uint32_t>();
  }
}

struct Script
{
  size_t initial_size;
  std::vector<Step> steps;
};

void
from_json(const json& j, Script& obj)
{
  obj.initial_size = j.at("initial_size").get<size_t>();
  obj.steps = j.at("steps").get<std::vector<Step>>();
}

std::string
read_file(const std::string& filename)
{
  std::ifstream file(filename, std::ios::binary);
  file.unsetf(std::ios::skipws);

  std::streampos fileSize;
  file.seekg(0, std::ios::end);
  fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> vec;
  vec.reserve(fileSize);
  vec.insert(vec.begin(),
             std::istream_iterator<uint8_t>(file),
             std::istream_iterator<uint8_t>());

  return std::string(vec.begin(), vec.end());
}

struct Simulation
{
  std::vector<mls::CipherSuite> suites;
  mls::SignatureScheme scheme;
  std::vector<std::optional<mls::Session>> sessions;

  Simulation(std::vector<mls::CipherSuite> suites, mls::SignatureScheme scheme)
    : suites(suites)
    , scheme(scheme)
  {}

  mls::bytes random() const { return mls::random_bytes(32); }

  mls::ClientInitKey fresh_client_init_key() const
  {
    auto priv = mls::SignaturePrivateKey::generate(scheme);
    auto id = random();
    auto cred = mls::Credential::basic(id, priv);
    auto init = random();
    return mls::ClientInitKey{ id, suites, init, cred };
  }

  void broadcast(const mls::bytes& message)
  {
    for (auto& session : sessions) {
      if (!session.has_value()) {
        continue;
      }

      session.value().handle(message);
    }
  }

  // XXX: Right now, this is by "create one-member and add"; it should be done
  // via direct initialization (Init)
  void init(size_t initial_size)
  {
    auto group_id = random();
    auto cik0 = fresh_client_init_key();
    auto cik1 = fresh_client_init_key();
    auto [session0, welcome, add] = mls::Session::start(group_id, cik0, cik1);
    auto session1 = mls::Session::join(cik1, welcome, add);

    sessions = { session0, session1 };
    while (sessions.size() < initial_size) {
      auto cik = fresh_client_init_key();
      auto [welcome, add] = sessions[0].value().add(cik);
      broadcast(add);
      sessions.emplace_back(mls::Session::join(cik, welcome, add));
    }

    std::cout << "Created a group with " << initial_size << " members"
              << std::endl;
  }

  // TODO Add at the leftmost blank slot instead of at the right edge
  void add(uint32_t by)
  {
    auto cik = fresh_client_init_key();
    auto [welcome, add] = sessions[by].value().add(cik);
    broadcast(add);
    sessions.emplace_back(mls::Session::join(cik, welcome, add));

    std::cout << "Added by " << by << std::endl;
  }

  void update(uint32_t by)
  {
    auto update = sessions[by].value().update(random());
    broadcast(update);

    std::cout << "Updated member " << by << std::endl;
  }

  void remove(uint32_t by, uint32_t of)
  {
    auto remove = sessions[by].value().remove(random(), of);
    sessions[of] = std::nullopt;
    broadcast(remove);

    std::cout << "Removed member " << of << " by " << by << std::endl;
  }
};

int
main(int argc, char** argv)
{
  const auto suites =
    std::vector<mls::CipherSuite>{ mls::CipherSuite::X25519_SHA256_AES128GCM };
  const auto scheme = mls::SignatureScheme::Ed25519;

  if (argc < 2) {
    std::cout << "Usage: simulator <script.json>" << std::endl;
  }

  std::string filename(argv[1]);
  auto script_json = read_file(filename);
  auto script = json::parse(script_json).get<Script>();

  // Initialize a set of sessions
  Simulation sim(suites, scheme);
  sim.init(script.initial_size);

  // Follow the steps in the script
  for (const auto& step : script.steps) {
    switch (step.action) {
      case Action::add:
        sim.add(step.by);
        break;

      case Action::update:
        sim.update(step.by);
        break;

      case Action::remove:
        sim.remove(step.by, step.of);
        break;
    }
  }

  std::cout << "Done" << std::endl; // XXX
}
