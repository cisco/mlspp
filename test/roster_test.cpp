#include "roster.h"
#include <catch.hpp>

using namespace mls;

TEST_CASE("Rosters can be created and accessed", "[roster]")
{
  auto priv = SignaturePrivateKey::generate();
  auto pub = priv.public_key();

  RawKeyCredential cred{ pub };
  REQUIRE(cred.public_key() == pub);

  Roster roster;
  roster.put(0, cred);
  REQUIRE(roster.get(0).public_key() == pub);
}
