#include "roster.h"
#include <catch.hpp>

using namespace mls;

#define SIG_TEST SignatureScheme::P256_SHA256

TEST_CASE("Rosters can be created and accessed", "[roster]")
{
  auto priv = SignaturePrivateKey::generate(SIG_TEST);
  auto pub = priv.public_key();

  RawKeyCredential cred{ pub };
  REQUIRE(cred.public_key() == pub);

  Roster roster;
  roster.put(0, cred);
  REQUIRE(roster.get(0).public_key() == pub);
}
