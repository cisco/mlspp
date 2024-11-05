#include "grease.h"
#include <catch2/catch_all.hpp>
#include <mls/core_types.h>
#include <mls/messages.h>

using namespace MLS_NAMESPACE;

TEST_CASE("GREASE capabilities")
{
  const auto capas_before = Capabilities::create_default();
  auto capas_after = capas_before;
  grease(capas_after, {});
  REQUIRE(capas_after != capas_before);
}

TEST_CASE("GREASE extensions")
{
  auto exts_before = ExtensionList{};
  exts_before.add(ApplicationIDExtension{ { 0, 1, 2, 3 } });
  exts_before.add(RatchetTreeExtension{});

  auto exts_after = exts_before;
  grease(exts_after);
  REQUIRE(exts_after != exts_before);
}

TEST_CASE("GREASE consistently")
{
  auto exts = ExtensionList{};
  const auto ext = Extension{ 0x1A1A, { 0, 1, 2, 3 } };
  exts.extensions.insert(std::end(exts.extensions), ext);

  const auto capas_before = Capabilities::create_default();
  auto capas_after = capas_before;
  grease(capas_after, exts);
  REQUIRE(capas_after != capas_before);
  REQUIRE(stdx::contains(capas_after.extensions, ext.type));
}
