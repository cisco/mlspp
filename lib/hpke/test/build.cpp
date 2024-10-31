#include <catch2/catch_all.hpp>

TEST_CASE("BoringSSL Define")
{
#if defined(__has_include)
#if __has_include(<openssl/is_boringssl.h>)
#if defined(WITH_BORINGSSL)
  REQUIRE(WITH_BORINGSSL);
#else
  FAIL("Expect #WITH_BORINGSSL set when compiling with BoringSSL");
#endif
#else
  SKIP("Only applicable to BoringSSL");
#endif
#else
  SKIP("Cannot ensure BoringSSL without __has_include()");
#endif
}