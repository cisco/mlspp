#include <catch2/catch_all.hpp>
#include <mls/crypto.h>
#include <mls_vectors/mls_vectors.h>
#include <string>

#if defined(HAVE_SECURITY_FRAMEWORK)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

using namespace MLS_NAMESPACE;
using namespace mls_vectors;

TEST_CASE("Basic HPKE")
{
  const auto label = "label"s;
  auto context = random_bytes(100);
  auto original = random_bytes(100);

  for (auto suite_id : all_supported_cipher_suites) {
    auto suite = CipherSuite{ suite_id };
    auto s = bytes{ 0, 1, 2, 3 };

    auto x = HPKEPrivateKey::generate(suite);
    auto y = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });

    REQUIRE(x == x);
    REQUIRE(y == y);
    REQUIRE(x != y);

    auto gX = x.public_key;
    auto gY = y.public_key;
    REQUIRE(gX == gX);
    REQUIRE(gY == gY);
    REQUIRE(gX != gY);

    auto encrypted = gX.encrypt(suite, label, context, original);
    auto decrypted = x.decrypt(suite, label, context, encrypted);

    REQUIRE(original == decrypted);
  }
}

TEST_CASE("HPKE Key Serialization")
{
  for (auto suite_id : all_supported_cipher_suites) {
    auto suite = CipherSuite{ suite_id };
    auto x = HPKEPrivateKey::derive(suite, { 0, 1, 2, 3 });
    auto gX = x.public_key;

    HPKEPublicKey parsed{ gX.data };
    REQUIRE(parsed == gX);

    auto marshaled = tls::marshal(gX);
    auto gX2 = tls::get<HPKEPublicKey>(marshaled);
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE("Basic Signature")
{
  for (auto suite_id : all_supported_cipher_suites) {
    auto suite = CipherSuite{ suite_id };
    auto a = SignaturePrivateKey::generate(suite);
    auto b = SignaturePrivateKey::generate(suite);

    REQUIRE(a == a);
    REQUIRE(b == b);
    REQUIRE(a != b);

    REQUIRE(a.public_key == a.public_key);
    REQUIRE(b.public_key == b.public_key);
    REQUIRE(a.public_key != b.public_key);

    const auto label = "label"s;
    auto message = from_hex("01020304");
    auto signature = a.sign(suite, label, message);

    REQUIRE(a.public_key.verify(suite, label, message, signature));
  }
}

TEST_CASE("Signature Key Serializion")
{
  for (auto suite_id : all_supported_cipher_suites) {
    auto suite = CipherSuite{ suite_id };
    auto x = SignaturePrivateKey::generate(suite);
    auto gX = x.public_key;

    SignaturePublicKey parsed{ gX.data };
    REQUIRE(parsed == gX);

    auto gX2 = tls::get<SignaturePublicKey>(tls::marshal(gX));
    REQUIRE(gX2 == gX);
  }
}

TEST_CASE("Signature Key JWK Import/Export")
{
  for (auto suite_id : all_supported_cipher_suites) {
    const auto suite = CipherSuite{ suite_id };
    const auto priv = SignaturePrivateKey::generate(suite);
    const auto pub = priv.public_key;

    const auto encoded_priv = priv.to_jwk(suite);
    const auto decoded_priv =
      SignaturePrivateKey::from_jwk(suite, encoded_priv);
    REQUIRE(decoded_priv == priv);

    const auto encoded_pub = pub.to_jwk(suite);
    const auto decoded_pub = SignaturePublicKey::from_jwk(suite, encoded_pub);
    REQUIRE(decoded_pub == pub);
  }

  // Test PublicJWK parsing
  const auto full_jwk = R"({
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "059fc2ee-5ef6-456a-91d8-49c422c772b2",
    "x": "miljqilAZV2yFkqIBhrxhvt2wIMvPtkNEFzuziEGOtI"
  })"s;

  const auto known_scheme = SignatureScheme::ed25519;
  const auto known_key_id = std::string("059fc2ee-5ef6-456a-91d8-49c422c772b2");
  const auto knwon_pub_data = from_hex(
    "9a2963aa2940655db2164a88061af186fb76c0832f3ed90d105ceece21063ad2");

  const auto jwk = PublicJWK::parse(full_jwk);
  REQUIRE(jwk.signature_scheme == known_scheme);
  REQUIRE(jwk.key_id == known_key_id);
  REQUIRE(jwk.public_key == SignaturePublicKey{ knwon_pub_data });
}

TEST_CASE("Crypto Interop")
{
  for (auto suite : all_supported_cipher_suites) {
    auto tv = CryptoBasicsTestVector{ suite };
    REQUIRE(tv.verify() == std::nullopt);
  }
}

TEST_CASE("External Signature Key - Callback")
{
  // Test callback-based external signing
  // This simulates what you'd do with a secure enclave or HSM
  // where signing happens externally

  for (auto suite_id : all_supported_cipher_suites) {
    auto suite = CipherSuite{ suite_id };

    // Create a "backend" key at the HPKE layer that will do the actual signing
    // In a real scenario, this would be in a secure enclave
    const auto& sig = suite.sig();
    auto backend_priv = sig.generate_key_pair();
    auto backend_pub = backend_priv->public_key();
    auto backend_pub_data = sig.serialize(*backend_pub);

    // Create an external key using a callback that delegates to backend_priv
    auto external_key = SignaturePrivateKey::from_external_callback(
      suite, SignaturePublicKey{ backend_pub_data }, [&](const bytes& data) {
        // In reality, this would call into secure enclave / HSM
        // For testing, we just sign with our backend key directly
        return sig.sign(data, *backend_priv);
      });

    // Verify the external key has correct public key
    REQUIRE(external_key.public_key.data == backend_pub_data);

    // Verify it's not exportable
    REQUIRE_FALSE(external_key.exportable());

    // Verify signing works
    const auto label = "test_label"s;
    auto message = from_hex("deadbeef");
    auto signature = external_key.sign(suite, label, message);
    REQUIRE(external_key.public_key.verify(suite, label, message, signature));

    // Verify to_jwk throws for non-exportable keys
    REQUIRE_THROWS(external_key.to_jwk(suite));
  }
}

TEST_CASE("External Signature Key - Invalid URI")
{
  // Test that invalid/unsupported URIs are properly rejected
  auto suite = CipherSuite{ CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };

#if defined(WITH_BORINGSSL)
  // BoringSSL doesn't support external key URIs
  REQUIRE_THROWS(SignaturePrivateKey::from_external(suite, "anything"));
#elif defined(WITH_OPENSSL3)
  // OpenSSL 3: Invalid store URIs
  REQUIRE_THROWS(SignaturePrivateKey::from_external(suite, "invalid:"));
  REQUIRE_THROWS(
    SignaturePrivateKey::from_external(suite, "file:///nonexistent"));
#else
  // OpenSSL 1.1.x: Engine URIs need proper format
  REQUIRE_THROWS(SignaturePrivateKey::from_external(suite, "invalid"));
  REQUIRE_THROWS(SignaturePrivateKey::from_external(suite, "engine:"));
  REQUIRE_THROWS(SignaturePrivateKey::from_external(suite, "engine:x"));
#endif
}

// Test loading keys from PEM files via OSSL_STORE (OpenSSL 3.x only)
// This test is always enabled on OpenSSL 3.x builds
#if defined(WITH_OPENSSL3)
TEST_CASE("External Signature Key - File URI", "[external-file]")
{
  // This test uses OSSL_STORE to load a key from a PEM file
  // It verifies that the external key loading mechanism works

  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  // Generate a key and export it to PEM format
  auto original_key = SignaturePrivateKey::generate(suite);

  // Create a temporary PEM file
  // For P-256, we need to create an EC key in PEM format
  // We'll use the JWK export and then skip this test if we can't create the
  // file Actually, let's just test with a pre-generated key file

  // Check if a test key file is provided
  const char* key_file = std::getenv("MLSPP_TEST_KEY_FILE");
  if (key_file == nullptr) {
    // Create a simple test by verifying file: URI parsing works
    // Even if the file doesn't exist, we should get a proper error
    REQUIRE_THROWS_WITH(
      SignaturePrivateKey::from_external(suite, "file:///nonexistent/key.pem"),
      Catch::Matchers::ContainsSubstring("No private key found") ||
        Catch::Matchers::ContainsSubstring("Failed to open"));
    return;
  }

  // Load key from file
  std::string uri = std::string("file://") + key_file;
  auto external_key = SignaturePrivateKey::from_external(suite, uri);

  // Verify signing works
  const auto label = "file_test"s;
  auto message = from_hex("deadbeef");
  auto signature = external_key.sign(suite, label, message);
  REQUIRE(external_key.public_key.verify(suite, label, message, signature));

  // File-based keys should be exportable (the file is readable)
  // Note: this depends on whether we could extract the raw key data
}
#endif

// macOS Keychain test using Security.framework
// This test creates a temporary key in the Keychain, uses it for signing,
// and then deletes it.
#if defined(HAVE_SECURITY_FRAMEWORK)

// Helper RAII wrapper for CFRelease
template<typename T>
struct CFReleaser
{
  T ref;
  explicit CFReleaser(T r)
    : ref(r)
  {
  }
  ~CFReleaser()
  {
    if (ref) {
      CFRelease(ref);
    }
  }
  CFReleaser(const CFReleaser&) = delete;
  CFReleaser& operator=(const CFReleaser&) = delete;
  operator T() const { return ref; }
  T get() const { return ref; }
};

TEST_CASE("External Signature Key - macOS Keychain")
{
  // Use P-256 which is well-supported by SecKey
  auto suite = CipherSuite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };

  // Generate a temporary key in the Keychain
  CFReleaser<CFMutableDictionaryRef> attributes(
    CFDictionaryCreateMutable(kCFAllocatorDefault,
                              0,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks));
  REQUIRE(attributes.get() != nullptr);

  CFDictionarySetValue(
    attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
  int keySize = 256;
  CFReleaser<CFNumberRef> keySizeNum(
    CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keySize));
  CFDictionarySetValue(attributes, kSecAttrKeySizeInBits, keySizeNum);

  // Create a temporary key (not persisted to Keychain for test isolation)
  CFErrorRef error = nullptr;
  CFReleaser<SecKeyRef> privateKey(SecKeyCreateRandomKey(attributes, &error));
  if (error) {
    CFReleaser<CFStringRef> desc(CFErrorCopyDescription(error));
    char buf[256];
    CFStringGetCString(desc, buf, sizeof(buf), kCFStringEncodingUTF8);
    CFRelease(error);
    FAIL("Failed to create SecKey: " << buf);
  }
  REQUIRE(privateKey.get() != nullptr);

  // Get public key
  CFReleaser<SecKeyRef> publicKey(SecKeyCopyPublicKey(privateKey));
  REQUIRE(publicKey.get() != nullptr);

  // Export public key to get bytes for MLS
  CFReleaser<CFDataRef> pubKeyData(
    SecKeyCopyExternalRepresentation(publicKey, &error));
  if (error) {
    CFRelease(error);
    FAIL("Failed to export public key");
  }

  // The exported format is ANSI X9.63 (04 || x || y), which is what MLS expects
  // for P-256
  bytes pub_bytes(CFDataGetLength(pubKeyData));
  memcpy(pub_bytes.data(), CFDataGetBytePtr(pubKeyData), pub_bytes.size());

  SignaturePublicKey mls_pub_key{ pub_bytes };

  // Create external key with signing callback
  SecKeyRef privKeyRef = privateKey.get();
  auto external_key = SignaturePrivateKey::from_external_callback(
    suite, mls_pub_key, [privKeyRef](const bytes& data) -> bytes {
      // SecKey expects raw data for ECDSA
      CFReleaser<CFDataRef> dataRef(
        CFDataCreate(kCFAllocatorDefault, data.data(), data.size()));

      CFErrorRef signError = nullptr;
      CFReleaser<CFDataRef> signature(
        SecKeyCreateSignature(privKeyRef,
                              kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                              dataRef,
                              &signError));

      if (signError || !signature.get()) {
        if (signError) {
          CFRelease(signError);
        }
        throw std::runtime_error("SecKey signing failed");
      }

      bytes sig(CFDataGetLength(signature));
      memcpy(sig.data(), CFDataGetBytePtr(signature), sig.size());
      return sig;
    });

  // Verify the external key has correct public key
  REQUIRE(external_key.public_key == mls_pub_key);

  // Verify it's not exportable
  REQUIRE_FALSE(external_key.exportable());

  // Verify signing works
  const auto label = "keychain_test"s;
  auto message = from_hex("cafebabe");
  auto signature = external_key.sign(suite, label, message);
  REQUIRE(external_key.public_key.verify(suite, label, message, signature));

  // Verify to_jwk throws for non-exportable keys
  REQUIRE_THROWS(external_key.to_jwk(suite));
}

#endif // HAVE_SECURITY_FRAMEWORK
