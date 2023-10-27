[![MLSPP CI](https://github.com/cisco/mlspp/actions/workflows/main_ci.yml/badge.svg)](https://github.com/cisco/mlspp/actions/workflows/main_ci.yml)

MLS++
=====

Implementation of the proposed [Messaging Layer
Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md)
protocol in C++.  Depends on C++17, STL for data structures, and
OpenSSL or BoringSSL for crypto.

Quickstart
----------

A convenience Makefile is included to avoid the need to remember a bunch of
CMake parameters.

```
> make        # Configures and builds the library 
> make dev    # Configure a "developer" build with tests and checks
> make test   # Builds and runs tests
> make format # Runs clang-format over the source
```

Conventions
-----------

* Following Mozilla `clang-format` style.  If you use the top-level
  Makefile (as suggested above), it will auto-format for you.
* General naming conventions:
  * Camel case for classes (`RatchetNode`)
  * Snake case for variables, functions, members (`derive_epoch_keys`)
  * Private member variables start with underscore (`_`)
  * In general, prefer descriptive names

OpenSSL / BoringSSL
-------------------

MLS++ requires OpenSSL of at least version 1.1.1, or BoringSSL compatible with the same requirement. MLS++ is compatible with OpenSSL >= 3.0. 

Pass `OPENSSL_ROOT_DIR` to guide CMake to select a specific OpenSSL/BoringSSL installation. You may also need to specify `OPENSSL_INCLUDE_DIR`, `OPENSSL_CRYPTO_LIBRARY`, and `OPENSSL_SSL_LIBRARY` depending on the file and folder structure of your installation. When manually passing `OPENSSL_*` options one should carefully verify that both the includes and libraries match the expected installation.
  
