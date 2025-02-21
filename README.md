[![MLSPP CI](https://github.com/cisco/mlspp/actions/workflows/main_ci.yml/badge.svg)](https://github.com/cisco/mlspp/actions/workflows/main_ci.yml)

MLS++
=====

Implementation of the proposed [Messaging Layer Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md) protocol in C++.  Depends on C++17, STL for data structures, and OpenSSL or BoringSSL for crypto.

Prerequisites
-------------

MLSPP requires a few prerequisite libraries in order to fully build.

* [nlohmann::json](https://github.com/nlohmann/json) - Tested with latest versions.
* Cryptography Library - OpenSSL 1.1.1, OpenSSL 3.0, BoringSSL compatible (see details below)
* [Catch2](https://github.com/catchorg/Catch2) - Only required when building the test suite.

### Installing Prerequisites 

The following should satisfy the prerequisites for these popular platforms. However, [vcpkg](https://vcpkg.io/en/) is recommended for developer builds.

```sh
# Linux - Ubuntu 20.04, Ubuntu 22.04
$ sudo apt install libssl-dev nlohmann-json3-dev doctest-dev

# MacOs - Homebrew
$ brew install nlohmann-json doctest
```

Quickstart
----------

A convenience Makefile is included to avoid the need to remember a bunch of CMake parameters. It will use [vcpkg](https://vcpkg.io/en/) to satisfy all dependencies.

Note that on Windows the make commands should be run in PowerShell instead of cmd.exe, otherwise, vcpkg will report the error 'error: in triplet x64-windows: Unable to find a valid Visual Studio instance'.

```
> make        # Configures and builds the library 
> make dev    # Configure a "developer" build with tests and checks using OpenSSL 1.1
> make dev3   # Configure a "developer" build with tests and checks using OpenSSL 3.0
> make devB   # Configure a "developer" build with tests and checks using BoringSSL
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
  
