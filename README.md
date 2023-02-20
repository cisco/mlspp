MLS++
=====

Implementation of the proposed [Messaging Layer
Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md)
protocol in C++.  Depends on C++17, STL for data structures, and
OpenSSL for crypto.

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
