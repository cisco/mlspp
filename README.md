MLS++
=====

Implementation of the proposed [Messaging Layer
Security](https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md)
protocol in C++.  Depends on C++17, STL for data structures, and
OpenSSL for crypto.


Quickstart
----------

Using the convenient Makefile that wraps CMake:

```
> make
> make test
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
* For cryptographic keys in particular:
  * `X_key` is the public key of an asymmetric key pair
  * `X_priv` is the private key of an asymmetric key pair
  * `X_secret` is a symmetric secret

