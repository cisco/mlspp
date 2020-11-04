MLS++
=====

Implementation of the proposed [Messaging Layer
Security](https://github.com/ekr/mls-protocol/blob/master/draft-barnes-mls-protocol.md)
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

Building, installing, linking etc
----------------------------

The usual "cmake dance" applies:
```
> mkdir build
> cd build
> cmake ..
> make
```

It is possible to install the library 
```
> make install
```

There is no uninstall target, so use:
```
> xargs rm < install_manifest.txt
```
To get rid of most of the files (Some manual directory cleanup might be needed)

Once installed there a pkgconfig file is installed so using this library from another cmake project could be done by:
```
```