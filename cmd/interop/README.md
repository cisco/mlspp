MLSpp interop harness
=====================

This directory builds a binary that wraps MLSpp with tooling to verify interop
with other stacks.  It has two main modes, a test-vector verification mode to
test basic protocol functions and a live testing mode for testing dynamic
protocol interactions.

```
> make
> ./build/mlspp_client -gen <type>  # Generate test vectors of a specified type (to stdout)
> ./build/mlspp_client -ver <type>  # Verify test vectors of a specified type (from stdin)
> ./build/mlspp_client -live <port> # Run a gRPC server for live testing
```

The test vector formats and the gRPC interface are specified in the [MLS interop
testing repo](https://github.com/mlswg/mls-implementations).
