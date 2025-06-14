# Description

A dead simple to use C++ wrapper for handling digital certificates using OpenSSL. 

# Dependencies

OpenSSL 0.9.8 or newer, including OpenSSL 1.1.

# How to build

Configure and build everything (library + tests):

```bash
# Configure (will automatically download Catch2)
cmake -B build -S .

# Build library and tests
cmake --build build
```

Run all tests or use CTest to run individual test cases:

```bash
# Run all tests
cmake --build build --target test-run

# Or use CTest to run individual test cases
cd build && ctest --verbose
```

# Acknowledgments

This product includes software developed by the OpenSSL Project
for use in the OpenSSL Toolkit (http://www.openssl.org/)

# License

This software is released under the Modified BSD License.
