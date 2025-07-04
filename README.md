# Description

A dead simple to use C++ wrapper for handling digital certificates using OpenSSL.

# Dependencies

OpenSSL 3.0.0 or newer.

# How to build

Configure and build everything (library + tests):

```bash
# Configure it (will automatically download Catch2)
cmake -B build -S .
# Alternatively, configure it for debugging
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug

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

# Documentation

API documentation is generated using Doxygen. To generate the documentation:

```bash
# Install Doxygen (if not already installed)
# On macOS: brew install doxygen
# On Ubuntu/Debian: sudo apt-get install doxygen
# On Windows: Download from https://www.doxygen.nl/

# Generate documentation
cmake --build build --target docs
```

The generated documentation will be available in `build/docs/html/index.html`.

# Acknowledgments

This product includes software developed by the OpenSSL Project
for use in the OpenSSL Toolkit (http://www.openssl.org/)

# License

This software is released under the Modified BSD License.
