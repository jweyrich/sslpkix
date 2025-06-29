#define CATCH_CONFIG_RUNNER
#include <catch2/catch_session.hpp>
#include <iostream>
#include "sslpkix/sslpkix.h"

struct TestRunnerSetup {
    TestRunnerSetup() {
        sslpkix::initialize();
        sslpkix::seed_prng();
    }

    ~TestRunnerSetup() = default;
};

int main(int argc, char* argv[]) {
    TestRunnerSetup setup;
    Catch::Session session;
    return session.run(argc, argv);
}