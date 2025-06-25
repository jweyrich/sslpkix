#define CATCH_CONFIG_RUNNER
#include <catch2/catch_session.hpp>
#include <iostream>
#include "sslpkix/sslpkix.h"

struct TestRunnerSetup {
    TestRunnerSetup() {
        bool success = sslpkix::startup();
        if (!success) {
            std::cerr << "ERROR: Failed to initialize SSLPKIX" << std::endl;
            exit(EXIT_FAILURE);
        }

        success = sslpkix::seed_prng();
        if (!success) {
            std::cerr << "ERROR: Failed to seed the PRNG" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    ~TestRunnerSetup() {
        sslpkix::shutdown();
    }
};

int main(int argc, char* argv[]) {
    TestRunnerSetup setup;
    Catch::Session session;
    return session.run(argc, argv);
}