cmake_minimum_required(VERSION 3.16)
project(libsslpkix VERSION 1.0.1 LANGUAGES C CXX)

# Platform detection is handled by CMAKE_SYSTEM_NAME automatically

# Standard installation directories
include(GNUInstallDirs)

# Find OpenSSL
if(APPLE)
    # On macOS, try to find OpenSSL from Homebrew first
    execute_process(
        COMMAND brew --prefix openssl@3
        OUTPUT_VARIABLE OPENSSL_ROOT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(OPENSSL_ROOT_DIR)
        set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR})
    endif()
elseif(WIN32 AND MINGW)
    # For MinGW, try common OpenSSL installation paths
    set(OPENSSL_ROOT_DIR "C:/msys64/mingw64" "C:/mingw64" "C:/OpenSSL-Win64")
    # Set additional hints for MinGW
    set(OPENSSL_USE_STATIC_LIBS FALSE)
endif()

find_package(OpenSSL REQUIRED)

# Fetch Catch2 for testing
include(FetchContent)
if(TEST_SOURCES OR EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.4.0  # Use a stable version
        GIT_SHALLOW    TRUE
    )

    FetchContent_MakeAvailable(Catch2)

    # Add Catch2's cmake modules to the path
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
endif()

# Project configuration
set(LIBNAME "sslpkix")
set(TESTNAME "run_tests")

# Build directories
set(BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})

# Source directories
set(SOURCE_DIRS
    src
    src/openssl/apps
    src/x509
)

set(TEST_DIR test)

# Collect source files
set(LIBRARY_SOURCES)
foreach(dir ${SOURCE_DIRS})
    file(GLOB_RECURSE dir_sources "${dir}/*.c" "${dir}/*.cpp")
    list(APPEND LIBRARY_SOURCES ${dir_sources})
endforeach()

# Collect test files
file(GLOB_RECURSE TEST_SOURCES "${TEST_DIR}/*.c" "${TEST_DIR}/*.cpp")

# Compiler flags
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

# Common compile options - compiler-specific
set(COMMON_COMPILE_OPTIONS)

# GCC and Clang compatible options (includes MinGW)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    list(APPEND COMMON_COMPILE_OPTIONS
        -pipe
        -O0
        -g3
        -Wall
        -Wextra
        -pedantic
        -fmessage-length=0
    )
    # MinGW-specific options
    if(MINGW)
        list(APPEND COMMON_COMPILE_OPTIONS
            -static-libgcc
            -static-libstdc++
        )
    endif()
# MSVC specific options
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    list(APPEND COMMON_COMPILE_OPTIONS
        /Od        # Equivalent to -O0 (disable optimization)
        /Zi        # Equivalent to -g3 (debug info)
        /W4        # Equivalent to -Wall -Wextra (high warning level)
        /permissive-  # Similar to -pedantic (strict conformance)
    )
    # MSVC-specific definitions
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
    )
endif()

# Platform-specific compile options
if(APPLE)
    list(APPEND COMMON_COMPILE_OPTIONS -Wno-deprecated-declarations)
elseif(WIN32)
    # Windows-specific definitions for both MSVC and MinGW
    add_compile_definitions(
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    if(MINGW)
        # MinGW-specific definitions
        add_compile_definitions(
            _WIN32_WINNT=0x0601  # Windows 7 and later
            WINVER=0x0601
        )
    endif()
endif()

# Create the shared library
add_library(${LIBNAME} SHARED ${LIBRARY_SOURCES})

# Set library properties
set_target_properties(${LIBNAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON
)

# Platform-specific library naming
if(APPLE)
    set_target_properties(${LIBNAME} PROPERTIES
        MACOSX_RPATH ON
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
    )
elseif(WIN32)
    if(MINGW)
        # MinGW naming convention
        set_target_properties(${LIBNAME} PROPERTIES
            OUTPUT_NAME "${LIBNAME}"
            PREFIX "lib"
            SUFFIX ".dll"
            IMPORT_SUFFIX ".dll.a"
        )
    elseif(CYGWIN)
        set_target_properties(${LIBNAME} PROPERTIES
            OUTPUT_NAME "${LIBNAME}"
            SUFFIX ".dll"
        )
    endif()
endif()

# Include directories
target_include_directories(${LIBNAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${OPENSSL_INCLUDE_DIR}
)

# Compile definitions
target_compile_definitions(${LIBNAME}
    PRIVATE
        SSLPKIX_LIBRARY
        DEBUG
)

# Compile options
target_compile_options(${LIBNAME} PRIVATE ${COMMON_COMPILE_OPTIONS})

# Link libraries
target_link_libraries(${LIBNAME}
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Platform-specific linker flags
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(${LIBNAME} PROPERTIES
        LINK_FLAGS "-Wl,-soname,${LIBNAME}.so.${PROJECT_VERSION_MAJOR}"
    )
elseif(APPLE)
    set_target_properties(${LIBNAME} PROPERTIES
        LINK_FLAGS "-headerpad_max_install_names -flat_namespace"
    )
elseif(WIN32)
    if(MINGW)
        # MinGW-specific linker flags
        set_target_properties(${LIBNAME} PROPERTIES
            LINK_FLAGS "-Wl,--out-implib,${CMAKE_CURRENT_BINARY_DIR}/lib${LIBNAME}.dll.a"
        )
        # Add Windows libraries that might be needed
        target_link_libraries(${LIBNAME} PRIVATE ws2_32 crypt32)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        # MSVC-specific settings for shared library
        set_target_properties(${LIBNAME} PROPERTIES
            WINDOWS_EXPORT_ALL_SYMBOLS ON
        )
    endif()
endif()

# Create test executable (if test sources exist)
if(TEST_SOURCES)
    add_executable(${TESTNAME} ${TEST_SOURCES})

    # Test include directories - using Catch2 target instead of manual paths
    target_include_directories(${TESTNAME}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${OPENSSL_INCLUDE_DIR}
    )

    # Test compile options - compiler-specific
    target_compile_options(${TESTNAME} PRIVATE ${COMMON_COMPILE_OPTIONS})

    # Add -rdynamic only for GCC/Clang on Unix-like systems
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT WIN32)
        target_compile_options(${TESTNAME} PRIVATE -rdynamic)
        target_link_libraries(${TESTNAME} PRIVATE ${CMAKE_DL_LIBS})
    endif()

    # Test compile definitions
    target_compile_definitions(${TESTNAME} PRIVATE DEBUG)

    # Link test with library and Catch2
    target_link_libraries(${TESTNAME}
        PRIVATE
            ${LIBNAME}
            Catch2::Catch2WithMain  # Catch2 v3 provides main automatically
            OpenSSL::SSL
            OpenSSL::Crypto
    )

    # Add dependency to ensure library is built first
    add_dependencies(${TESTNAME} ${LIBNAME})

    # Set test binary output directory to match original structure
    set_target_properties(${TESTNAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/build
    )

    # On Windows, ensure the DLL is in the same directory as the test executable
    if(WIN32)
        add_custom_command(TARGET ${TESTNAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:${LIBNAME}>
            $<TARGET_FILE_DIR:${TESTNAME}>
            COMMENT "Copying DLL to test directory"
        )
    endif()
endif()

# Installation
install(TARGETS ${LIBNAME}
    EXPORT ${LIBNAME}Targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers (if they exist)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/include)
    install(DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
    )
endif()

# Create and install package config (optional)
include(CMakePackageConfigHelpers)

# Only create package config if template exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/${LIBNAME}Config.cmake.in")
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/${LIBNAME}Config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}Config.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${LIBNAME}
        NO_SET_AND_CHECK_MACRO
        NO_CHECK_REQUIRED_COMPONENTS_MACRO
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}ConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}ConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${LIBNAME}
    )

    install(EXPORT ${LIBNAME}Targets
        FILE ${LIBNAME}Targets.cmake
        NAMESPACE ${LIBNAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${LIBNAME}
    )
else()
    # Create a simple package config file
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}ConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    # Generate a basic config file
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}Config.cmake"
"# ${LIBNAME} package config
include(CMakeFindDependencyMacro)
find_dependency(OpenSSL REQUIRED)

include(\"\${CMAKE_CURRENT_LIST_DIR}/${LIBNAME}Targets.cmake\")
")

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME}ConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${LIBNAME}
    )

    install(EXPORT ${LIBNAME}Targets
        FILE ${LIBNAME}Targets.cmake
        NAMESPACE ${LIBNAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${LIBNAME}
    )
endif()

# Custom targets for compatibility with original Makefile

# Strip target (not available on Windows)
if(NOT WIN32)
    add_custom_target(strip-binaries
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${LIBNAME}>
        DEPENDS ${LIBNAME}
        COMMENT "Stripping debug symbols from library"
    )

    add_custom_target(install-strip
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target strip-binaries
        COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR}
        COMMENT "Installing stripped binaries"
    )
endif()

# Test target
if(TEST_SOURCES)
    enable_testing()

    # Use Catch2's test discovery if available (Catch2 v3)
    if(TARGET Catch2::Catch2WithMain)
        include(Catch)
        catch_discover_tests(${TESTNAME})
    else()
        add_test(NAME ${TESTNAME} COMMAND ${TESTNAME})
    endif()

    # Custom target to run tests (matching original Makefile behavior)
    add_custom_target(test-run
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/build/${TESTNAME}
        DEPENDS ${TESTNAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Running tests with Catch2"
    )

    # Add convenience target that matches the test Makefile
    add_custom_target(build-binary
        DEPENDS ${TESTNAME}
        COMMENT "Building test binary"
    )
endif()

# Print configuration summary
message(STATUS "Configuration Summary:")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID}")
if(MINGW)
    message(STATUS "  MinGW detected: YES")
endif()
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  OpenSSL found: ${OPENSSL_FOUND}")
if(OPENSSL_FOUND)
    message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
    message(STATUS "  OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
endif()
message(STATUS "  Library sources: ${LIBRARY_SOURCES}")
if(TEST_SOURCES)
    message(STATUS "  Test sources found: YES")
    message(STATUS "  Catch2 will be downloaded automatically")
else()
    message(STATUS "  Test sources found: NO")
endif()
