cmake_minimum_required(VERSION 3.14)
project(sentinel VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find required packages
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)

# Gumbo parser (may need manual path on some systems)
find_library(GUMBO_LIBRARY gumbo)
find_path(GUMBO_INCLUDE_DIR gumbo.h)

if(NOT GUMBO_LIBRARY)
    message(FATAL_ERROR "Gumbo library not found")
endif()

# Core library: HTTP client and crawler (Person A)
add_library(sentinel_core
    src/core/http_client.cpp
    src/core/crawler.cpp
)

target_include_directories(sentinel_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${GUMBO_INCLUDE_DIR}
)

target_link_libraries(sentinel_core PUBLIC
    CURL::libcurl
    ${GUMBO_LIBRARY}
    nlohmann_json::nlohmann_json
)

# Logging library: Hash-chained JSONL logger (Person B)
add_library(sentinel_logging
    src/logging/chain.cpp
)

target_include_directories(sentinel_logging PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(sentinel_logging PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Artifacts library: Repro script and test generators (Person B)
add_library(sentinel_artifacts
    src/artifacts/artifacts.cpp
)

target_include_directories(sentinel_artifacts PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(sentinel_artifacts PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Budget library: Risk policy and evaluation (Person B)
add_library(sentinel_budget
    src/budget/policy.cpp
)

target_include_directories(sentinel_budget PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(sentinel_budget PUBLIC
    nlohmann_json::nlohmann_json
)

# Main executable
add_executable(sentinel
    src/main.cpp
)

target_link_libraries(sentinel PRIVATE
    sentinel_core
    sentinel_logging
    sentinel_artifacts
    sentinel_budget
)

# Testing with Catch2 (optional)
option(BUILD_TESTS "Build test suite" ON)

if(BUILD_TESTS)
    find_package(Catch2 QUIET)
    
    if(Catch2_FOUND)
        enable_testing()
        
        add_executable(sentinel_tests
            tests/test_chain.cpp
            tests/test_artifacts.cpp
            tests/test_budget.cpp
        )
        
        target_link_libraries(sentinel_tests PRIVATE
            sentinel_logging
            sentinel_artifacts
            sentinel_budget
            Catch2::Catch2
        )
        
        include(CTest)
        include(Catch)
        catch_discover_tests(sentinel_tests)
    else()
        message(STATUS "Catch2 not found, skipping tests")
    endif()
endif()

# Installation
install(TARGETS sentinel DESTINATION bin)
install(FILES 
    ci-policy.yml
    DESTINATION share/sentinel
)