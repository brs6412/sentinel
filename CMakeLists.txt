cmake_minimum_required(VERSION 3.18)
project(Sentinel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -------------------- Dependencies --------------------
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)

# Gumbo parser
find_library(GUMBO_LIBRARY gumbo)
find_path(GUMBO_INCLUDE_DIR gumbo.h)
if(NOT GUMBO_LIBRARY OR NOT GUMBO_INCLUDE_DIR)
    message(FATAL_ERROR "Gumbo library not found")
endif()

# -------------------- Libraries -----------------------
add_library(schema INTERFACE)
target_include_directories(schema INTERFACE ${CMAKE_SOURCE_DIR})

add_library(core
    src/core/http_client.cpp
    src/core/crawler.cpp
)
target_include_directories(core PUBLIC
    $<TARGET_PROPERTY:nlohmann_json::nlohmann_json,INTERFACE_INCLUDE_DIRECTORIES>
    src/core
    ${GUMBO_INCLUDE_DIR}
)
target_link_libraries(core PUBLIC
    CURL::libcurl
    ${GUMBO_LIBRARY}
    OpenSSL::Crypto
    schema
)

add_library(logging
    src/logging/chain.cpp
)
target_include_directories(logging PUBLIC src/logging)
target_link_libraries(logging PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

add_library(artifacts
    src/artifacts/artifacts.cpp
    src/artifacts/vuln_engine.cpp
)
target_include_directories(artifacts PUBLIC src/artifacts)
target_link_libraries(artifacts PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    schema
)

add_library(budget
    src/budget/policy.cpp
)
target_include_directories(budget PUBLIC src/budget)
target_link_libraries(budget PUBLIC nlohmann_json::nlohmann_json)

# -------------------- Executables ---------------------
add_executable(sentinel src/main.cpp)
target_link_libraries(sentinel PRIVATE core logging artifacts budget)

# LLM demo / tools
add_executable(sentinel-llm src/sentinel_llm.cpp)
target_link_libraries(sentinel-llm PRIVATE core logging artifacts budget)

# Reporter stub (adjust path if your file lives under src/)
add_executable(reporter_stub src/reporter_stub.cpp)
target_link_libraries(reporter_stub PRIVATE nlohmann_json::nlohmann_json)

add_executable(sentinel-validate tools/sentinel_validate.cpp)
target_link_libraries(sentinel-validate PRIVATE nlohmann_json::nlohmann_json)

# -------------------- Apps ----------------------------
# Demo server app (expects apps/demo_server/CMakeLists.txt)
add_subdirectory(apps/demo_server)

