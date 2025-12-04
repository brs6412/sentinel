cmake_minimum_required(VERSION 3.18)
project(Sentinel LANGUAGES CXX)

include(CTest)
enable_testing()

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
    src/core/vuln_engine.cpp
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
)
target_include_directories(artifacts PUBLIC 
    src/artifacts
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(artifacts PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    schema
    logging
)

add_library(budget
    src/budget/policy.cpp
)
target_include_directories(budget PUBLIC src/budget)
target_link_libraries(budget PUBLIC nlohmann_json::nlohmann_json)

add_library(llm INTERFACE)
target_include_directories(llm INTERFACE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)
target_include_directories(llm SYSTEM INTERFACE
    ${CMAKE_SOURCE_DIR}/third_party
)
target_link_libraries(llm INTERFACE nlohmann_json::nlohmann_json)

# -------------------- Executables ---------------------
add_executable(sentinel src/main.cpp)
target_link_libraries(sentinel PRIVATE core logging artifacts budget)

# LLM demo / tools
add_executable(sentinel-llm src/sentinel_llm.cpp)
target_link_libraries(sentinel-llm PRIVATE core logging artifacts budget llm)

# Reporter stub (adjust path if your file lives under src/)
add_executable(reporter_stub src/reporter_stub.cpp)
target_link_libraries(reporter_stub PRIVATE nlohmann_json::nlohmann_json)

add_executable(sentinel-validate tools/sentinel_validate.cpp)
target_link_libraries(sentinel-validate PRIVATE nlohmann_json::nlohmann_json)

# -------------------- Apps ----------------------------
# Demo server app (expects apps/demo_server/CMakeLists.txt)
add_subdirectory(apps/demo_server)
add_subdirectory(apps/llm)

# -------------------- Tests ---------------------------
# LLM test main (Catch2)
add_library(catch_llm_main OBJECT tests/catch_main_llm.cpp)
target_include_directories(catch_llm_main PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/third_party
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_compile_features(catch_llm_main PRIVATE cxx_std_20)
target_compile_options(catch_llm_main PRIVATE -Wno-unused-parameter -Wno-error=unused-parameter)

# LLM test executables
add_executable(test_ollama_client tests/test_ollama_client.cpp $<TARGET_OBJECTS:catch_llm_main> third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_ollama_client PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/third_party
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_compile_features(test_ollama_client PRIVATE cxx_std_20)
target_compile_options(test_ollama_client PRIVATE -Wno-unused-parameter -Wno-error=unused-parameter)
if(nlohmann_json_FOUND)
    target_link_libraries(test_ollama_client PRIVATE nlohmann_json::nlohmann_json)
endif()
target_link_libraries(test_ollama_client PRIVATE llm)
if(TARGET test_ollama_client)
    add_test(NAME test_ollama_client COMMAND test_ollama_client)
    set_tests_properties(test_ollama_client PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_ollama_client PROPERTIES LABELS "llm;ollama")
endif()

add_executable(test_poe_renderer tests/test_poe_renderer.cpp $<TARGET_OBJECTS:catch_llm_main> third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_poe_renderer PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/third_party
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_compile_features(test_poe_renderer PRIVATE cxx_std_20)
target_compile_options(test_poe_renderer PRIVATE -Wno-unused-parameter -Wno-error=unused-parameter)
if(nlohmann_json_FOUND)
    target_link_libraries(test_poe_renderer PRIVATE nlohmann_json::nlohmann_json)
endif()
target_link_libraries(test_poe_renderer PRIVATE llm)
if(TARGET test_poe_renderer)
    add_test(NAME test_poe_renderer COMMAND test_poe_renderer)
    set_tests_properties(test_poe_renderer PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_poe_renderer PROPERTIES LABELS "llm;poe")
endif()

# Auto-generated security regression tests
if(EXISTS ${CMAKE_SOURCE_DIR}/artifacts/latest_security_tests.cpp)
    add_executable(test_security_findings artifacts/latest_security_tests.cpp)
    target_include_directories(test_security_findings PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/catch2
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}
    )
    target_link_libraries(test_security_findings PRIVATE
        core
        nlohmann_json::nlohmann_json
        CURL::libcurl
    )
    add_test(NAME test_security_findings COMMAND test_security_findings)
    set_tests_properties(test_security_findings PROPERTIES
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        LABELS "security;regression"
    )
endif()

# Ensure top-level CTest file generation
file(WRITE ${CMAKE_BINARY_DIR}/CTestCustom.cmake "## sentinel custom\n")
