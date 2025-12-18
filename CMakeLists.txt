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
    src/core/session_manager.cpp
    src/core/response_analyzer.cpp
    src/core/timing_analyzer.cpp
    src/core/baseline_comparator.cpp
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
# Test helpers library
add_library(test_helpers
    tests/helpers/http_test_helpers.cpp
)
target_include_directories(test_helpers PUBLIC
    ${CMAKE_SOURCE_DIR}/tests
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_helpers PUBLIC core)

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

# Session manager tests
add_executable(test_session_manager tests/test_session_manager.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_session_manager PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_session_manager PRIVATE core)
if(TARGET test_session_manager)
    add_test(NAME test_session_manager COMMAND test_session_manager)
    set_tests_properties(test_session_manager PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_session_manager PROPERTIES LABELS "session;auth")
endif()

# Response analyzer tests
add_executable(test_response_analyzer tests/test_response_analyzer.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_response_analyzer PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_response_analyzer PRIVATE core)
if(TARGET test_response_analyzer)
    add_test(NAME test_response_analyzer COMMAND test_response_analyzer)
    set_tests_properties(test_response_analyzer PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_response_analyzer PROPERTIES LABELS "response;pattern;analysis")
endif()

# Timing analyzer tests
add_executable(test_timing_analyzer tests/test_timing_analyzer.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_timing_analyzer PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_timing_analyzer PRIVATE core)
if(TARGET test_timing_analyzer)
    add_test(NAME test_timing_analyzer COMMAND test_timing_analyzer)
    set_tests_properties(test_timing_analyzer PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_timing_analyzer PROPERTIES LABELS "timing;blind;injection")
endif()

# Baseline comparator tests
add_executable(test_baseline_comparator tests/test_baseline_comparator.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_baseline_comparator PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_baseline_comparator PRIVATE core)
if(TARGET test_baseline_comparator)
    add_test(NAME test_baseline_comparator COMMAND test_baseline_comparator)
    set_tests_properties(test_baseline_comparator PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_baseline_comparator PROPERTIES LABELS "baseline;comparison;behavioral")
endif()

# Information disclosure tests
add_executable(test_information_disclosure tests/test_information_disclosure.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_information_disclosure PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_information_disclosure PRIVATE core)
if(TARGET test_information_disclosure)
    add_test(NAME test_information_disclosure COMMAND test_information_disclosure)
    set_tests_properties(test_information_disclosure PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_information_disclosure PROPERTIES LABELS "information;disclosure;security")
endif()

# Open redirect tests
add_executable(test_open_redirect tests/test_open_redirect.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_open_redirect PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_open_redirect PRIVATE core)
if(TARGET test_open_redirect)
    add_test(NAME test_open_redirect COMMAND test_open_redirect)
    set_tests_properties(test_open_redirect PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_open_redirect PROPERTIES LABELS "open;redirect;phishing")
endif()

# Directory listing tests
add_executable(test_directory_listing tests/test_directory_listing.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_directory_listing PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_directory_listing PRIVATE core)
if(TARGET test_directory_listing)
    add_test(NAME test_directory_listing COMMAND test_directory_listing)
    set_tests_properties(test_directory_listing PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_directory_listing PROPERTIES LABELS "directory;listing;information_disclosure")
endif()

# HTTP method vulnerability tests
add_executable(test_http_method_vulnerabilities tests/test_http_method_vulnerabilities.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_http_method_vulnerabilities PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_http_method_vulnerabilities PRIVATE core)
if(TARGET test_http_method_vulnerabilities)
    add_test(NAME test_http_method_vulnerabilities COMMAND test_http_method_vulnerabilities)
    set_tests_properties(test_http_method_vulnerabilities PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_http_method_vulnerabilities PROPERTIES LABELS "http;method;vulnerability")
endif()

# SQL injection tests
add_executable(test_sql_injection tests/test_sql_injection.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_sql_injection PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_sql_injection PRIVATE core)
if(TARGET test_sql_injection)
    add_test(NAME test_sql_injection COMMAND test_sql_injection)
    set_tests_properties(test_sql_injection PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_sql_injection PROPERTIES LABELS "sql;injection;vulnerability")
endif()

# Command injection tests
add_executable(test_command_injection tests/test_command_injection.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_command_injection PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_command_injection PRIVATE core)
if(TARGET test_command_injection)
    add_test(NAME test_command_injection COMMAND test_command_injection)
    set_tests_properties(test_command_injection PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_command_injection PROPERTIES LABELS "command;injection;vulnerability")
endif()

# Path traversal tests
add_executable(test_path_traversal tests/test_path_traversal.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_path_traversal PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_path_traversal PRIVATE core)
if(TARGET test_path_traversal)
    add_test(NAME test_path_traversal COMMAND test_path_traversal)
    set_tests_properties(test_path_traversal PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_path_traversal PROPERTIES LABELS "path;traversal;vulnerability")
endif()

# SSRF tests
add_executable(test_ssrf tests/test_ssrf.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_ssrf PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_ssrf PRIVATE core)
if(TARGET test_ssrf)
    add_test(NAME test_ssrf COMMAND test_ssrf)
    set_tests_properties(test_ssrf PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_ssrf PROPERTIES LABELS "ssrf;server_side_request_forgery;vulnerability")
endif()

# XXE tests
add_executable(test_xxe tests/test_xxe.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_xxe PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_xxe PRIVATE core)
if(TARGET test_xxe)
    add_test(NAME test_xxe COMMAND test_xxe)
    set_tests_properties(test_xxe PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_xxe PROPERTIES LABELS "xxe;xml_external_entity;vulnerability")
endif()

# SSTI tests
add_executable(test_ssti tests/test_ssti.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_ssti PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_ssti PRIVATE core)
if(TARGET test_ssti)
    add_test(NAME test_ssti COMMAND test_ssti)
    set_tests_properties(test_ssti PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_ssti PROPERTIES LABELS "ssti;server_side_template_injection;vulnerability")
endif()

# Sensitive data exposure tests
add_executable(test_sensitive_data_exposure tests/test_sensitive_data_exposure.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_sensitive_data_exposure PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_sensitive_data_exposure PRIVATE core)
if(TARGET test_sensitive_data_exposure)
    add_test(NAME test_sensitive_data_exposure COMMAND test_sensitive_data_exposure)
    set_tests_properties(test_sensitive_data_exposure PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_sensitive_data_exposure PROPERTIES LABELS "sensitive_data;data_exposure;vulnerability")
endif()

# Enhanced IDOR tests
add_executable(test_idor tests/test_idor.cpp third_party/catch2/catch_amalgamated.cpp)
set_source_files_properties(third_party/catch2/catch_amalgamated.cpp PROPERTIES COMPILE_DEFINITIONS "CATCH_CONFIG_MAIN")
target_include_directories(test_idor PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/catch2
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(test_idor PRIVATE core)
if(TARGET test_idor)
    add_test(NAME test_idor COMMAND test_idor)
    set_tests_properties(test_idor PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(test_idor PROPERTIES LABELS "idor;insecure_direct_object_reference;vulnerability")
endif()

# Ensure top-level CTest file generation
file(WRITE ${CMAKE_BINARY_DIR}/CTestCustom.cmake "## sentinel custom\n")
