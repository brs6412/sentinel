cmake_minimum_required(VERSION 3.18)

# Sentinel LLM CLI tool
add_executable(sentinel_llm main.cpp)

# Link libraries
target_link_libraries(sentinel_llm PRIVATE
    llm
    nlohmann_json::nlohmann_json
)

# C++20 standard
set_target_properties(sentinel_llm PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/apps/llm
)

# Include directories (mark third_party as SYSTEM)
target_include_directories(sentinel_llm PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    SYSTEM ${CMAKE_SOURCE_DIR}/third_party
)

# Compiler warnings (silence unused-parameter from third_party)
target_compile_options(sentinel_llm PRIVATE
    -Wno-unused-parameter
    -Wno-error=unused-parameter
)

