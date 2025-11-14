/**
 * @file main_llm.cpp
 * @brief Test main for LLM tests using Catch2
 */

#define CATCH_CONFIG_MAIN
#include "third_party/catch2.hpp"

// Include test implementations (Catch2 already included above, so their includes will be no-ops)
#include "test_ollama_client.cpp"
#include "test_poe_renderer.cpp"

