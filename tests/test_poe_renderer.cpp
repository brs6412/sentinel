/**
 * @file test_poe_renderer.cpp
 * @brief Unit tests for RenderPoE function
 * 
 * Tests the ability to extract proof-of-exploit commands from various LLM
 * response formats, including nested JSON, plain strings, and edge cases.
 */

#include "catch2/catch_amalgamated.hpp"
#include "llm/poe_renderer.h"
#include <nlohmann/json.hpp>

/**
 * Test extracting reproducer from a simple JSON object
 * @test_poe_renderer.cpp (17-23)
 */
TEST_CASE("RenderPoE extracts reproducer from JSON object", "[llm]") {
    nlohmann::json input;
    input["reproducer"] = "curl -X GET 'https://example.com/test' -v";
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result == "curl -X GET 'https://example.com/test' -v");
}

/**
 * Test extracting reproducer from nested JSON in response field
 * @test_poe_renderer.cpp (29-36)
 */
TEST_CASE("RenderPoE extracts reproducer from nested response", "[llm]") {
    nlohmann::json input;
    input["response"] = R"({"reproducer":"curl -X POST 'https://api.example.com/data' -d 'test'"})";
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.find("curl") != std::string::npos);
    REQUIRE(result.find("reproducer") == std::string::npos); // Should extract just the curl command
}

/**
 * Test that plain text input is returned as-is
 * @test_poe_renderer.cpp (42-47)
 */
TEST_CASE("RenderPoE returns fallback for plain text input", "[llm]") {
    nlohmann::json input = "This is plain text, not JSON";
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result == "This is plain text, not JSON");
}

/**
 * Test that missing reproducer field triggers fallback template
 * @test_poe_renderer.cpp (53-60)
 */
TEST_CASE("RenderPoE returns fallback when reproducer field missing", "[llm]") {
    nlohmann::json input;
    input["other_field"] = "some value";
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.find("Fallback PoE") != std::string::npos);
    REQUIRE(result.find("curl") != std::string::npos);
}

/**
 * Test parsing JSON when input is a JSON string
 * @test_poe_renderer.cpp (66-71)
 */
TEST_CASE("RenderPoE handles string JSON input", "[llm]") {
    nlohmann::json input = R"({"reproducer":"curl -X GET 'https://test.com' -H 'X-Test: value'"})";
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result == "curl -X GET 'https://test.com' -H 'X-Test: value'");
}

/**
 * Test handling Ollama's standard response format
 * @test_poe_renderer.cpp (77-84)
 */
TEST_CASE("RenderPoE handles Ollama response format", "[llm]") {
    nlohmann::json input;
    input["response"] = "Some text response";
    input["done"] = true;
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result == "Some text response");
}

/**
 * Test extracting reproducer from JSON string nested in response field
 * @test_poe_renderer.cpp (90-98)
 */
TEST_CASE("RenderPoE extracts reproducer from nested JSON string", "[llm]") {
    nlohmann::json input;
    std::string nested_json = R"({"reproducer":"curl -X DELETE 'https://api.example.com/resource/123'"})";
    input["response"] = nested_json;
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.find("curl") != std::string::npos);
    REQUIRE(result.find("DELETE") != std::string::npos);
}

/**
 * Test that empty JSON objects trigger fallback
 * @test_poe_renderer.cpp (104-109)
 */
TEST_CASE("RenderPoE handles empty JSON object", "[llm]") {
    nlohmann::json input = nlohmann::json::object();
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.find("Fallback PoE") != std::string::npos);
}

/**
 * Test that null reproducer values trigger fallback
 * @test_poe_renderer.cpp (115-121)
 */
TEST_CASE("RenderPoE handles null reproducer field", "[llm]") {
    nlohmann::json input;
    input["reproducer"] = nullptr;
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.find("Fallback PoE") != std::string::npos);
}

/**
 * Test that empty string reproducer returns empty result
 * @test_poe_renderer.cpp (127-133)
 */
TEST_CASE("RenderPoE handles empty reproducer string", "[llm]") {
    nlohmann::json input;
    input["reproducer"] = "";
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.empty());
}

/**
 * Test that non-string reproducer values trigger fallback
 * @test_poe_renderer.cpp (139-145)
 */
TEST_CASE("RenderPoE handles reproducer field that is not a string", "[llm]") {
    nlohmann::json input;
    input["reproducer"] = 12345;
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.find("Fallback PoE") != std::string::npos);
}

/**
 * Test that non-string response values trigger fallback
 * @test_poe_renderer.cpp (151-157)
 */
TEST_CASE("RenderPoE handles response field that is not a string", "[llm]") {
    nlohmann::json input;
    input["response"] = 999;
    
    std::string result = llm::RenderPoE(input);
    REQUIRE(result.find("Fallback PoE") != std::string::npos);
}

/**
 * Test that malformed JSON strings are returned as-is
 * @test_poe_renderer.cpp (163-170)
 */
TEST_CASE("RenderPoE handles malformed nested JSON string", "[llm]") {
    nlohmann::json input;
    input["response"] = "{invalid json";
    
    std::string result = llm::RenderPoE(input);
    // Can't parse it, so just return what we got
    REQUIRE(result == "{invalid json");
}

/**
 * Test handling JSON strings that aren't objects
 * @test_poe_renderer.cpp (176-183)
 */
TEST_CASE("RenderPoE handles nested JSON string with non-object", "[llm]") {
    nlohmann::json input;
    input["response"] = R"("just a string")";
    
    std::string result = llm::RenderPoE(input);
    // Response is a JSON string, not an object, so we return it as-is (with quotes)
    REQUIRE(result == R"("just a string")");
}

/**
 * Test that nested JSON without reproducer returns the response string
 * @test_poe_renderer.cpp (189-196)
 */
TEST_CASE("RenderPoE handles nested JSON without reproducer field", "[llm]") {
    nlohmann::json input;
    input["response"] = R"({"other":"value"})";
    
    std::string result = llm::RenderPoE(input);
    // No reproducer found, so return the response string unchanged
    REQUIRE(result == R"({"other":"value"})");
}

