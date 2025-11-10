#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <sstream>

namespace llm {

/**
 * @file poe_renderer.h
 * @brief Extract proof-of-exploit commands from LLM responses
 *
 * LLMs can return proof-of-exploit scripts in various formats. This function
 * tries to extract a curl command or script from the response, with a sensible
 * fallback if the format isn't what we expect.
 */

/**
 * Extract a proof-of-exploit command from an LLM response
 * @poe_renderer.h (14-54)
 * @param llm_result JSON response from the LLM (could be various formats)
 * @return A curl command or script, or a fallback template if nothing found
 */
inline std::string RenderPoE(const nlohmann::json& llm_result) {
    // If llm_result is a string, try to parse it as JSON
    nlohmann::json parsed;
    if (llm_result.is_string()) {
        try {
            parsed = nlohmann::json::parse(llm_result.get<std::string>());
        } catch (...) {
            // If parsing fails, treat as plain text
            return llm_result.get<std::string>();
        }
    } else {
        parsed = llm_result;
    }

    // Check for "reproducer" field
    if (parsed.is_object() && parsed.contains("reproducer") && parsed["reproducer"].is_string()) {
        return parsed["reproducer"].get<std::string>();
    }

    // Check for "response" field (Ollama format)
    if (parsed.is_object() && parsed.contains("response") && parsed["response"].is_string()) {
        std::string response = parsed["response"].get<std::string>();
        // Try to parse nested JSON
        try {
            auto nested = nlohmann::json::parse(response);
            if (nested.is_object() && nested.contains("reproducer") && nested["reproducer"].is_string()) {
                return nested["reproducer"].get<std::string>();
            }
        } catch (...) {
            // Not JSON, return as-is
        }
        return response;
    }

    // Fallback: generate minimal curl command
    std::ostringstream fallback;
    fallback << "# Fallback PoE (LLM did not return structured reproducer)\n";
    fallback << "curl -X GET 'https://example.com' -v";

    return fallback.str();
}

}  // namespace llm

