#pragma once

#include <string>
#include <sstream>
#include <nlohmann/json.hpp>

namespace llm {

// Helper functions to build prompts for LLM interactions.
// These functions format security findings and other inputs into prompts
// that work well with LLMs for generating proof-of-exploit scripts and
// safety scores.

/**
 * @brief Build a prompt asking the LLM to generate a proof-of-exploit script
 * @param finding_json Security finding with category, URL, method, evidence, etc.
 * @return Formatted prompt string
 */
inline std::string BuildPoEPrompt(const nlohmann::json& finding_json) {
    std::ostringstream prompt;

    prompt << "Generate a concise proof-of-exploit (PoE) script for this security finding:\n\n";

    if (finding_json.contains("category") && finding_json["category"].is_string()) {
        prompt << "Category: " << finding_json["category"].get<std::string>() << "\n";
    }

    if (finding_json.contains("url") && finding_json["url"].is_string()) {
        prompt << "URL: " << finding_json["url"].get<std::string>() << "\n";
    }

    if (finding_json.contains("method") && finding_json["method"].is_string()) {
        prompt << "Method: " << finding_json["method"].get<std::string>() << "\n";
    }

    if (finding_json.contains("evidence") && finding_json["evidence"].is_object()) {
        prompt << "Evidence: " << finding_json["evidence"].dump(2) << "\n";
    }

    prompt << "\nProvide a single curl command or minimal script that reproduces this finding. "
           << "Be concise and deterministic.";

    return prompt.str();
}

/**
 * @brief Build a prompt asking the LLM to rate input safety on a 0-100 scale
 * @param input_snippet Text to evaluate for safety/risk
 * @return Formatted prompt string
 */
inline std::string BuildSafetyScorePrompt(const std::string& input_snippet) {
    std::ostringstream prompt;

    prompt << "Rate the safety/risk level of this input on a scale of 0-100 "
           << "(0=safe, 100=high risk). Respond with only a number.\n\n";
    prompt << "Input:\n" << input_snippet << "\n\nScore:";

    return prompt.str();
}

}  // namespace llm

