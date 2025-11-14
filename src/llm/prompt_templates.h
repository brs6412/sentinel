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
 * @brief Build a prompt asking the LLM to generate structured PoE JSON
 * @param finding_json Security finding JSON object
 * @return Formatted prompt instruction string for generating PoE JSON
 */
inline std::string BuildStructuredPoEPrompt(const nlohmann::json& finding_json) {
    std::ostringstream prompt;

    prompt << "You are Sentinel PoE. Read the field 'finding' (JSON). "
           << "Output ONLY a single JSON object with exactly these keys: "
           << "summary, why, fix, test, tags: { cwe, owasp }. "
           << "No markdown, no prose outside JSON, no code fences.\n\n"
           << "The 'test' field MUST be either:\n"
           << "- A short checklist of concrete steps to verify the fix "
           << "(for example, bullet-like text starting with '-' or '1.'), OR\n"
           << "- A tiny, copy/pasteable code snippet, such as a curl command "
           << "or a minimal unit test skeleton.\n"
           << "Make it specific to this vulnerability. Avoid vague statements "
           << "like 'verify it works' – show exactly what to run or check.\n"
           << "If emitting code, use something simple like curl or Python/pytest-style function.\n"
           << "Checklist format is fine (e.g., '- send request without header; "
           << "- send request with header; compare results').\n"
           << "The test field may contain newlines for multiple checklist lines or code.\n\n"
           << "Expected JSON structure:\n"
           << "{\n"
           << "  \"summary\": \"...\",\n"
           << "  \"why\": \"...\",\n"
           << "  \"fix\": \"...\",\n"
           << "  \"test\": \"...\",\n"
           << "  \"tags\": {\n"
           << "    \"cwe\": \"...\",\n"
           << "    \"owasp\": \"...\"\n"
           << "  }\n"
           << "}\n\n"
           << "Finding:\n"
           << finding_json.dump(2);

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

