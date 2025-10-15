#pragma once
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

namespace artifacts {

/**
 * @brief Represents a finding that needs reproduction artifacts
 */
struct Finding {
    std::string id;
    std::string url;
    std::string category;
    std::string method;
    std::map<std::string, std::string> headers;
    std::string body;
    nlohmann::json evidence;
    std::string severity;
    double confidence;
    std::string remediation_id;
};

/**
 * @brief Generates reproduction artifacts for findings
 */
class ArtifactGenerator {
public:
    /**
     * @brief Generate a POSIX shell script with repro functions
     * @param findings Vector of findings to generate repros for
     * @param output_path Path to write repro.sh
     * @return true if successful
     */
    static bool generate_repro_script(
        const std::vector<Finding>& findings,
        const std::string& output_path
    );
    
    /**
     * @brief Generate Catch2 test file for findings
     * @param findings Vector of findings to generate tests for
     * @param run_id Unique run identifier
     * @param output_path Path to write test file
     * @return true if successful
     */
    static bool generate_catch2_tests(
        const std::vector<Finding>& findings,
        const std::string& run_id,
        const std::string& output_path
    );
    
    /**
     * @brief Generate assets manifest with SHA-256 hashes
     * @param artifact_dir Directory containing artifacts
     * @param output_path Path to write manifest.json
     * @return true if successful
     */
    static bool generate_manifest(
        const std::string& artifact_dir,
        const std::string& output_path
    );

private:
    /**
     * @brief Generate curl command for a finding
     * @param finding The finding to reproduce
     * @return curl command string
     */
    static std::string generate_curl_command(const Finding& finding);
    
    /**
     * @brief Generate Catch2 test case for a finding
     * @param finding The finding to test
     * @return Test case source code
     */
    static std::string generate_test_case(const Finding& finding);
    
    /**
     * @brief Compute SHA-256 hash of a file
     * @param file_path Path to file
     * @return Hex-encoded hash or empty on error
     */
    static std::string hash_file(const std::string& file_path);
    
    /**
     * @brief Escape string for shell
     * @param s Input string
     * @return Shell-escaped string
     */
    static std::string shell_escape(const std::string& s);
    
    /**
     * @brief Escape string for C++ string literal
     * @param s Input string
     * @return C++-escaped string
     */
    static std::string cpp_escape(const std::string& s);
};

} // namespace artifacts