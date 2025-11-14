#pragma once
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>
#include <schema/finding.h>
#include <schema/crawl_result.h>

namespace artifacts {

// Generate reproduction scripts and test files from security findings.
// Takes security findings and turns them into executable scripts (shell and
// Catch2 tests) that can reproduce the issues. Also generates manifests with
// SHA-256 hashes for integrity checking.

class ArtifactGenerator {
public:
    /**
     * @brief Generate a shell script with functions to reproduce each finding
     * @param findings List of security findings to generate repros for
     * @param output_path Where to write the repro.sh file
     * @return true if written successfully
     */
    static bool generate_repro_script(
        const std::vector<Finding>& findings,
        const std::string& output_path
    );
    
    /**
     * @brief Generate a Catch2 test file with test cases for each finding
     * @param findings List of security findings to generate tests for
     * @param run_id Unique identifier for this scan run
     * @param output_path Where to write the test file
     * @return true if written successfully
     */
    static bool generate_catch2_tests(
        const std::vector<Finding>& findings,
        const std::string& run_id,
        const std::string& output_path
    );
    
    /**
     * @brief Generate a manifest JSON file with SHA-256 hashes of all artifacts
     * @param artifact_dir Directory containing the artifacts to hash
     * @param output_path Where to write manifest.json
     * @return true if written successfully
     */
    static bool generate_manifest(
        const std::string& artifact_dir,
        const std::string& output_path
    );

private:
    /**
     * @brief Build a curl command that reproduces a finding
     * @param finding The finding to reproduce
     * @return curl command string
     */
    static std::string generate_curl_command(const Finding& finding);
    
    /**
     * @brief Generate Catch2 test case source code for a finding
     * @param finding The finding to test
     * @return Test case C++ source code
     */
    static std::string generate_test_case(const Finding& finding);
    
    /**
     * @brief Compute SHA-256 hash of a file
     * @param file_path Path to the file
     * @return Hex-encoded hash, or empty string on error
     */
    static std::string hash_file(const std::string& file_path);
    
    /**
     * @brief Escape a string so it's safe to use in a shell command
     * @param s String to escape
     * @return Shell-safe string
     */
    static std::string shell_escape(const std::string& s);
    
    /**
     * @brief Escape a string so it's safe to use in a C++ string literal
     * @param s String to escape
     * @return C++-safe string
     */
    static std::string cpp_escape(const std::string& s);
};

} // namespace artifacts
