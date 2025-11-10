#pragma once
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>
#include <schema/finding.h>
#include <schema/crawl_result.h>

namespace artifacts {

/**
 * @file artifacts.h
 * @brief Generate reproduction scripts and test files from security findings
 * 
 * Takes security findings and turns them into executable scripts (shell and
 * Catch2 tests) that can reproduce the issues. Also generates manifests with
 * SHA-256 hashes for integrity checking.
 */

/**
 * Generates reproduction artifacts for security findings
 * @artifacts.h (14-86)
 */
class ArtifactGenerator {
public:
    /**
     * Generate a shell script with functions to reproduce each finding
     * @artifacts.h (22-25)
     * @param findings List of security findings to generate repros for
     * @param output_path Where to write the repro.sh file
     * @return true if written successfully
     */
    static bool generate_repro_script(
        const std::vector<Finding>& findings,
        const std::string& output_path
    );
    
    /**
     * Generate a Catch2 test file with test cases for each finding
     * @artifacts.h (34-38)
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
     * Generate a manifest JSON file with SHA-256 hashes of all artifacts
     * @artifacts.h (46-49)
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
     * Build a curl command that reproduces a finding
     * @artifacts.h (57)
     * @param finding The finding to reproduce
     * @return curl command string
     */
    static std::string generate_curl_command(const Finding& finding);
    
    /**
     * Generate Catch2 test case source code for a finding
     * @artifacts.h (64)
     * @param finding The finding to test
     * @return Test case C++ source code
     */
    static std::string generate_test_case(const Finding& finding);
    
    /**
     * Compute SHA-256 hash of a file
     * @artifacts.h (71)
     * @param file_path Path to the file
     * @return Hex-encoded hash, or empty string on error
     */
    static std::string hash_file(const std::string& file_path);
    
    /**
     * Escape a string so it's safe to use in a shell command
     * @artifacts.h (78)
     * @param s String to escape
     * @return Shell-safe string
     */
    static std::string shell_escape(const std::string& s);
    
    /**
     * Escape a string so it's safe to use in a C++ string literal
     * @artifacts.h (85)
     * @param s String to escape
     * @return C++-safe string
     */
    static std::string cpp_escape(const std::string& s);
};

} // namespace artifacts
