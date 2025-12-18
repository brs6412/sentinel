#pragma once
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>
#include <schema/finding.h>
#include <schema/crawl_result.h>

namespace artifacts {

/**
 * @brief Generates reproduction scripts and test files from security findings
 * 
 * The ArtifactGenerator takes security findings discovered during a scan and
 * converts them into executable artifacts that can be used to:
 * - Reproduce vulnerabilities manually (shell scripts with curl commands)
 * - Automatically verify fixes (Catch2 test cases)
 * - Verify artifact integrity (SHA-256 hashes in manifests)
 * 
 * This makes it easy to share findings with developers, integrate into CI/CD
 * pipelines, and track whether vulnerabilities have been fixed.
 */
class ArtifactGenerator {
public:
    /**
     * @brief Generates a shell script with functions to reproduce each finding
     * 
     * Creates a bash script (repro.sh) where each finding gets its own function
     * that can be called to reproduce the vulnerability. The script includes curl
     * commands with all necessary headers, cookies, and request bodies. This is
     * useful for manual verification or sharing with developers who need to see
     * the issue firsthand.
     * 
     * @param findings The list of security findings to generate reproduction
     *                 functions for. Each finding becomes a separate function.
     * @param output_path The file path where the shell script should be written.
     *                   Typically something like "out/tests/repro.sh"
     * 
     * @return true if the script was written successfully, false if file I/O
     *         failed (e.g., permission denied, disk full)
     * 
     * @note The generated script is made executable automatically. If that fails,
     *       a warning is printed but the function still returns true.
     */
    static bool generate_repro_script(
        const std::vector<Finding>& findings,
        const std::string& output_path
    );
    
    /**
     * @brief Generates a Catch2 test file with test cases for each finding
     * 
     * Creates a complete Catch2 test file with fully functional test cases that
     * can verify whether vulnerabilities have been fixed. Each finding becomes
     * a TEST_CASE that makes actual HTTP requests and uses REQUIRE() assertions
     * to verify the vulnerability condition. The generated tests are ready to
     * compile and run without modification.
     * 
     * @param findings The list of security findings to generate test cases for.
     *                 Each finding becomes a separate TEST_CASE.
     * @param run_id A unique identifier for this scan run (e.g., "run_20240101_120000").
     *               This is included in the generated file header for tracking.
     * @param output_path The file path where the test file should be written.
     *                   Typically something like "out/tests/generated_tests.cpp"
     * 
     * @return true if the test file was written successfully, false if file I/O
     *         failed
     * 
     * @note Generated tests use the test_helpers library and can be configured
     *       via the TARGET_URL environment variable.
     */
    static bool generate_catch2_tests(
        const std::vector<Finding>& findings,
        const std::string& run_id,
        const std::string& output_path
    );
    
    /**
     * @brief Generates a manifest JSON file with SHA-256 hashes of all artifacts
     * 
     * Creates a JSON manifest that lists all files in the artifact directory
     * along with their SHA-256 hashes. This allows you to verify that artifacts
     * haven't been tampered with and provides an audit trail. The manifest
     * includes file names, paths, sizes, and hashes.
     * 
     * @param artifact_dir The directory containing artifacts to hash. All regular
     *                    files in this directory will be included in the manifest.
     * @param output_path The file path where the manifest should be written.
     *                   Typically "out/tests/manifest.json"
     * 
     * @return true if the manifest was written successfully, false if the directory
     *         couldn't be scanned or the file couldn't be written
     * 
     * @note The manifest file itself is excluded from the manifest to avoid
     *       circular dependencies. Errors reading individual files are logged
     *       but don't stop the manifest generation.
     */
    static bool generate_manifest(
        const std::string& artifact_dir,
        const std::string& output_path
    );

private:
    /**
     * @brief Builds a curl command string that reproduces a finding
     * 
     * Converts a Finding into a curl command that can be run from the command
     * line to reproduce the vulnerability. Handles method, headers, cookies,
     * and request body, with proper shell escaping for safety.
     * 
     * @param finding The security finding to convert into a curl command
     * 
     * @return A curl command string ready to execute in a shell
     * 
     * @note All special characters in URLs, headers, and body are properly
     *       escaped for shell safety.
     */
    static std::string generate_curl_command(const Finding& finding);
    
    /**
     * @brief Generates Catch2 test case source code for a single finding
     * 
     * Creates the C++ source code for a complete TEST_CASE that verifies the
     * vulnerability condition. The generated test makes actual HTTP requests,
     * uses helper functions for verification, and includes appropriate assertions.
     * Different vulnerability types get different verification logic (e.g., SQL
     * injection tests check for SQL errors, header tests verify header presence).
     * 
     * @param finding The security finding to generate a test case for
     * 
     * @return A string containing the complete TEST_CASE source code, including
     *         comments with finding metadata
     * 
     * @note The generated test uses REQUIRE() assertions, not WARN(), and is
     *       fully functional without modification.
     */
    static std::string generate_test_case(const Finding& finding);
    
    /**
     * @brief Computes the SHA-256 hash of a file
     * 
     * Reads a file and computes its SHA-256 hash, returning it as a hex-encoded
     * string. This is used for generating artifact manifests to ensure integrity.
     * 
     * @param file_path The path to the file to hash
     * 
     * @return A hex-encoded SHA-256 hash string, or an empty string if the file
     *         couldn't be read or hashed
     * 
     * @note Does not throw exceptions. Returns empty string on any error.
     */
    static std::string hash_file(const std::string& file_path);
    
    /**
     * @brief Escapes a string so it's safe to use in a shell command
     * 
     * Wraps a string in single quotes and escapes any single quotes within it
     * so it can be safely used in shell commands. This prevents shell injection
     * when generating curl commands.
     * 
     * @param s The string to escape
     * 
     * @return A shell-safe string wrapped in single quotes with internal quotes
     *         properly escaped
     * 
     * @note Does not throw exceptions.
     */
    static std::string shell_escape(const std::string& s);
    
    /**
     * @brief Escapes a string so it's safe to use in a C++ string literal
     * 
     * Escapes special characters (quotes, backslashes, newlines, etc.) so the
     * string can be safely embedded in C++ source code as a string literal.
     * This is used when generating test case source code.
     * 
     * @param s The string to escape
     * 
     * @return A C++ string literal-safe string with special characters escaped
     * 
     * @note Does not throw exceptions.
     */
    static std::string cpp_escape(const std::string& s);
};

} // namespace artifacts
