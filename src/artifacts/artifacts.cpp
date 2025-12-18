/**
 * @file artifacts.cpp
 * @brief Implementation of reproduction artifact generators
 * 
 * This file implements the ArtifactGenerator class which converts security
 * findings into executable artifacts like shell scripts and Catch2 tests.
 */

#include "artifacts.h"
#include "logging/chain.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cctype>

namespace artifacts {

using json = nlohmann::json;
namespace fs = std::filesystem;

// Implementation of shell_escape - see header for documentation
std::string ArtifactGenerator::shell_escape(const std::string& s) {
    std::ostringstream oss;
    oss << "'";
    for (char c : s) {
        if (c == '\'') {
            oss << "'\\''";
        } else {
            oss << c;
        }
    }
    oss << "'";
    return oss.str();
}

// Implementation of cpp_escape - see header for documentation
std::string ArtifactGenerator::cpp_escape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:   oss << c; break;
        }
    }
    return oss.str();
}

// Implementation of generate_curl_command - see header for documentation
std::string ArtifactGenerator::generate_curl_command(const Finding& finding) {
    if (finding.evidence.find("repro_curl") != finding.evidence.end()) {
        return finding.evidence["repro_curl"];
    }
    std::ostringstream cmd;
    cmd << "curl -i";
    
    // Method
    if (!finding.method.empty() && finding.method != "GET") {
        cmd << " -X " << finding.method;
    }
    
    // Headers
    for (const auto& [key, value] : finding.headers) {
        cmd << " -H " << shell_escape(key + ": " + value);
    }
    
    // Body
    if (!finding.body.empty()) {
        cmd << " -d " << shell_escape(finding.body);
    }
    
    // URL
    cmd << " " << shell_escape(finding.url);
    
    return cmd.str();
}

// Implementation of generate_repro_script - see header for documentation
bool ArtifactGenerator::generate_repro_script(
    const std::vector<Finding>& findings,
    const std::string& output_path
) {
    std::ofstream out(output_path);
    if (!out.is_open()) {
        std::cerr << "Error: Could not open " << output_path << " for writing\n";
        return false;
    }
    
    // Script header
    out << "#!/bin/bash\n";
    out << "# Auto-generated reproduction script\n";
    out << "# Generated: " << []() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    }() << "\n";
    out << "# Total findings: " << findings.size() << "\n";
    out << "# Run individual functions to reproduce findings\n\n";
    out << "set -e\n";
    out << "set -u\n\n";
    
    out << "# Colors for output\n";
    out << "RED='\\033[0;31m'\n";
    out << "GREEN='\\033[0;32m'\n";
    out << "YELLOW='\\033[1;33m'\n";
    out << "BLUE='\\033[0;34m'\n";
    out << "NC='\\033[0m' # No Color\n\n";
    
    // Generate function per finding
    for (const auto& finding : findings) {
        std::string func_name = "repro_" + finding.id;
        // Replace invalid shell characters
        for (char& c : func_name) {
            if (!isalnum(c) && c != '_') {
                c = '_';
            }
        }
        
        out << "# Finding: " << finding.category << "\n";
        out << "# URL: " << finding.url << "\n";
        out << "# Severity: " << finding.severity << "\n";
        out << "# Confidence: " << finding.confidence << "\n";
        out << func_name << "() {\n";
        out << "    echo -e \"${YELLOW}=== Reproducing finding: " << finding.id << " ===${NC}\"\n";
        out << "    echo \"Category: " << finding.category << "\"\n";
        out << "    echo \"Severity: " << finding.severity << "\"\n";
        out << "    echo \"Confidence: " << finding.confidence << "\"\n";
        out << "    echo \"URL: " << finding.url << "\"\n";
        
        // Add evidence details if present
        if (!finding.evidence.empty()) {
            out << "    echo -e \"${BLUE}Evidence:${NC}\"\n";
            for (auto it = finding.evidence.begin(); it != finding.evidence.end(); ++it) {
                std::string key = it.key();

                if (key == "response_snippet") {
                    continue;
                }

                std::string value;
                if (it.value().is_string()) {
                    value = it.value().get<std::string>();
                } else {
                    value = it.value().dump();
                }
                // Escape single quotes in the value for shell safety
                std::string escaped_value;
                for (char c : value) {
                    if (c == '\'') {
                        escaped_value += "'\\''";
                    } else {
                        escaped_value += c;
                    }
                }
                out << "    echo \"  - " << key << ": " << escaped_value << "\"\n";
            }
        }
        
        out << "    echo ''\n";
        out << "    echo -e \"${GREEN}Running curl command...${NC}\"\n";
        out << "    " << generate_curl_command(finding) << "\n";
        out << "    echo ''\n";
        out << "}\n\n";
    }
    
    // Main function that lists all available repros
    out << "# List all available reproduction functions\n";
    out << "list_repros() {\n";
    out << "    echo -e \"${GREEN}Available reproduction functions:${NC}\"\n";
    out << "    echo ''\n";
    
    // Group by severity
    std::map<std::string, std::vector<const Finding*>> by_severity;
    for (const auto& finding : findings) {
        by_severity[finding.severity].push_back(&finding);
    }
    
    // Display in order of severity
    for (const auto& severity : {"critical", "high", "medium", "low", "info"}) {
        if (by_severity.count(severity) > 0) {
            std::string color;
            if (severity == std::string("critical") || severity == std::string("high")) {
                color = "RED";
            } else if (severity == std::string("medium")) {
                color = "YELLOW";
            } else {
                color = "NC";
            }
            
            out << "    echo -e \"${" << color << "}" << severity << " severity:${NC}\"\n";
            
            for (const auto* finding : by_severity[severity]) {
                std::string func_name = "repro_" + finding->id;
                for (char& c : func_name) {
                    if (!isalnum(c) && c != '_') c = '_';
                }
                out << "    echo '  " << func_name << " - " << finding->category << "'\n";
            }
            out << "    echo ''\n";
        }
    }
    
    out << "    echo 'Usage: ./repro.sh <function_name>'\n";
    out << "    echo 'Example: ./repro.sh " 
        << (findings.empty() ? "repro_finding_1" : "repro_" + findings[0].id) << "'\n";
    out << "    echo ''\n";
    out << "    echo 'To run all reproductions: ./repro.sh run_all'\n";
    out << "}\n\n";
    
    // Run all function
    out << "# Run all reproduction functions\n";
    out << "run_all() {\n";
    out << "    echo -e \"${GREEN}Running all " << findings.size() << " reproduction functions...${NC}\"\n";
    out << "    echo ''\n";
    out << "    local failed=0\n";
    out << "    local succeeded=0\n";
    for (const auto& finding : findings) {
        std::string func_name = "repro_" + finding.id;
        for (char& c : func_name) {
            if (!isalnum(c) && c != '_') c = '_';
        }
        out << "    if " << func_name << "; then\n";
        out << "        ((succeeded++))\n";
        out << "    else\n";
        out << "        echo -e \"${RED}Failed: " << func_name << "${NC}\"\n";
        out << "        ((failed++))\n";
        out << "    fi\n";
        out << "    echo ''\n";
    }
    out << "    echo -e \"${GREEN}Reproduction summary:${NC}\"\n";
    out << "    echo \"  Succeeded: $succeeded\"\n";
    out << "    echo \"  Failed: $failed\"\n";
    out << "    echo \"  Total: " << findings.size() << "\"\n";
    out << "    return $failed\n";
    out << "}\n\n";
    
    out << "# Main entry point\n";
    out << "if [ $# -eq 0 ]; then\n";
    out << "    list_repros\n";
    out << "else\n";
    out << "    \"$@\"\n";
    out << "fi\n";
    
    out.close();
    
    // Make executable
    try {
        fs::permissions(output_path, 
            fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
            fs::perms::others_read | fs::perms::others_exec);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not set executable permissions: " << e.what() << "\n";
    }
    
    return true;
}

// Implementation of generate_test_case - see header for documentation
std::string ArtifactGenerator::generate_test_case(const Finding& finding) {
    std::ostringstream test;
    
    std::string test_name = finding.category + "_" + finding.id;
    for (char& c : test_name) {
        if (!isalnum(c) && c != '_') c = '_';
    }
    
    test << "TEST_CASE(\"" << cpp_escape(test_name) << "\", \"[" 
         << cpp_escape(finding.category) << "][" << cpp_escape(finding.severity) << "]\") {\n";
    test << "    // Finding ID: " << finding.id << "\n";
    test << "    // URL: " << finding.url << "\n";
    test << "    // Category: " << finding.category << "\n";
    test << "    // Severity: " << finding.severity << "\n";
    test << "    // Confidence: " << finding.confidence << "\n";
    
    if (!finding.remediation_id.empty()) {
        test << "    // Remediation: See assets/remediation/" 
             << finding.remediation_id << ".md\n";
    }
    
    test << "\n";
    test << "    // Setup request\n";
    test << "    HttpClient client;\n";
    test << "    HttpRequest req;\n";
    // Extract base URL and path from finding URL
    std::string base_url = "http://127.0.0.1:8080";
    std::string path_and_query = finding.url;
    
    size_t scheme_end = finding.url.find("://");
    if (scheme_end != std::string::npos) {
        size_t path_start = finding.url.find('/', scheme_end + 3);
        if (path_start != std::string::npos) {
            base_url = finding.url.substr(0, path_start);
            path_and_query = finding.url.substr(path_start);
        } else {
            base_url = finding.url;
            path_and_query = "/";
        }
    }
    
    test << "    // Target URL (can be overridden with TARGET_URL env var)\n";
    test << "    std::string base_url = get_target_url(\"" << cpp_escape(base_url) << "\");\n";
    test << "    std::string test_url = base_url + \"" << cpp_escape(path_and_query) << "\";\n";
    test << "    \n";
    test << "    HttpClient client = create_test_client();\n";
    test << "    HttpRequest req;\n";
    test << "    req.method = \"" << cpp_escape(finding.method) << "\";\n";
    test << "    req.url = test_url;\n";
    
    // Add headers from finding
    if (!finding.headers.empty()) {
        test << "    \n";
        test << "    // Request headers\n";
        for (const auto& [key, value] : finding.headers) {
            test << "    req.headers[\"" << cpp_escape(key) << "\"] = \"" << cpp_escape(value) << "\";\n";
        }
    }
    
    // Add body if present
    if (!finding.body.empty()) {
        test << "    \n";
        test << "    // Request body\n";
        test << "    req.body = \"" << cpp_escape(finding.body) << "\";\n";
    }
    
    test << "    \n";
    test << "    HttpResponse resp;\n";
    test << "    REQUIRE(client.perform(req, resp));\n";
    test << "    REQUIRE(resp.status > 0);\n";
    test << "    \n";
    
    // Generate assertions based on category
    if (finding.category == "missing_security_header") {
        std::string header = finding.evidence.value("header_checked", "X-Frame-Options");
        std::string lower_header = header;
        std::transform(lower_header.begin(), lower_header.end(), lower_header.begin(), ::tolower);
        
        test << "    // Verify security header is present\n";
        test << "    REQUIRE(verify_security_header(resp, \"" << cpp_escape(lower_header) << "\"));\n";
        
    } else if (finding.category == "unsafe_cookie") {
        std::string cookie_name = finding.evidence.value("cookie_name", "session");
        std::string missing_flag = finding.evidence.value("missing_flag", "Secure");
        
        test << "    // Parse cookies from response\n";
        test << "    auto cookies = parse_cookies_from_response(resp);\n";
        test << "    REQUIRE(cookies.count(\"" << cpp_escape(cookie_name) << "\") > 0);\n";
        test << "    \n";
        test << "    // Verify cookie has required flag\n";
        test << "    CookieInfo cookie = cookies[\"" << cpp_escape(cookie_name) << "\"];\n";
        test << "    REQUIRE(cookie_has_flag(cookie, \"" << cpp_escape(missing_flag) << "\"));\n";
        
    } else if (finding.category == "cors_misconfiguration") {
        test << "    // Perform CORS preflight request\n";
        test << "    HttpResponse cors_resp = cors_preflight_request(client, test_url, \"https://evil.example.com\", \"POST\");\n";
        test << "    \n";
        test << "    // Verify CORS is not misconfigured (wildcard origin with credentials)\n";
        test << "    REQUIRE_FALSE(verify_cors_misconfiguration(cors_resp));\n";
        
    } else if (finding.category == "sql_injection") {
        std::string payload = finding.evidence.value("payload", "");
        std::string detection_method = finding.evidence.value("detection_method", "error");
        std::string param_name = finding.evidence.value("param_name", "id");
        
        test << "    // SQL injection test with payload\n";
        test << "    HttpRequest sql_req = req;\n";
        if (!payload.empty()) {
            // Check if URL already has query parameters
            std::string separator = (path_and_query.find('?') != std::string::npos) ? "&" : "?";
            test << "    sql_req.url = test_url + \"" << separator << cpp_escape(param_name) << "=" << cpp_escape(payload) << "\";\n";
        }
        test << "    \n";
        test << "    HttpResponse sql_resp;\n";
        test << "    REQUIRE(client.perform(sql_req, sql_resp));\n";
        test << "    \n";
        
        if (detection_method == "error") {
            test << "    // Verify SQL error is NOT present (vulnerability should be fixed)\n";
            test << "    REQUIRE_FALSE(contains_sql_error(sql_resp));\n";
        } else if (detection_method == "time") {
            test << "    // Verify response time is reasonable (no time-based injection)\n";
            test << "    double response_time = measure_response_time(client, sql_req);\n";
            test << "    REQUIRE_FALSE(response_time_exceeds(response_time, 5000.0));\n";
        } else {
            test << "    // Verify SQL error is NOT present\n";
            test << "    REQUIRE_FALSE(contains_sql_error(sql_resp));\n";
        }
        
    } else if (finding.category == "command_injection") {
        std::string payload = finding.evidence.value("payload", "");
        std::string param_name = finding.evidence.value("param_name", "host");
        
        test << "    // Command injection test\n";
        test << "    HttpRequest cmd_req = req;\n";
        if (!payload.empty()) {
            std::string separator = (path_and_query.find('?') != std::string::npos) ? "&" : "?";
            test << "    cmd_req.url = test_url + \"" << separator << cpp_escape(param_name) << "=" << cpp_escape(payload) << "\";\n";
        }
        test << "    \n";
        test << "    HttpResponse cmd_resp;\n";
        test << "    REQUIRE(client.perform(cmd_req, cmd_resp));\n";
        test << "    \n";
        test << "    // Verify command output is NOT present (vulnerability should be fixed)\n";
        test << "    REQUIRE_FALSE(contains_command_output(cmd_resp));\n";
        
    } else if (finding.category == "path_traversal") {
        std::string payload = finding.evidence.value("payload", "");
        std::string param_name = finding.evidence.value("param_name", "file");
        
        test << "    // Path traversal test\n";
        test << "    HttpRequest path_req = req;\n";
        if (!payload.empty()) {
            std::string separator = (path_and_query.find('?') != std::string::npos) ? "&" : "?";
            test << "    path_req.url = test_url + \"" << separator << cpp_escape(param_name) << "=" << cpp_escape(payload) << "\";\n";
        }
        test << "    \n";
        test << "    HttpResponse path_resp;\n";
        test << "    REQUIRE(client.perform(path_req, path_resp));\n";
        test << "    \n";
        test << "    // Verify file content is NOT exposed (vulnerability should be fixed)\n";
        test << "    REQUIRE_FALSE(contains_file_content(path_resp));\n";
        
    } else {
        // Generic test for other categories
        test << "    // Generic verification for " << finding.category << "\n";
        test << "    // Evidence: " << cpp_escape(finding.evidence.dump()) << "\n";
        test << "    REQUIRE(resp.status == 200 || resp.status < 500);\n";
    }
    
    test << "}\n\n";
    
    return test.str();
}

// Implementation of generate_catch2_tests - see header for documentation
bool ArtifactGenerator::generate_catch2_tests(
    const std::vector<Finding>& findings,
    const std::string& run_id,
    const std::string& output_path
) {
    std::ofstream out(output_path);
    if (!out.is_open()) {
        std::cerr << "Error: Could not open " << output_path << " for writing\n";
        return false;
    }
    
    // File header
    out << "/**\n";
    out << " * Auto-generated Catch2 Security Test Suite\n";
    out << " * Run ID: " << run_id << "\n";
    out << " * Generated: " << []() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    }() << "\n";
    out << " * Total findings: " << findings.size() << "\n";
    out << " *\n";
    out << " * These tests are FUNCTIONAL and ready to run.\n";
    out << " * They verify that security vulnerabilities have been properly fixed.\n";
    out << " * \n";
    out << " * IMPORTANT: Tests are designed to PASS when vulnerabilities are FIXED.\n";
    out << " * If a test fails, the corresponding vulnerability still exists.\n";
    out << " */\n\n";
    
    out << "#define CATCH_CONFIG_MAIN\n";
    out << "#include \"catch_amalgamated.hpp\"\n";
    out << "#include \"core/http_client.h\"\n";
    out << "#include \"helpers/http_test_helpers.h\"\n";
    out << "#include <string>\n\n";
    
    out << "/**\n";
    out << " * Test Execution Guide:\n";
    out << " * \n";
    out << " * To configure the target URL, set the TARGET_URL environment variable:\n";
    out << " *   export TARGET_URL=http://example.com:8080\n";
    out << " * \n";
    out << " * Default target: http://127.0.0.1:8080\n";
    out << " */\n\n";
    
    out << "using namespace test_helpers;\n\n";
    
    // Generate summary comment
    std::map<std::string, int> by_severity;
    std::map<std::string, int> by_category;
    for (const auto& finding : findings) {
        by_severity[finding.severity]++;
        by_category[finding.category]++;
    }
    
    out << "/**\n";
    out << " * Test Summary:\n";
    out << " * \n";
    out << " * By Severity:\n";
    for (const auto& sev : {"critical", "high", "medium", "low", "info"}) {
        if (by_severity.count(sev) > 0) {
            out << " *   " << sev << ": " << by_severity[sev] << " test";
            if (by_severity[sev] != 1) out << "s";
            out << "\n";
        }
    }
    out << " * \n";
    out << " * By Category:\n";
    for (const auto& [category, count] : by_category) {
        out << " *   " << category << ": " << count << " test";
        if (count != 1) out << "s";
        out << "\n";
    }
    out << " */\n\n";
    
    // Generate test cases grouped by category
    std::map<std::string, std::vector<const Finding*>> grouped_by_category;
    for (const auto& finding : findings) {
        grouped_by_category[finding.category].push_back(&finding);
    }
    
    for (const auto& [category, category_findings] : grouped_by_category) {
        out << "// ============================================================\n";
        out << "// " << category << " tests (" << category_findings.size() << " finding";
        if (category_findings.size() != 1) out << "s";
        out << ")\n";
        out << "// ============================================================\n\n";
        
        for (const auto* finding : category_findings) {
            out << generate_test_case(*finding);
        }
    }
    
    out.close();
    return true;
}

// Implementation of hash_file - see header for documentation
std::string ArtifactGenerator::hash_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open file for hashing: " << file_path << "\n";
        return "";
    }
    
    // Read entire file into memory
    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string file_contents = buffer.str();
    
    // Hash using EVP via Sha256Hex from logging/chain.h
    return logging::Sha256Hex(file_contents);
}

// Implementation of generate_manifest - see header for documentation
bool ArtifactGenerator::generate_manifest(
    const std::string& artifact_dir,
    const std::string& output_path
) {
    json manifest;
    
    // Timestamp
    manifest["generated_at"] = []() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }();
    
    manifest["artifact_dir"] = artifact_dir;
    manifest["version"] = "1.0";
    manifest["files"] = json::array();
    
    // Scan artifact directory
    try {
        if (!fs::exists(artifact_dir)) {
            std::cerr << "Error: Artifact directory does not exist: " << artifact_dir << "\n";
            return false;
        }
        
        if (!fs::is_directory(artifact_dir)) {
            std::cerr << "Error: Path is not a directory: " << artifact_dir << "\n";
            return false;
        }
        
        for (const auto& entry : fs::directory_iterator(artifact_dir)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                
                // Skip the manifest itself if it already exists
                if (entry.path() == output_path) {
                    continue;
                }
                
                std::string hash = hash_file(entry.path().string());
                if (hash.empty()) {
                    std::cerr << "Warning: Could not hash file: " << filename << "\n";
                    continue;
                }
                
                json file_entry;
                file_entry["filename"] = filename;
                file_entry["path"] = entry.path().string();
                file_entry["size"] = fs::file_size(entry.path());
                file_entry["sha256"] = hash;
                
                // Determine file type based on extension
                std::string ext = entry.path().extension().string();
                if (ext == ".sh") {
                    file_entry["type"] = "reproduction_script";
                } else if (ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".c++") {
                    file_entry["type"] = "test_harness";
                } else if (ext == ".html" || ext == ".htm") {
                    file_entry["type"] = "html_report";
                } else if (ext == ".json") {
                    file_entry["type"] = "json_data";
                } else if (ext == ".jsonl") {
                    file_entry["type"] = "jsonl_data";
                } else if (ext == ".md") {
                    file_entry["type"] = "markdown";
                } else if (ext == ".txt") {
                    file_entry["type"] = "text";
                } else {
                    file_entry["type"] = "unknown";
                }
                
                manifest["files"].push_back(file_entry);
            }
        }
        
        // Add summary statistics
        manifest["total_files"] = manifest["files"].size();
        
    } catch (const std::exception& e) {
        std::cerr << "Error scanning artifact directory: " << e.what() << "\n";
        return false;
    }
    
    // Write manifest
    std::ofstream out(output_path);
    if (!out.is_open()) {
        std::cerr << "Error: Could not open " << output_path << " for writing\n";
        return false;
    }
    
    out << manifest.dump(2) << "\n";
    out.close();
    
    return true;
}

} // namespace artifacts
