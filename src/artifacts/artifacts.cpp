// Implementation of reproduction artifact generators

#include "artifacts.h"
#include "logging/chain.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace artifacts {

using json = nlohmann::json;
namespace fs = std::filesystem;

// Shell escape helper
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

// C++ string literal escape
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

// Generate curl command
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

// Generate repro script
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

// Generate test case with FUNCTIONAL implementation using actual HttpClient API
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
    test << "    req.url = \"" << cpp_escape(finding.url) << "\";\n";
    
    // Set method
    if (!finding.method.empty()) {
        test << "    req.method = \"" << cpp_escape(finding.method) << "\";\n";
    } else {
        test << "    req.method = \"GET\";\n";
    }
    
    // Set headers
    if (!finding.headers.empty()) {
        test << "\n";
        test << "    // Request headers\n";
        for (const auto& [key, value] : finding.headers) {
            test << "    req.headers[\"" << cpp_escape(key) << "\"] = \"" 
                 << cpp_escape(value) << "\";\n";
        }
    }
    
    // Set body
    if (!finding.body.empty()) {
        test << "\n";
        test << "    // Request body\n";
        test << "    req.body = \"" << cpp_escape(finding.body) << "\";\n";
    }
    
    test << "\n";
    test << "    // Execute request\n";
    test << "    HttpResponse resp;\n";
    test << "    bool success = client.perform(req, resp);\n";
    test << "    REQUIRE(success);\n";
    test << "    INFO(\"Response status: \" << resp.status);\n";
    test << "\n";
    
    // Generate category-specific assertions
    if (finding.category == "missing_security_header") {
        std::string header = finding.evidence.value("header", "X-Frame-Options");
        test << "    // Verify security header '" << cpp_escape(header) << "' is present\n";
        test << "    bool has_header = false;\n";
        test << "    for (const auto& [key, value] : resp.headers) {\n";
        test << "        if (strcasecmp(key.c_str(), \"" << cpp_escape(header) << "\") == 0) {\n";
        test << "            has_header = true;\n";
        test << "            INFO(\"Found header: \" << key << \": \" << value);\n";
        test << "            break;\n";
        test << "        }\n";
        test << "    }\n";
        test << "    REQUIRE(has_header);\n";
        
    } else if (finding.category == "unsafe_cookie") {
        std::string cookie_name = finding.evidence.value("cookie", "session");
        std::string description = finding.evidence.value("description", "");
        
        test << "    // Verify cookie '" << cpp_escape(cookie_name) << "' has proper security flags\n";
        test << "    bool cookie_found = false;\n";
        test << "    bool has_secure = false;\n";
        test << "    bool has_httponly = false;\n";
        test << "    std::string cookie_value;\n";
        test << "\n";
        test << "    for (const auto& [key, value] : resp.headers) {\n";
        test << "        if (strcasecmp(key.c_str(), \"set-cookie\") == 0) {\n";
        test << "            if (value.find(\"" << cpp_escape(cookie_name) << "=\") != std::string::npos) {\n";
        test << "                cookie_found = true;\n";
        test << "                cookie_value = value;\n";
        test << "                INFO(\"Set-Cookie: \" << value);\n";
        test << "                \n";
        test << "                // Check for Secure flag (case-insensitive)\n";
        test << "                std::string lower_value = value;\n";
        test << "                std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);\n";
        test << "                if (lower_value.find(\"; secure\") != std::string::npos ||\n";
        test << "                    lower_value.find(\";secure\") != std::string::npos) {\n";
        test << "                    has_secure = true;\n";
        test << "                }\n";
        test << "                \n";
        test << "                // Check for HttpOnly flag (case-insensitive)\n";
        test << "                if (lower_value.find(\"; httponly\") != std::string::npos ||\n";
        test << "                    lower_value.find(\";httponly\") != std::string::npos) {\n";
        test << "                    has_httponly = true;\n";
        test << "                }\n";
        test << "                break;\n";
        test << "            }\n";
        test << "        }\n";
        test << "    }\n";
        test << "\n";
        test << "    REQUIRE(cookie_found);\n";
        
        // Check what specific issue was found
        std::string desc_lower = description;
        std::transform(desc_lower.begin(), desc_lower.end(), desc_lower.begin(), ::tolower);
        
        if (desc_lower.find("secure") != std::string::npos) {
            test << "    REQUIRE(has_secure);  // Issue: " << cpp_escape(description) << "\n";
        }
        if (desc_lower.find("httponly") != std::string::npos) {
            test << "    REQUIRE(has_httponly);  // Issue: " << cpp_escape(description) << "\n";
        }
        
    } else if (finding.category == "reflected_xss") {
        std::string param = finding.evidence.value("param", "");
        std::string injected = finding.evidence.value("injected", "");
        
        test << "    // Verify XSS payload is properly escaped/sanitized\n";
        if (!injected.empty()) {
            test << "    // The injected marker should NOT appear unescaped in response\n";
            test << "    std::string marker = \"" << cpp_escape(injected) << "\";\n";
            test << "    bool found_unescaped = resp.body.find(marker) != std::string::npos;\n";
            test << "    INFO(\"Response body length: \" << resp.body.length());\n";
            test << "    if (found_unescaped) {\n";
            test << "        INFO(\"XSS marker found unescaped in response!\");\n";
            test << "    }\n";
            test << "    REQUIRE_FALSE(found_unescaped);\n";
        } else {
            test << "    // Check that dangerous XSS patterns are not present\n";
            test << "    REQUIRE(resp.body.find(\"<script\") == std::string::npos);\n";
            test << "    REQUIRE(resp.body.find(\"<SCRIPT\") == std::string::npos);\n";
            test << "    REQUIRE(resp.body.find(\"javascript:\") == std::string::npos);\n";
            test << "    REQUIRE(resp.body.find(\"onerror=\") == std::string::npos);\n";
            test << "    REQUIRE(resp.body.find(\"onload=\") == std::string::npos);\n";
        }
        
    } else if (finding.category == "cors_misconfiguration") {
        test << "    // Verify CORS headers are properly configured\n";
        test << "    std::string acao;\n";
        test << "    std::string acac;\n";
        test << "\n";
        test << "    for (const auto& [key, value] : resp.headers) {\n";
        test << "        if (strcasecmp(key.c_str(), \"access-control-allow-origin\") == 0) {\n";
        test << "            acao = value;\n";
        test << "        }\n";
        test << "        if (strcasecmp(key.c_str(), \"access-control-allow-credentials\") == 0) {\n";
        test << "            acac = value;\n";
        test << "        }\n";
        test << "    }\n";
        test << "\n";
        test << "    INFO(\"Access-Control-Allow-Origin: \" << acao);\n";
        test << "    INFO(\"Access-Control-Allow-Credentials: \" << acac);\n";
        test << "\n";
        test << "    // DANGEROUS: wildcard origin (*) with credentials (true)\n";
        test << "    bool dangerous_cors = (acao == \"*\" && acac == \"true\");\n";
        test << "    REQUIRE_FALSE(dangerous_cors);\n";
        
    } else {
        // Generic verification for unknown categories
        test << "    // Generic verification for " << finding.category << "\n";
        test << "    INFO(\"Response body length: \" << resp.body.length());\n";
        test << "    INFO(\"Response time: \" << resp.total_time << \"s\");\n";
        test << "\n";
        
        if (!finding.evidence.empty()) {
            test << "    // Evidence from scan:\n";
            for (auto it = finding.evidence.begin(); it != finding.evidence.end(); ++it) {
                std::string key = it.key();

                // Skip repro_curl as it's redundant with the reproduction script
                if (key == "repro_curl") {
                    continue;
                }

                std::string value;
                if (it.value().is_string()) {
                    value = it.value().get<std::string>();
                } else {
                    value = it.value().dump();
                }
                test << "    // " << cpp_escape(key) << ": " << cpp_escape(value) << "\n";
            }
        }
        
        test << "\n";
        test << "    // Verify we got a valid HTTP response\n";
        test << "    REQUIRE(resp.status > 0);\n";
        test << "    REQUIRE(resp.status < 600);\n";
    }
    
    test << "}\n\n";
    
    return test.str();
}

// Generate Catch2 tests with functional implementation
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
    out << "#include <catch2/catch.hpp>\n";
    out << "#include <core/http_client.h>\n";
    out << "#include <string>\n";
    out << "#include <map>\n";
    out << "#include <vector>\n";
    out << "#include <algorithm>\n";
    out << "#include <cstring>  // for strcasecmp\n\n";
    
    out << "/**\n";
    out << " * Test Execution Guide:\n";
    out << " * \n";
    out << " * Run all security tests:\n";
    out << " *   ./test_security_findings\n";
    out << " * \n";
    out << " * Run tests for specific vulnerability category:\n";
    out << " *   ./test_security_findings [missing_security_header]\n";
    out << " *   ./test_security_findings [reflected_xss]\n";
    out << " *   ./test_security_findings [unsafe_cookie]\n";
    out << " * \n";
    out << " * Run tests by severity:\n";
    out << " *   ./test_security_findings [critical]\n";
    out << " *   ./test_security_findings [high]\n";
    out << " *   ./test_security_findings [medium]\n";
    out << " * \n";
    out << " * Run a specific test:\n";
    out << " *   ./test_security_findings \"missing_security_header_finding_1\"\n";
    out << " * \n";
    out << " * Verbose output:\n";
    out << " *   ./test_security_findings -s\n";
    out << " */\n\n";
    
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

// Hash file
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

// Generate manifest
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
