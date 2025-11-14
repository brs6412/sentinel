// Implementation of reproduction artifact generators

#include "artifacts.h"
#include "logging/chain.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iomanip>
#include <chrono>

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
    std::ostringstream cmd;
    cmd << "curl -i";
    
    // Method
    if (finding.method != "GET") {
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
        return false;
    }
    
    // Script header
    out << "#!/bin/sh\n";
    out << "# Auto-generated reproduction script\n";
    out << "# Generated: " << []() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    }() << "\n";
    out << "# Run individual functions to reproduce findings\n\n";
    out << "set -e\n\n";
    
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
        out << "    echo 'Reproducing finding: " << finding.id << "'\n";
        out << "    echo 'Category: " << finding.category << "'\n";
        out << "    echo 'URL: " << finding.url << "'\n";
        out << "    echo ''\n";
        out << "    " << generate_curl_command(finding) << "\n";
        out << "}\n\n";
    }
    
    // Main function that lists all available repros
    out << "# List all available reproduction functions\n";
    out << "list_repros() {\n";
    out << "    echo 'Available reproduction functions:'\n";
    out << "    echo ''\n";
    for (const auto& finding : findings) {
        std::string func_name = "repro_" + finding.id;
        for (char& c : func_name) {
            if (!isalnum(c) && c != '_') c = '_';
        }
        out << "    echo '  " << func_name << " - " << finding.category 
            << " (" << finding.severity << ")'\n";
    }
    out << "    echo ''\n";
    out << "    echo 'Usage: ./repro.sh <function_name>'\n";
    out << "    echo 'Example: ./repro.sh " << (findings.empty() ? "repro_001" : "repro_" + findings[0].id) << "'\n";
    out << "}\n\n";
    
    out << "# Run specific function if provided, otherwise list\n";
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

// Generate test case
std::string ArtifactGenerator::generate_test_case(const Finding& finding) {
    std::ostringstream test;
    
    std::string test_name = finding.category + "_" + finding.id;
    for (char& c : test_name) {
        if (!isalnum(c) && c != '_') c = '_';
    }
    
    test << "TEST_CASE(\"" << cpp_escape(test_name) << "\", \"[" 
         << cpp_escape(finding.category) << "]\") {\n";
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
    
    // Generate assertions based on category
    if (finding.category == "missing_security_header") {
        std::string header = finding.evidence.value("header_checked", "X-Frame-Options");
        test << "    // TODO: Implement HTTP request to verify header presence\n";
        test << "    // Expected: Response should include " << cpp_escape(header) << " header\n";
        test << "    //\n";
        test << "    // Example implementation:\n";
        test << "    // HttpRequest req;\n";
        test << "    // req.url = \"" << cpp_escape(finding.url) << "\";\n";
        test << "    // HttpResponse resp;\n";
        test << "    // client.perform(req, resp);\n";
        test << "    // REQUIRE(resp.headers.count(\"" << cpp_escape(header) << "\") > 0);\n";
        test << "\n";
        test << "    WARN(\"Test not yet implemented\");\n";
        
    } else if (finding.category == "unsafe_cookie") {
        std::string cookie_name = finding.evidence.value("cookie_name", "session");
        std::string missing_flag = finding.evidence.value("missing_flag", "Secure");
        test << "    // TODO: Implement HTTP request to verify cookie flags\n";
        test << "    // Expected: Cookie '" << cpp_escape(cookie_name) 
             << "' should have " << cpp_escape(missing_flag) << " flag\n";
        test << "    //\n";
        test << "    // Example implementation:\n";
        test << "    // auto cookies = parse_set_cookie_headers(resp.headers);\n";
        test << "    // REQUIRE(cookies[\"" << cpp_escape(cookie_name) 
             << "\"].has_flag(\"" << cpp_escape(missing_flag) << "\"));\n";
        test << "\n";
        test << "    WARN(\"Test not yet implemented\");\n";
        
    } else if (finding.category == "cors_misconfiguration") {
        test << "    // TODO: Implement OPTIONS preflight request\n";
        test << "    // Expected: CORS should not allow credentials with wildcard origin\n";
        test << "    //\n";
        test << "    // Example implementation:\n";
        test << "    // HttpRequest req;\n";
        test << "    // req.method = \"OPTIONS\";\n";
        test << "    // req.url = \"" << cpp_escape(finding.url) << "\";\n";
        test << "    // req.headers[\"Origin\"] = \"https://evil.example.com\";\n";
        test << "    // req.headers[\"Access-Control-Request-Method\"] = \"POST\";\n";
        test << "    // HttpResponse resp;\n";
        test << "    // client.perform(req, resp);\n";
        test << "    //\n";
        test << "    // std::string acao = resp.headers[\"access-control-allow-origin\"];\n";
        test << "    // std::string acac = resp.headers[\"access-control-allow-credentials\"];\n";
        test << "    // REQUIRE_FALSE(acao == \"*\" && acac == \"true\");\n";
        test << "\n";
        test << "    WARN(\"Test not yet implemented\");\n";
        
    } else {
        test << "    // TODO: Implement verification for " << finding.category << "\n";
        test << "    // Evidence: " << finding.evidence.dump() << "\n";
        test << "\n";
        test << "    WARN(\"Test not yet implemented\");\n";
    }
    
    test << "}\n\n";
    
    return test.str();
}

// Generate Catch2 tests
bool ArtifactGenerator::generate_catch2_tests(
    const std::vector<Finding>& findings,
    const std::string& run_id,
    const std::string& output_path
) {
    std::ofstream out(output_path);
    if (!out.is_open()) {
        return false;
    }
    
    // File header
    out << "/**\n";
    out << " * Auto-generated Catch2 test harness\n";
    out << " * Run ID: " << run_id << "\n";
    out << " * Generated: " << []() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    }() << "\n";
    out << " * Findings: " << findings.size() << "\n";
    out << " */\n\n";
    
    out << "#define CATCH_CONFIG_MAIN\n";
    out << "#include <catch2/catch.hpp>\n\n";
    out << "// TODO: Include your HTTP client helpers\n";
    out << "// #include \"http_client.h\"\n";
    out << "// #include \"test_helpers.h\"\n\n";
    
    out << "/**\n";
    out << " * These tests were generated from security scan findings.\n";
    out << " * Each test case corresponds to a specific vulnerability or issue.\n";
    out << " * \n";
    out << " * To make these tests functional:\n";
    out << " * 1. Include your HTTP client library\n";
    out << " * 2. Implement the TODO sections\n";
    out << " * 3. Replace WARN() with REQUIRE() assertions\n";
    out << " * 4. Add any necessary setup/teardown\n";
    out << " */\n\n";
    
    // Generate test cases
    for (const auto& finding : findings) {
        out << generate_test_case(finding);
    }
    
    out.close();
    return true;
}

// Hash file
std::string ArtifactGenerator::hash_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    
    // Read entire file into memory
    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string file_contents = buffer.str();
    
    // Hash using EVP via Sha256Hex
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
    manifest["files"] = json::array();
    
    // Scan artifact directory
    try {
        for (const auto& entry : fs::directory_iterator(artifact_dir)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                
                // Skip the manifest itself if it already exists
                if (entry.path() == output_path) {
                    continue;
                }
                
                std::string hash = hash_file(entry.path().string());
                
                json file_entry;
                file_entry["filename"] = filename;
                file_entry["path"] = entry.path().string();
                file_entry["size"] = fs::file_size(entry.path());
                file_entry["sha256"] = hash;
                
                manifest["files"].push_back(file_entry);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error scanning artifact directory: " << e.what() << "\n";
        return false;
    }
    
    // Write manifest
    std::ofstream out(output_path);
    if (!out.is_open()) {
        return false;
    }
    
    out << manifest.dump(2) << "\n";
    out.close();
    
    return true;
}

} // namespace artifacts