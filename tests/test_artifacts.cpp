/**
 * @file test_artifacts.cpp
 * @brief Unit tests for artifact generation functions
 * 
 * Tests the ability to generate shell scripts, Catch2 test files, and
 * manifest files from security findings. Also tests string escaping.
 */

#include <catch2/catch.hpp>
#include "artifacts/artifacts.h"
#include <filesystem>
#include <fstream>

using namespace artifacts;
namespace fs = std::filesystem;

/**
 * Test generating a shell script with repro functions
 * @test_artifacts.cpp (21-71)
 */
TEST_CASE("ArtifactGenerator generates repro script", "[artifacts]") {
    std::vector<Finding> findings;
    
    Finding f1;
    f1.id = "finding_001";
    f1.url = "https://example.com/test";
    f1.category = "missing_security_header";
    f1.method = "GET";
    f1.headers["Accept"] = "text/html";
    f1.severity = "medium";
    f1.confidence = 0.95;
    findings.push_back(f1);
    
    Finding f2;
    f2.id = "finding_002";
    f2.url = "https://example.com/api/data";
    f2.category = "cors_misconfiguration";
    f2.method = "OPTIONS";
    f2.headers["Origin"] = "https://evil.com";
    f2.severity = "high";
    f2.confidence = 0.90;
    findings.push_back(f2);
    
    std::string script_path = "test_repro.sh";
    
    SECTION("Script generation succeeds") {
        REQUIRE(ArtifactGenerator::generate_repro_script(findings, script_path));
        REQUIRE(fs::exists(script_path));
        
        // Check script is executable
        auto perms = fs::status(script_path).permissions();
        REQUIRE((perms & fs::perms::owner_exec) != fs::perms::none);
        
        // Read and verify content
        std::ifstream in(script_path);
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        
        REQUIRE(content.find("#!/bin/sh") != std::string::npos);
        REQUIRE(content.find("repro_finding_001") != std::string::npos);
        REQUIRE(content.find("repro_finding_002") != std::string::npos);
        REQUIRE(content.find("curl") != std::string::npos);
        REQUIRE(content.find("https://example.com/test") != std::string::npos);
        REQUIRE(content.find("list_repros") != std::string::npos);
    }
    
    // Cleanup
    if (fs::exists(script_path)) {
        fs::remove(script_path);
    }
}

/**
 * Test generating a Catch2 test file
 * @test_artifacts.cpp (77-114)
 */
TEST_CASE("ArtifactGenerator generates Catch2 tests", "[artifacts]") {
    std::vector<Finding> findings;
    
    Finding f;
    f.id = "xss_001";
    f.url = "https://example.com/search?q=test";
    f.category = "reflected_xss";
    f.method = "GET";
    f.severity = "high";
    f.confidence = 0.85;
    f.evidence["payload"] = "<script>alert(1)</script>";
    findings.push_back(f);
    
    std::string test_path = "test_repro.cpp";
    std::string run_id = "test_run_001";
    
    SECTION("Test file generation succeeds") {
        REQUIRE(ArtifactGenerator::generate_catch2_tests(findings, run_id, test_path));
        REQUIRE(fs::exists(test_path));
        
        // Read and verify content
        std::ifstream in(test_path);
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        
        REQUIRE(content.find("#include <catch2/catch.hpp>") != std::string::npos);
        REQUIRE(content.find("TEST_CASE") != std::string::npos);
        REQUIRE(content.find("reflected_xss") != std::string::npos);
        REQUIRE(content.find("xss_001") != std::string::npos);
        REQUIRE(content.find(run_id) != std::string::npos);
        REQUIRE(content.find("WARN") != std::string::npos);
    }
    
    // Cleanup
    if (fs::exists(test_path)) {
        fs::remove(test_path);
    }
}

/**
 * Test generating a manifest file with SHA-256 hashes
 * @test_artifacts.cpp (120-161)
 */
TEST_CASE("ArtifactGenerator generates manifest", "[artifacts]") {
    std::string test_dir = "test_artifacts_dir";
    fs::create_directories(test_dir);
    
    // Create some test files
    {
        std::ofstream f1(test_dir + "/file1.txt");
        f1 << "test content 1";
    }
    {
        std::ofstream f2(test_dir + "/file2.json");
        f2 << "{\"key\": \"value\"}";
    }
    
    std::string manifest_path = test_dir + "/manifest.json";
    
    SECTION("Manifest generation succeeds") {
        REQUIRE(ArtifactGenerator::generate_manifest(test_dir, manifest_path));
        REQUIRE(fs::exists(manifest_path));
        
        // Parse and verify manifest
        std::ifstream in(manifest_path);
        nlohmann::json manifest;
        in >> manifest;
        
        REQUIRE(manifest.contains("generated_at"));
        REQUIRE(manifest.contains("files"));
        REQUIRE(manifest["files"].is_array());
        REQUIRE(manifest["files"].size() >= 2);
        
        // Check that hashes are present
        for (const auto& file : manifest["files"]) {
            REQUIRE(file.contains("filename"));
            REQUIRE(file.contains("sha256"));
            REQUIRE(file.contains("size"));
            REQUIRE(!file["sha256"].get<std::string>().empty());
        }
    }
    
    // Cleanup
    fs::remove_all(test_dir);
}

/**
 * Test that URLs with special characters are properly escaped in shell scripts
 * @test_artifacts.cpp (167-214)
 */
TEST_CASE("Shell escaping works correctly", "[artifacts]") {
    SECTION("Simple strings") {
        // This is a private method, but we can test the public interface
        // by checking generated scripts contain properly escaped strings
        Finding f;
        f.id = "test";
        f.url = "https://example.com/path?param=value with spaces";
        f.category = "test";
        f.method = "GET";
        f.severity = "low";
        f.confidence = 0.5;
        
        std::string script = "test_escape.sh";
        REQUIRE(ArtifactGenerator::generate_repro_script({f}, script));
        
        std::ifstream in(script);
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        
        // URL should be quoted in the script
        REQUIRE(content.find("'https://example.com/path?param=value with spaces'") 
                != std::string::npos);
        
        fs::remove(script);
    }
    
    SECTION("Special characters") {
        Finding f;
        f.id = "special";
        f.url = "https://example.com/test'quote";
        f.category = "test";
        f.method = "GET";
        f.severity = "low";
        f.confidence = 0.5;
        
        std::string script = "test_special.sh";
        REQUIRE(ArtifactGenerator::generate_repro_script({f}, script));
        
        std::ifstream in(script);
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        
        // Single quote should be escaped
        REQUIRE(content.find("'\\''") != std::string::npos);
        
        fs::remove(script);
    }
}

/**
 * Test that multiple findings create multiple repro functions
 * @test_artifacts.cpp (220-248)
 */
TEST_CASE("Multiple findings generate multiple functions", "[artifacts]") {
    std::vector<Finding> findings;
    
    for (int i = 0; i < 5; i++) {
        Finding f;
        f.id = "finding_" + std::to_string(i);
        f.url = "https://example.com/test" + std::to_string(i);
        f.category = "test_category";
        f.method = "GET";
        f.severity = "low";
        f.confidence = 0.5;
        findings.push_back(f);
    }
    
    std::string script = "test_multiple.sh";
    REQUIRE(ArtifactGenerator::generate_repro_script(findings, script));
    
    std::ifstream in(script);
    std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
    
    // Check all functions are present
    for (int i = 0; i < 5; i++) {
        std::string func_name = "repro_finding_" + std::to_string(i);
        REQUIRE(content.find(func_name) != std::string::npos);
    }
    
    fs::remove(script);
}

/**
 * Test that generated Catch2 tests include finding evidence
 * @test_artifacts.cpp (254-277)
 */
TEST_CASE("Catch2 tests include evidence", "[artifacts]") {
    Finding f;
    f.id = "header_001";
    f.url = "https://example.com/";
    f.category = "missing_security_header";
    f.method = "GET";
    f.severity = "medium";
    f.confidence = 0.95;
    f.evidence["header_checked"] = "X-Frame-Options";
    f.evidence["observed_value"] = nullptr;
    
    std::string test_path = "test_evidence.cpp";
    REQUIRE(ArtifactGenerator::generate_catch2_tests({f}, "run_001", test_path));
    
    std::ifstream in(test_path);
    std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
    
    // Check evidence is mentioned
    REQUIRE(content.find("X-Frame-Options") != std::string::npos);
    REQUIRE(content.find("missing_security_header") != std::string::npos);
    
    fs::remove(test_path);
}

/**
 * Test that empty finding lists still generate valid (but minimal) artifacts
 * @test_artifacts.cpp (283-315)
 */
TEST_CASE("Empty findings generate valid but empty artifacts", "[artifacts]") {
    std::vector<Finding> empty_findings;
    
    SECTION("Empty repro script") {
        std::string script = "test_empty.sh";
        REQUIRE(ArtifactGenerator::generate_repro_script(empty_findings, script));
        
        std::ifstream in(script);
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        
        // Should still have header and list function
        REQUIRE(content.find("#!/bin/sh") != std::string::npos);
        REQUIRE(content.find("list_repros") != std::string::npos);
        
        fs::remove(script);
    }
    
    SECTION("Empty test file") {
        std::string test_path = "test_empty.cpp";
        REQUIRE(ArtifactGenerator::generate_catch2_tests(empty_findings, "run_001", test_path));
        
        std::ifstream in(test_path);
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        
        // Should have includes but no test cases
        REQUIRE(content.find("#include <catch2/catch.hpp>") != std::string::npos);
        REQUIRE(content.find("Findings: 0") != std::string::npos);
        
        fs::remove(test_path);
    }
}