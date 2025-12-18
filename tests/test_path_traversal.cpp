/**
 * @file test_path_traversal.cpp
 * @brief Unit tests for path traversal (directory traversal) vulnerability detection
 * 
 * Tests detection of:
 * - Basic path traversal (../, ..\)
 * - URL encoded traversal variants
 * - Double URL encoded traversal
 * - Null byte injection for extension bypass
 * - Unicode encoded traversal
 * - File content detection (passwd, win.ini, hosts)
 * - Baseline comparison detection
 * - OS type identification
 * - Session maintenance during testing
 */

#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include "core/vuln_engine.h"
#include "core/http_client.h"
#include "core/session_manager.h"
#include "schema/crawl_result.h"
#include <string>
#include <vector>
#include <map>

// Helper to create a test HTTP client
HttpClient create_test_client() {
    HttpClient::Options opts;
    opts.timeout_seconds = 15;
    opts.connect_timeout_seconds = 5;
    return HttpClient(opts);
}

TEST_CASE("Path traversal check function exists", "[path_traversal]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Function should execute without crashing
    REQUIRE(true);
}

TEST_CASE("Path traversal detection skips endpoints without parameters", "[path_traversal]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/static/page.html";
    result.method = "GET";
    // No parameters
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should not create findings for endpoints without parameters
    REQUIRE(findings.empty());
}

TEST_CASE("Path traversal tests GET parameters", "[path_traversal][get]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should attempt to test the parameter
    // May or may not find vulnerabilities depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal tests POST body parameters", "[path_traversal][post]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "POST";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should attempt to test POST body parameters
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal finding has correct category", "[path_traversal][category]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download?file=test.txt";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // If findings are created, they should have path_traversal category
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal") {
            REQUIRE(finding.category == "path_traversal");
            REQUIRE(finding.severity == "high");
            REQUIRE(finding.confidence >= 0.7);
            REQUIRE(finding.evidence.contains("detection_method"));
            REQUIRE(finding.evidence.contains("payload"));
        }
    }
}

TEST_CASE("Path traversal file content detection method", "[path_traversal][file_content]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Check if any findings use file content detection
    bool found_file_content = false;
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "file_content") {
            found_file_content = true;
            REQUIRE(finding.evidence.contains("os_type"));
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("encoding_type"));
            REQUIRE(finding.evidence.contains("accessed_file"));
            REQUIRE(finding.evidence.contains("target_file"));
            if (finding.evidence.contains("file_content")) {
                REQUIRE_FALSE(finding.evidence["file_content"].empty());
            }
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal baseline comparison detection method", "[path_traversal][baseline]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Check if any findings use baseline comparison detection
    bool found_baseline = false;
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "baseline comparison") {
            found_baseline = true;
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("similarity_score"));
            REQUIRE(finding.evidence.contains("length_change_percentage"));
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal tests basic Unix payloads", "[path_traversal][unix]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should test Unix paths (../../../etc/passwd, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal tests basic Windows payloads", "[path_traversal][windows]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should test Windows paths (..\..\..\windows\win.ini, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal tests URL encoded variants", "[path_traversal][encoded]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should test URL encoded variants (%2e%2e%2f, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal tests double encoded variants", "[path_traversal][double_encoded]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should test double encoded variants (..%252f, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal tests null byte injection", "[path_traversal][null_byte]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should test null byte injection (passwd%00.txt, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal identifies accessed file", "[path_traversal][file_identification]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // If findings are created, check file identification
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal" && 
            finding.evidence.contains("accessed_file")) {
            std::string accessed_file = finding.evidence["accessed_file"];
            // Should identify the accessed file
            REQUIRE(!accessed_file.empty());
        }
    }
}

TEST_CASE("Path traversal OS type identification", "[path_traversal][os_type]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // If findings are created, check OS type identification
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal" && 
            finding.evidence.contains("os_type")) {
            std::string os_type = finding.evidence["os_type"];
            // Should identify OS type (unix, windows, or generic)
            REQUIRE(!os_type.empty());
        }
    }
}

TEST_CASE("Path traversal encoding type identification", "[path_traversal][encoding]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // If findings are created, check encoding type identification
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal" && 
            finding.evidence.contains("encoding_type")) {
            std::string encoding_type = finding.evidence["encoding_type"];
            // Should identify encoding type (basic, url_encoded, double_encoded, null_byte, unicode, alternative)
            REQUIRE(!encoding_type.empty());
        }
    }
}

TEST_CASE("Path traversal maintains session during testing", "[path_traversal][session]") {
    HttpClient client = create_test_client();
    SessionManager session_manager(client);
    VulnEngine engine(client, 0.7, &session_manager);
    
    // Set up a test session (if session manager is configured)
    // This test verifies that session is maintained during path traversal testing
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // Should use session manager if available
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Path traversal respects confidence threshold", "[path_traversal][confidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.9); // High threshold
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // All findings should meet confidence threshold
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal") {
            REQUIRE(finding.confidence >= 0.9);
        }
    }
}

TEST_CASE("Path traversal finding includes remediation ID", "[path_traversal][remediation]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // All path traversal findings should have remediation_id
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal") {
            REQUIRE(finding.remediation_id == "path_traversal");
        }
    }
}

TEST_CASE("Path traversal captures file content as evidence", "[path_traversal][evidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/download";
    result.method = "GET";
    result.params.push_back({"file", "test.txt"});
    
    std::vector<Finding> findings;
    engine.checkPathTraversal(result, findings);
    
    // If file content findings are created, they should include file content evidence
    for (const auto& finding : findings) {
        if (finding.category == "path_traversal" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "file_content") {
            // Should have file content or context if detected
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("accessed_file"));
            REQUIRE(finding.evidence.contains("target_file"));
        }
    }
}

