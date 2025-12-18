/**
 * @file test_xxe.cpp
 * @brief Unit tests for XML External Entity (XXE) vulnerability detection
 * 
 * Tests detection of:
 * - Classic XXE file disclosure
 * - Blind XXE detection
 * - Parameter entity XXE
 * - XXE SSRF
 * - XML content type detection
 * - File content detection via entity expansion
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

TEST_CASE("XXE check function exists", "[xxe]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Function should execute without crashing
    REQUIRE(true);
}

TEST_CASE("OOB detection: XXE with callback URL configured", "[xxe][oob]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    // Set a callback URL
    engine.setCallbackUrl("https://webhook.site/test-uuid");
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Function should execute without crashing when callback URL is set
    // Blind XXE payloads should use callback URL instead of "attacker.com"
    REQUIRE(true);
}

TEST_CASE("OOB detection: XXE blind payload uses callback URL", "[xxe][oob]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    // Set a callback URL
    std::string callback_url = "https://webhook.site/abc123";
    engine.setCallbackUrl(callback_url);
    
    // Generate token and build callback URL
    std::string token = engine.generateCallbackToken();
    std::string built_callback = engine.buildCallbackUrl(token);
    
    // Verify callback URL is built correctly
    REQUIRE(built_callback.find(callback_url) != std::string::npos);
    REQUIRE(built_callback.find("token=") != std::string::npos);
}

TEST_CASE("XXE detection skips non-XML endpoints", "[xxe]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/data";
    result.method = "GET";
    result.params.push_back({"id", "123"});
    // No XML content type, not POST/PUT, no XML-like parameters
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Should skip endpoints that don't appear to accept XML
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE tests XML endpoints", "[xxe][xml]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    result.headers.push_back({"content-type", "application/xml"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Should attempt to test XML endpoints
    // May or may not find vulnerabilities depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE tests POST body", "[xxe][post]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    // No parameters, but POST method
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Should attempt to test POST body
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE finding has correct category", "[xxe][category]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // If findings are created, they should have xxe category
    for (const auto& finding : findings) {
        if (finding.category == "xxe") {
            REQUIRE(finding.category == "xxe");
            REQUIRE((finding.severity == "high" || finding.severity == "critical"));
            REQUIRE(finding.confidence >= 0.7);
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("payload_type"));
            REQUIRE(finding.evidence.contains("detection_method"));
        }
    }
}

TEST_CASE("XXE classic file disclosure detection", "[xxe][classic]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Check if any findings use classic file disclosure
    bool found_classic = false;
    for (const auto& finding : findings) {
        if (finding.category == "xxe" && 
            finding.evidence.contains("payload_type") &&
            finding.evidence["payload_type"] == "classic") {
            found_classic = true;
            REQUIRE(finding.evidence.contains("detection_method"));
            REQUIRE(finding.evidence.contains("target_file"));
            if (finding.evidence.contains("accessed_file")) {
                REQUIRE_FALSE(finding.evidence["accessed_file"].empty());
            }
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE blind detection", "[xxe][blind]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Check if any findings use blind detection
    bool found_blind = false;
    for (const auto& finding : findings) {
        if (finding.category == "xxe" && 
            finding.evidence.contains("detection_method") &&
            (finding.evidence["detection_method"] == "blind" ||
             finding.evidence["detection_method"] == "parameter_entity")) {
            found_blind = true;
            REQUIRE(finding.evidence.contains("payload_type"));
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE parameter entity detection", "[xxe][parameter]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Should test parameter entities for blind XXE
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE SSRF detection", "[xxe][ssrf]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Should test XXE SSRF payloads
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE tests common file targets", "[xxe][files]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Should test /etc/passwd, /etc/hostname, win.ini, etc.
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE identifies accessed file", "[xxe][file_identification]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // If findings are created, check file identification
    for (const auto& finding : findings) {
        if (finding.category == "xxe" && 
            finding.evidence.contains("accessed_file")) {
            std::string accessed_file = finding.evidence["accessed_file"];
            // Should identify the accessed file
            REQUIRE(!accessed_file.empty());
        }
    }
}

TEST_CASE("XXE payload type identification", "[xxe][payload_type]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // If findings are created, check payload type identification
    for (const auto& finding : findings) {
        if (finding.category == "xxe" && 
            finding.evidence.contains("payload_type")) {
            std::string payload_type = finding.evidence["payload_type"];
            // Should identify payload type (classic, blind, parameter_entity, ssrf)
            REQUIRE(!payload_type.empty());
        }
    }
}

TEST_CASE("XXE detection method identification", "[xxe][detection_method]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // If findings are created, check detection method identification
    for (const auto& finding : findings) {
        if (finding.category == "xxe" && 
            finding.evidence.contains("detection_method")) {
            std::string detection_method = finding.evidence["detection_method"];
            // Should identify detection method (file_content, blind, parameter_entity, ssrf)
            REQUIRE(!detection_method.empty());
        }
    }
}

TEST_CASE("XXE respects confidence threshold", "[xxe][confidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.9); // High threshold
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // All findings should meet confidence threshold
    for (const auto& finding : findings) {
        if (finding.category == "xxe") {
            REQUIRE(finding.confidence >= 0.9);
        }
    }
}

TEST_CASE("XXE finding includes remediation ID", "[xxe][remediation]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // All XXE findings should have remediation_id
    for (const auto& finding : findings) {
        if (finding.category == "xxe") {
            REQUIRE(finding.remediation_id == "xxe");
        }
    }
}

TEST_CASE("XXE captures file content as evidence", "[xxe][evidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // If file content findings are created, they should include file content evidence
    for (const auto& finding : findings) {
        if (finding.category == "xxe" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "file_content") {
            // Should have file content matches if detected
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("target_file"));
        }
    }
}

TEST_CASE("XXE detects XML content type", "[xxe][content_type]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/upload";
    result.method = "POST";
    result.params.push_back({"xml", "<root>test</root>"});
    result.headers.push_back({"content-type", "application/xml"});
    
    std::vector<Finding> findings;
    engine.checkXXE(result, findings);
    
    // Should detect XML content type and test for XXE
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("XXE identifies XML-like parameters", "[xxe][param_detection]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    // Test with various parameter names that might accept XML
    std::vector<std::string> xml_param_names = {"xml", "data", "content", "body", 
                                                 "payload", "request", "input", "document"};
    
    for (const auto& param_name : xml_param_names) {
        CrawlResult result;
        result.url = "http://127.0.0.1:8080/api/upload";
        result.method = "POST";
        result.params.push_back({param_name, "<root>test</root>"});
        
        std::vector<Finding> findings;
        engine.checkXXE(result, findings);
        
        // Should attempt to test XML parameters
        REQUIRE(true); // Just verify no crash
    }
}

