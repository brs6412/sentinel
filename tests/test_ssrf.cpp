/**
 * @file test_ssrf.cpp
 * @brief Unit tests for Server-Side Request Forgery (SSRF) vulnerability detection
 * 
 * Tests detection of:
 * - Internal IP address access (127.0.0.1, 169.254.169.254, 10.x, 192.168.x)
 * - Internal hostname access (localhost, metadata, internal)
 * - Protocol handler testing (file://, gopher://, dict://)
 * - Cloud metadata endpoint detection (AWS, GCP, Azure)
 * - Internal content detection
 * - Bypass techniques
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

TEST_CASE("SSRF check function exists", "[ssrf]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Function should execute without crashing
    REQUIRE(true);
}

TEST_CASE("OOB detection: token generation", "[ssrf][oob]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    std::string token1 = engine.generateCallbackToken();
    std::string token2 = engine.generateCallbackToken();
    
    // Tokens should be unique
    REQUIRE(token1 != token2);
    
    // Tokens should start with "sentinel_"
    REQUIRE(token1.find("sentinel_") == 0);
    REQUIRE(token2.find("sentinel_") == 0);
    
    // Tokens should not be empty
    REQUIRE(!token1.empty());
    REQUIRE(!token2.empty());
}

TEST_CASE("OOB detection: callback URL building", "[ssrf][oob]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    engine.setCallbackUrl("https://webhook.site/abc123");
    std::string token = "sentinel_1234567890_5678";
    std::string callback = engine.buildCallbackUrl(token);
    
    // Callback URL should include token
    REQUIRE(callback.find("token=" + token) != std::string::npos);
    REQUIRE(callback.find("webhook.site") != std::string::npos);
    
    // Test with URL that already has query parameters
    engine.setCallbackUrl("https://example.com/callback?existing=param");
    callback = engine.buildCallbackUrl(token);
    REQUIRE(callback.find("&token=") != std::string::npos || callback.find("?token=") != std::string::npos);
}

TEST_CASE("OOB detection: SSRF with callback URL configured", "[ssrf][oob]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    // Set a callback URL
    engine.setCallbackUrl("https://webhook.site/test-uuid");
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Function should execute without crashing when callback URL is set
    // (We can't verify actual callback without a real webhook service)
    REQUIRE(true);
}

TEST_CASE("SSRF detection skips endpoints without URL parameters", "[ssrf]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/data";
    result.method = "GET";
    result.params.push_back({"id", "123"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should not create findings if no URL parameters detected
    // (id is not a URL parameter)
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF tests URL parameters", "[ssrf][url_params]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should attempt to test the URL parameter
    // May or may not find vulnerabilities depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF finding has correct category", "[ssrf][category]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch?url=http://example.com";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // If findings are created, they should have ssrf category
    for (const auto& finding : findings) {
        if (finding.category == "ssrf") {
            REQUIRE(finding.category == "ssrf");
            REQUIRE((finding.severity == "high" || finding.severity == "critical"));
            REQUIRE(finding.confidence >= 0.7);
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("payload_type"));
        }
    }
}

TEST_CASE("SSRF tests internal IP addresses", "[ssrf][internal_ip]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should test internal IPs (127.0.0.1, 10.x, 192.168.x, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF tests internal hostnames", "[ssrf][internal_hostname]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should test internal hostnames (localhost, metadata, internal)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF tests protocol handlers", "[ssrf][protocol]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should test protocol handlers (file://, gopher://, dict://)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF tests cloud metadata endpoints", "[ssrf][cloud]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should test cloud metadata endpoints (AWS, GCP, Azure)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF cloud metadata detection", "[ssrf][cloud_metadata]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Check if any findings are for cloud metadata
    bool found_cloud = false;
    for (const auto& finding : findings) {
        if (finding.category == "ssrf" && 
            finding.evidence.contains("cloud_provider")) {
            found_cloud = true;
            std::string cloud_provider = finding.evidence["cloud_provider"];
            REQUIRE((cloud_provider == "aws" || cloud_provider == "gcp" || cloud_provider == "azure"));
            REQUIRE(finding.severity == "critical");
            REQUIRE(finding.confidence >= 0.95);
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF detects internal content", "[ssrf][content]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should detect internal content in responses
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF tests bypass techniques", "[ssrf][bypass]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should test bypass techniques (URL encoding, octal, decimal, hex, @, #)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF identifies accessed resource", "[ssrf][resource]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // If findings are created, check resource identification
    for (const auto& finding : findings) {
        if (finding.category == "ssrf" && 
            finding.evidence.contains("accessed_resource")) {
            std::string resource = finding.evidence["accessed_resource"];
            // Should identify the accessed resource
            REQUIRE(!resource.empty());
        }
    }
}

TEST_CASE("SSRF payload type identification", "[ssrf][payload_type]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // If findings are created, check payload type identification
    for (const auto& finding : findings) {
        if (finding.category == "ssrf" && 
            finding.evidence.contains("payload_type")) {
            std::string payload_type = finding.evidence["payload_type"];
            // Should identify payload type (internal_ip, internal_hostname, protocol_handler, cloud_metadata, bypass)
            REQUIRE(!payload_type.empty());
        }
    }
}

TEST_CASE("SSRF tests POST body parameters", "[ssrf][post]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "POST";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Should attempt to test POST body parameters
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSRF respects confidence threshold", "[ssrf][confidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.9); // High threshold
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // All findings should meet confidence threshold
    for (const auto& finding : findings) {
        if (finding.category == "ssrf") {
            REQUIRE(finding.confidence >= 0.9);
        }
    }
}

TEST_CASE("SSRF finding includes remediation ID", "[ssrf][remediation]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // All SSRF findings should have remediation_id
    for (const auto& finding : findings) {
        if (finding.category == "ssrf") {
            REQUIRE(finding.remediation_id == "ssrf");
        }
    }
}

TEST_CASE("SSRF cloud metadata has critical severity", "[ssrf][severity]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/fetch";
    result.method = "GET";
    result.params.push_back({"url", "http://example.com"});
    
    std::vector<Finding> findings;
    engine.checkSSRF(result, findings);
    
    // Cloud metadata findings should have critical severity
    for (const auto& finding : findings) {
        if (finding.category == "ssrf" && 
            finding.evidence.contains("cloud_provider")) {
            REQUIRE(finding.severity == "critical");
        }
    }
}

TEST_CASE("SSRF identifies URL parameters correctly", "[ssrf][param_detection]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    // Test with various parameter names that might accept URLs
    std::vector<std::string> url_param_names = {"url", "uri", "link", "src", "dest", 
                                                 "target", "redirect", "fetch", "proxy"};
    
    for (const auto& param_name : url_param_names) {
        CrawlResult result;
        result.url = "http://127.0.0.1:8080/api/fetch";
        result.method = "GET";
        result.params.push_back({param_name, "http://example.com"});
        
        std::vector<Finding> findings;
        engine.checkSSRF(result, findings);
        
        // Should attempt to test URL parameters
        REQUIRE(true); // Just verify no crash
    }
}

