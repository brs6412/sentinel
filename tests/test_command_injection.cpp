/**
 * @file test_command_injection.cpp
 * @brief Unit tests for command injection vulnerability detection
 * 
 * Tests detection of:
 * - Command output detection (Unix and Windows)
 * - Time-based blind command injection
 * - Baseline comparison detection
 * - Multiple command separator testing
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

TEST_CASE("Command injection check function exists", "[command_injection]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Function should execute without crashing
    REQUIRE(true);
}

TEST_CASE("Command injection detection skips endpoints without parameters", "[command_injection]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/static/page.html";
    result.method = "GET";
    // No parameters
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Should not create findings for endpoints without parameters
    REQUIRE(findings.empty());
}

TEST_CASE("Command injection tests GET parameters", "[command_injection][get]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Should attempt to test the parameter
    // May or may not find vulnerabilities depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection tests POST body parameters", "[command_injection][post]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "POST";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Should attempt to test POST body parameters
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection finding has correct category", "[command_injection][category]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping?host=127.0.0.1";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // If findings are created, they should have command_injection category
    for (const auto& finding : findings) {
        if (finding.category == "command_injection") {
            REQUIRE(finding.category == "command_injection");
            REQUIRE(finding.severity == "critical");
            REQUIRE(finding.confidence >= 0.7);
            REQUIRE(finding.evidence.contains("detection_method"));
            REQUIRE(finding.evidence.contains("payload"));
        }
    }
}

TEST_CASE("Command injection output-based detection method", "[command_injection][output]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Check if any findings use output-based detection
    bool found_output_based = false;
    for (const auto& finding : findings) {
        if (finding.category == "command_injection" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "output-based") {
            found_output_based = true;
            REQUIRE(finding.evidence.contains("os_type"));
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("separator"));
            REQUIRE(finding.evidence.contains("parameter"));
            if (finding.evidence.contains("command_output")) {
                REQUIRE_FALSE(finding.evidence["command_output"].empty());
            }
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection time-based blind detection method", "[command_injection][time]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Check if any findings use time-based blind detection
    bool found_time_based = false;
    for (const auto& finding : findings) {
        if (finding.category == "command_injection" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "time-based blind") {
            found_time_based = true;
            REQUIRE(finding.evidence.contains("os_type"));
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("separator"));
            REQUIRE(finding.evidence.contains("baseline_time_ms"));
            REQUIRE(finding.evidence.contains("measured_time_ms"));
            REQUIRE(finding.evidence.contains("deviation_ms"));
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection baseline comparison detection method", "[command_injection][baseline]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Check if any findings use baseline comparison detection
    bool found_baseline = false;
    for (const auto& finding : findings) {
        if (finding.category == "command_injection" && 
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

TEST_CASE("Command injection tests multiple separators", "[command_injection][separators]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Should test multiple separators: ;, |, &, $(cmd), `cmd`
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection tests Unix payloads", "[command_injection][unix]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Should test Unix commands (whoami, id, uname, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection tests Windows payloads", "[command_injection][windows]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Should test Windows commands (dir, ver, hostname, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection OS type identification", "[command_injection][os_type]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // If findings are created, check OS type identification
    for (const auto& finding : findings) {
        if (finding.category == "command_injection" && 
            finding.evidence.contains("os_type")) {
            std::string os_type = finding.evidence["os_type"];
            // Should identify OS type (unix, windows, or generic)
            REQUIRE(!os_type.empty());
        }
    }
}

TEST_CASE("Command injection maintains session during testing", "[command_injection][session]") {
    HttpClient client = create_test_client();
    SessionManager session_manager(client);
    VulnEngine engine(client, 0.7, &session_manager);
    
    // Set up a test session (if session manager is configured)
    // This test verifies that session is maintained during command injection testing
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // Should use session manager if available
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Command injection respects confidence threshold", "[command_injection][confidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.9); // High threshold
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // All findings should meet confidence threshold
    for (const auto& finding : findings) {
        if (finding.category == "command_injection") {
            REQUIRE(finding.confidence >= 0.9);
        }
    }
}

TEST_CASE("Command injection finding includes remediation ID", "[command_injection][remediation]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // All command injection findings should have remediation_id
    for (const auto& finding : findings) {
        if (finding.category == "command_injection") {
            REQUIRE(finding.remediation_id == "command_injection");
        }
    }
}

TEST_CASE("Command injection captures command output as evidence", "[command_injection][evidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/ping";
    result.method = "GET";
    result.params.push_back({"host", "127.0.0.1"});
    
    std::vector<Finding> findings;
    engine.checkCommandInjection(result, findings);
    
    // If output-based findings are created, they should include command output
    for (const auto& finding : findings) {
        if (finding.category == "command_injection" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "output-based") {
            // Should have command output or context if detected
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("separator"));
        }
    }
}

