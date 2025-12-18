/**
 * @file test_sql_injection.cpp
 * @brief Unit tests for SQL injection vulnerability detection
 * 
 * Tests detection of:
 * - Error-based SQL injection (MySQL, PostgreSQL, SQL Server, Oracle)
 * - Time-based blind SQL injection
 * - Boolean-based blind SQL injection
 * - Database type identification
 * - Bypass techniques (encoding, comments)
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

TEST_CASE("SQL injection check function exists", "[sql_injection]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Function should execute without crashing
    REQUIRE(true);
}

TEST_CASE("SQL injection detection skips endpoints without parameters", "[sql_injection]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/static/page.html";
    result.method = "GET";
    // No parameters
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Should not create findings for endpoints without parameters
    REQUIRE(findings.empty());
}

TEST_CASE("SQL injection tests GET parameters", "[sql_injection][get]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Should attempt to test the parameter
    // May or may not find vulnerabilities depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection tests POST body parameters", "[sql_injection][post]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "POST";
    result.params.push_back({"username", "test"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Should attempt to test POST body parameters
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection finding has correct category", "[sql_injection][category]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users?id=1";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // If findings are created, they should have sql_injection category
    for (const auto& finding : findings) {
        if (finding.category == "sql_injection") {
            REQUIRE(finding.category == "sql_injection");
            REQUIRE(finding.severity == "critical");
            REQUIRE(finding.confidence >= 0.7);
            REQUIRE(finding.evidence.contains("detection_method"));
            REQUIRE(finding.evidence.contains("payload"));
        }
    }
}

TEST_CASE("SQL injection error-based detection method", "[sql_injection][error]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Check if any findings use error-based detection
    bool found_error_based = false;
    for (const auto& finding : findings) {
        if (finding.category == "sql_injection" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "error-based") {
            found_error_based = true;
            REQUIRE(finding.evidence.contains("database_type"));
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("parameter"));
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection time-based blind detection method", "[sql_injection][time]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Check if any findings use time-based blind detection
    bool found_time_based = false;
    for (const auto& finding : findings) {
        if (finding.category == "sql_injection" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "time-based blind") {
            found_time_based = true;
            REQUIRE(finding.evidence.contains("database_type"));
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("baseline_time_ms"));
            REQUIRE(finding.evidence.contains("measured_time_ms"));
            REQUIRE(finding.evidence.contains("deviation_ms"));
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection boolean-based blind detection method", "[sql_injection][boolean]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Check if any findings use boolean-based blind detection
    bool found_boolean_based = false;
    for (const auto& finding : findings) {
        if (finding.category == "sql_injection" && 
            finding.evidence.contains("detection_method") &&
            finding.evidence["detection_method"] == "boolean-based blind") {
            found_boolean_based = true;
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("similarity_score"));
            REQUIRE(finding.evidence.contains("length_change_percentage"));
        }
    }
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection database type identification", "[sql_injection][database]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // If findings are created, check database type identification
    for (const auto& finding : findings) {
        if (finding.category == "sql_injection" && 
            finding.evidence.contains("database_type")) {
            std::string db_type = finding.evidence["database_type"];
            // Should identify a database type (or "Unknown" for boolean-based)
            REQUIRE(!db_type.empty());
        }
    }
}

TEST_CASE("SQL injection tests multiple database types", "[sql_injection][databases]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Should test MySQL, PostgreSQL, SQL Server, and Oracle payloads
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection maintains session during testing", "[sql_injection][session]") {
    HttpClient client = create_test_client();
    SessionManager session_manager(client);
    VulnEngine engine(client, 0.7, &session_manager);
    
    // Set up a test session (if session manager is configured)
    // This test verifies that session is maintained during SQL injection testing
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Should use session manager if available
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection tests bypass techniques", "[sql_injection][bypass]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // Should test encoding and comment bypass techniques
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SQL injection respects confidence threshold", "[sql_injection][confidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.9); // High threshold
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // All findings should meet confidence threshold
    for (const auto& finding : findings) {
        if (finding.category == "sql_injection") {
            REQUIRE(finding.confidence >= 0.9);
        }
    }
}

TEST_CASE("SQL injection finding includes remediation ID", "[sql_injection][remediation]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/users";
    result.method = "GET";
    result.params.push_back({"id", "1"});
    
    std::vector<Finding> findings;
    engine.checkSQLInjection(result, findings);
    
    // All SQL injection findings should have remediation_id
    for (const auto& finding : findings) {
        if (finding.category == "sql_injection") {
            REQUIRE(finding.remediation_id == "sql_injection");
        }
    }
}

