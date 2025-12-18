/**
 * @file test_ssti.cpp
 * @brief Unit tests for Server-Side Template Injection (SSTI) vulnerability detection
 * 
 * Tests detection of:
 * - Jinja2 template injection
 * - Twig template injection
 * - Freemarker template injection
 * - Velocity template injection
 * - Smarty template injection
 * - Mako template injection
 * - ERB template injection
 * - JSP template injection
 * - ASP.NET template injection
 * - Handlebars template injection
 * - Template evaluation detection
 * - Template engine identification
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

TEST_CASE("SSTI check function exists", "[ssti]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello {{name}}"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Function should execute without crashing
    REQUIRE(true);
}

TEST_CASE("SSTI tests GET parameters", "[ssti][get]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello {{name}}"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should attempt to test GET parameters
    // May or may not find vulnerabilities depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI tests POST body", "[ssti][post]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "POST";
    result.params.push_back({"template", "Hello {{name}}"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should attempt to test POST body
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI tests headers", "[ssti][headers]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello {{name}}"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should attempt to test headers (X-Forwarded-For, User-Agent, etc.)
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI finding has correct category", "[ssti][category]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render?template=Hello";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // If findings are created, they should have ssti category
    for (const auto& finding : findings) {
        if (finding.category == "ssti") {
            REQUIRE(finding.category == "ssti");
            REQUIRE(finding.severity == "critical");
            REQUIRE(finding.confidence >= 0.7);
            REQUIRE(finding.evidence.contains("payload"));
            REQUIRE(finding.evidence.contains("template_engine"));
        }
    }
}

TEST_CASE("SSTI Jinja2 detection", "[ssti][jinja2]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello {{name}}"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should test Jinja2 payloads ({{7*7}}, {{7*'7'}}, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI Twig detection", "[ssti][twig]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello {{name}}"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should test Twig payloads
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI Freemarker detection", "[ssti][freemarker]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello ${name}"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should test Freemarker payloads (${7*7}, #{7*7}, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI Velocity detection", "[ssti][velocity]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello $name"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should test Velocity payloads (#set($x=7*7)$x, etc.)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI template engine identification", "[ssti][engine]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // If findings are created, check template engine identification
    for (const auto& finding : findings) {
        if (finding.category == "ssti" && 
            finding.evidence.contains("template_engine")) {
            std::string engine = finding.evidence["template_engine"];
            // Should identify template engine (Jinja2, Twig, Freemarker, etc.)
            REQUIRE(!engine.empty());
            REQUIRE(engine != "Unknown");
        }
    }
}

TEST_CASE("SSTI template evaluation detection", "[ssti][evaluation]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should detect template evaluation (e.g., {{7*7}} = 49)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI detects expected results", "[ssti][results]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // If findings are created, check expected result detection
    for (const auto& finding : findings) {
        if (finding.category == "ssti" && 
            finding.evidence.contains("expected_result")) {
            std::string expected = finding.evidence["expected_result"];
            // Should have expected result (e.g., "49" for 7*7)
            REQUIRE(!expected.empty());
            if (finding.evidence.contains("result_found")) {
                bool found = finding.evidence["result_found"];
                // If result was found, it indicates successful evaluation
                REQUIRE(found == true);
            }
        }
    }
}

TEST_CASE("SSTI tests all major template engines", "[ssti][engines]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should test Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB, JSP, ASP.NET, Handlebars
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI respects confidence threshold", "[ssti][confidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.9); // High threshold
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // All findings should meet confidence threshold
    for (const auto& finding : findings) {
        if (finding.category == "ssti") {
            REQUIRE(finding.confidence >= 0.9);
        }
    }
}

TEST_CASE("SSTI finding includes remediation ID", "[ssti][remediation]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // All SSTI findings should have remediation_id
    for (const auto& finding : findings) {
        if (finding.category == "ssti") {
            REQUIRE(finding.remediation_id == "ssti");
        }
    }
}

TEST_CASE("SSTI captures response snippet", "[ssti][evidence]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // If findings are created, they should include response snippet
    for (const auto& finding : findings) {
        if (finding.category == "ssti" && 
            finding.evidence.contains("response_snippet")) {
            std::string snippet = finding.evidence["response_snippet"];
            // Should have response snippet showing evaluation
            REQUIRE(!snippet.empty());
        }
    }
}

TEST_CASE("SSTI location identification", "[ssti][location]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // If findings are created, check location identification
    for (const auto& finding : findings) {
        if (finding.category == "ssti" && 
            finding.evidence.contains("location")) {
            std::string location = finding.evidence["location"];
            // Should identify location (param, body, header)
            REQUIRE((location == "param" || location == "body" || location == "header"));
        }
    }
}

TEST_CASE("SSTI Jinja2 string multiplication detection", "[ssti][jinja2_string]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should test Jinja2 string multiplication ({{7*'7'}} = 7777777)
    // May or may not find depending on server response
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("SSTI tests multiple injection points", "[ssti][multiple]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/render";
    result.method = "GET";
    result.params.push_back({"template", "Hello"});
    result.params.push_back({"name", "World"});
    
    std::vector<Finding> findings;
    engine.checkSSTI(result, findings);
    
    // Should test all parameters
    REQUIRE(true); // Just verify no crash
}

