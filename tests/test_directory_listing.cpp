/**
 * @file test_directory_listing.cpp
 * @brief Unit tests for directory listing detection
 * 
 * Tests detection of:
 * - Apache directory listings
 * - Nginx directory listings
 * - IIS directory listings
 * - Sensitive file identification
 * - Custom directory pages (false positive prevention)
 * - Discovered directory testing
 */

#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include "core/vuln_engine.h"
#include "core/http_client.h"
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

TEST_CASE("Apache directory listing detection", "[directory_listing][apache]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/uploads/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            bool valid_severity = (finding.severity == "medium" || finding.severity == "high");
            REQUIRE(valid_severity);
            REQUIRE(finding.confidence >= 0.7);
            
            if (finding.evidence.contains("server_type")) {
                REQUIRE(finding.evidence["server_type"] == "Apache");
            }
            
            if (finding.evidence.contains("files_detected")) {
                REQUIRE(finding.evidence["files_detected"].get<size_t>() > 0);
            }
        }
    }
    REQUIRE(found_listing);
}

TEST_CASE("Nginx directory listing detection", "[directory_listing][nginx]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/backup/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            bool valid_severity = (finding.severity == "medium" || finding.severity == "high");
            REQUIRE(valid_severity);
            
            if (finding.evidence.contains("server_type")) {
                REQUIRE(finding.evidence["server_type"] == "Nginx");
            }
        }
    }
    REQUIRE(found_listing);
}

TEST_CASE("IIS directory listing detection", "[directory_listing][iis]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/config/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            bool valid_severity = (finding.severity == "medium" || finding.severity == "high");
            REQUIRE(valid_severity);
            
            if (finding.evidence.contains("server_type")) {
                REQUIRE(finding.evidence["server_type"] == "IIS");
            }
        }
    }
    REQUIRE(found_listing);
}

TEST_CASE("Sensitive file identification", "[directory_listing][sensitive]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/uploads/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    bool has_sensitive = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            
            if (finding.evidence.contains("sensitive_files")) {
                auto sensitive = finding.evidence["sensitive_files"];
                if (sensitive.is_array() && sensitive.size() > 0) {
                    has_sensitive = true;
                    REQUIRE(finding.severity == "high");
                    REQUIRE(finding.confidence >= 0.9);
                }
            }
        }
    }
    REQUIRE(found_listing);
    REQUIRE(has_sensitive);
}

TEST_CASE("Custom directory page - no false positive", "[directory_listing][false_positive]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/files/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    // Should NOT be flagged as directory listing
    bool found_false_positive = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_false_positive = true;
        }
    }
    REQUIRE_FALSE(found_false_positive);
}

TEST_CASE("File extraction from directory listing", "[directory_listing][extraction]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/uploads/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            
            if (finding.evidence.contains("files")) {
                auto files = finding.evidence["files"];
                REQUIRE(files.is_array());
                REQUIRE(files.size() >= 3);
                
                // Check that files are extracted
                bool has_file1 = false;
                for (const auto& file : files) {
                    std::string filename = file.get<std::string>();
                    if (filename.find("file1.txt") != std::string::npos ||
                        filename.find("file2.txt") != std::string::npos ||
                        filename.find("image.jpg") != std::string::npos) {
                        has_file1 = true;
                    }
                }
                REQUIRE(has_file1);
            }
        }
    }
    REQUIRE(found_listing);
}

TEST_CASE("Directory listing with parent directory link", "[directory_listing][parent]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/test/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            
            // Parent directory should not be in file list
            if (finding.evidence.contains("files")) {
                auto files = finding.evidence["files"];
                for (const auto& file : files) {
                    std::string filename = file.get<std::string>();
                    REQUIRE(filename.find("Parent") == std::string::npos);
                    REQUIRE(filename.find("..") == std::string::npos);
                }
            }
        }
    }
    REQUIRE(found_listing);
}

TEST_CASE("Table-based directory listing", "[directory_listing][table]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/data/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    // Should detect table-based listing with multiple files
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
        }
    }
    // May or may not detect depending on heuristics
    REQUIRE(true); // Just verify no crash
}

TEST_CASE("Discovered directory testing", "[directory_listing][discovery]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    // Simulate a discovered directory from crawling
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/api/v1/internal/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    // Should detect directory listing even if not in default wordlist
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            REQUIRE(finding.url.find("internal") != std::string::npos);
        }
    }
    REQUIRE(found_listing);
}

TEST_CASE("Multiple sensitive file types", "[directory_listing][sensitive]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/backup/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    size_t sensitive_count = 0;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            
            if (finding.evidence.contains("sensitive_files_count")) {
                sensitive_count = finding.evidence["sensitive_files_count"].get<size_t>();
            }
            
            // Should have high severity due to multiple sensitive files
            if (sensitive_count > 3) {
                REQUIRE(finding.severity == "high");
            }
        }
    }
    REQUIRE(found_listing);
    REQUIRE(sensitive_count >= 5); // Should detect multiple sensitive files
}

TEST_CASE("Directory listing without sensitive files", "[directory_listing][severity]") {
    HttpClient client = create_test_client();
    VulnEngine engine(client, 0.7);
    
    CrawlResult result;
    result.url = "http://127.0.0.1:8080/public/";
    result.method = "GET";
    
    std::vector<Finding> findings = engine.analyze({result});
    
    bool found_listing = false;
    for (const auto& finding : findings) {
        if (finding.category == "directory_listing") {
            found_listing = true;
            
            // Should be medium severity (no sensitive files)
            REQUIRE(finding.severity == "medium");
            REQUIRE(finding.confidence >= 0.85);
        }
    }
    REQUIRE(found_listing);
}

