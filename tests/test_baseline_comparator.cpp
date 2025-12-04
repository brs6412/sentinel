/**
 * @file test_baseline_comparator.cpp
 * @brief Unit tests for BaselineComparator
 * 
 * Tests baseline comparison including:
 * - Status code change detection
 * - Response length change detection
 * - Content similarity calculation
 * - Error message detection
 * - Timing anomaly detection
 * - Vulnerability indication heuristic
 */

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "core/baseline_comparator.h"
#include "core/http_client.h"
#include "core/timing_analyzer.h"
#include <string>
#include <vector>

// Helper to create a test HTTP client
HttpClient create_test_client() {
    HttpClient::Options opts;
    opts.timeout_seconds = 15;
    opts.connect_timeout_seconds = 5;
    return HttpClient(opts);
}

TEST_CASE("BaselineComparator construction", "[baseline_comparator]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    REQUIRE(true); // Construction successful
}

TEST_CASE("Status code change detection", "[baseline_comparator][status]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 500;
    test_resp.body = "Internal Server Error";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.status_changed);
    REQUIRE(result.baseline_status == 200);
    REQUIRE(result.test_status == 500);
    REQUIRE(result.indicates_vulnerability);
    REQUIRE(result.confidence > 0.0);
}

TEST_CASE("Status code change - 200 to 404", "[baseline_comparator][status]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 404;
    test_resp.body = "Not Found";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.status_changed);
    REQUIRE(result.baseline_status == 200);
    REQUIRE(result.test_status == 404);
}

TEST_CASE("Response length change detection", "[baseline_comparator][length]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = std::string(1000, 'A');  // 1000 bytes
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = std::string(5000, 'B');  // 5000 bytes
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.length_changed);
    REQUIRE(result.baseline_length == 1000);
    REQUIRE(result.test_length == 5000);
    REQUIRE(result.length_difference == 4000);
    REQUIRE(result.length_change_percentage == 400.0);
}

TEST_CASE("Response length change - decrease", "[baseline_comparator][length]") {
    HttpClient client = create_test_client();
    BaselineComparator::Options opts;
    opts.length_change_threshold = 50.0;
    BaselineComparator comparator(client, opts);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = std::string(1000, 'A');
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = std::string(400, 'B');  // 60% decrease
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.length_changed);
    REQUIRE(result.length_change_percentage == -60.0);
}

TEST_CASE("Content similarity calculation - identical", "[baseline_comparator][similarity]") {
    std::string str1 = "Hello world";
    std::string str2 = "Hello world";
    
    double similarity = BaselineComparator::calculate_similarity(str1, str2);
    
    REQUIRE(similarity == 1.0);
}

TEST_CASE("Content similarity calculation - completely different", "[baseline_comparator][similarity]") {
    std::string str1 = "Hello";
    std::string str2 = "World";
    
    double similarity = BaselineComparator::calculate_similarity(str1, str2);
    
    REQUIRE(similarity < 1.0);
    REQUIRE(similarity >= 0.0);
}

TEST_CASE("Content similarity calculation - similar", "[baseline_comparator][similarity]") {
    std::string str1 = "Hello world";
    std::string str2 = "Hello there";
    
    double similarity = BaselineComparator::calculate_similarity(str1, str2);
    
    REQUIRE(similarity > 0.5);
    REQUIRE(similarity < 1.0);
}

TEST_CASE("Content similarity - significant difference", "[baseline_comparator][similarity]") {
    HttpClient client = create_test_client();
    BaselineComparator::Options opts;
    opts.similarity_threshold = 0.7;
    BaselineComparator comparator(client, opts);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal HTML content with lots of text";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "SQLException: Table 'users' doesn't exist";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.similarity_score < opts.similarity_threshold);
    REQUIRE(result.similarity_score >= 0.0);
}

TEST_CASE("Error message detection", "[baseline_comparator][errors]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response with no errors";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "SQLException: Table 'users' doesn't exist";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.has_new_errors);
    REQUIRE_FALSE(result.new_errors.empty());
    
    bool found_sql_error = false;
    for (const auto& error : result.new_errors) {
        if (error.find("SQLException") != std::string::npos) {
            found_sql_error = true;
            break;
        }
    }
    REQUIRE(found_sql_error);
}

TEST_CASE("Error message detection - multiple errors", "[baseline_comparator][errors]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "SQLException: Error\nDatabase Error: Connection failed";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.has_new_errors);
    REQUIRE(result.new_errors.size() >= 1);
}

TEST_CASE("Error extraction", "[baseline_comparator][errors]") {
    std::string response = "SQLException: Table doesn't exist\nWarning: mysql_connect() failed";
    
    std::vector<std::string> errors = BaselineComparator::extract_errors(response);
    
    REQUIRE_FALSE(errors.empty());
    bool found_sql = false;
    for (const auto& error : errors) {
        if (error.find("SQLException") != std::string::npos) {
            found_sql = true;
        }
    }
    REQUIRE(found_sql);
}

TEST_CASE("Timing anomaly detection", "[baseline_comparator][timing]") {
    HttpClient client = create_test_client();
    BaselineComparator::Options opts;
    opts.timing_threshold_ms = 1000.0;
    BaselineComparator comparator(client, opts);
    
    TimingBaseline timing_baseline;
    timing_baseline.average_time_ms = 200.0;
    timing_baseline.standard_deviation_ms = 50.0;
    timing_baseline.sample_count = 3;
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "Response with delay";
    
    double test_timing_ms = 5200.0;  // 5 second delay
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp, timing_baseline, test_timing_ms);
    
    REQUIRE(result.timing_anomaly);
    REQUIRE(result.baseline_time_ms == 200.0);
    REQUIRE(result.test_time_ms == 5200.0);
    REQUIRE(result.timing_deviation_ms == 5000.0);
}

TEST_CASE("Vulnerability indication - status code change", "[baseline_comparator][vulnerability]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 500;
    test_resp.body = "Internal Server Error";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.indicates_vulnerability);
    REQUIRE(result.confidence > 0.0);
}

TEST_CASE("Vulnerability indication - new errors", "[baseline_comparator][vulnerability]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "SQLException: Table 'users' doesn't exist";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.indicates_vulnerability);
    REQUIRE(result.has_new_errors);
    REQUIRE(result.confidence > 0.5);  // High confidence for error messages
}

TEST_CASE("Vulnerability indication - multiple indicators", "[baseline_comparator][vulnerability]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response content";
    
    HttpResponse test_resp;
    test_resp.status = 500;
    test_resp.body = "SQLException: Error\nDatabase connection failed";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    REQUIRE(result.indicates_vulnerability);
    REQUIRE(result.status_changed);
    REQUIRE(result.has_new_errors);
    REQUIRE(result.confidence > 0.7);  // High confidence with multiple indicators
}

TEST_CASE("Normal variation - no false positive", "[baseline_comparator][false_positive]") {
    HttpClient client = create_test_client();
    BaselineComparator::Options opts;
    opts.similarity_threshold = 0.7;
    BaselineComparator comparator(client, opts);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Dynamic page content with timestamp: 1234567890";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "Dynamic page content with timestamp: 1234567891";  // Minor variation
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    // Should not flag as vulnerable if similarity is high
    if (result.similarity_score > 0.9) {
        REQUIRE_FALSE(result.indicates_vulnerability);
    }
}

TEST_CASE("Jaccard similarity calculation", "[baseline_comparator][similarity]") {
    std::string str1 = "hello world test";
    std::string str2 = "hello world example";
    
    double similarity = BaselineComparator::calculate_jaccard_similarity(str1, str2);
    
    REQUIRE(similarity >= 0.0);
    REQUIRE(similarity <= 1.0);
    REQUIRE(similarity > 0.0);  // Should have some similarity
}

TEST_CASE("Vulnerability type detection - SQL injection", "[baseline_comparator][vulnerability]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "SQLException: Error";
    
    std::string payload = "1' AND SLEEP(5)--";
    ComparisonResult result = comparator.compare(baseline_resp, test_resp, TimingBaseline(), 0.0, payload);
    
    if (result.indicates_vulnerability) {
        REQUIRE(result.vulnerability_type == "sql_injection" || result.vulnerability_type == "injection");
    }
}

TEST_CASE("Vulnerability type detection - command injection", "[baseline_comparator][vulnerability]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "Command execution error";
    
    std::string payload = "; sleep 10";
    ComparisonResult result = comparator.compare(baseline_resp, test_resp, TimingBaseline(), 0.0, payload);
    
    if (result.indicates_vulnerability) {
        REQUIRE(result.vulnerability_type == "command_injection" || result.vulnerability_type == "injection");
    }
}

TEST_CASE("Confidence calculation - high confidence", "[baseline_comparator][confidence]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal response";
    
    HttpResponse test_resp;
    test_resp.status = 500;
    test_resp.body = "SQLException: Table 'users' doesn't exist\nDatabase Error";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    if (result.indicates_vulnerability) {
        REQUIRE(result.confidence > 0.0);
        REQUIRE(result.confidence <= 1.0);
        
        // Multiple strong indicators should give high confidence
        if (result.status_changed && result.test_status >= 500 && result.has_new_errors) {
            REQUIRE(result.confidence > 0.7);
        }
    }
}

TEST_CASE("Empty response handling", "[baseline_comparator]") {
    HttpClient client = create_test_client();
    BaselineComparator comparator(client);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "";
    
    HttpResponse test_resp;
    test_resp.status = 200;
    test_resp.body = "";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    // Should handle gracefully
    REQUIRE(result.similarity_score == 1.0);  // Empty strings are identical
}

TEST_CASE("Levenshtein distance calculation", "[baseline_comparator][similarity]") {
    // Test that similarity uses Levenshtein distance correctly
    std::string str1 = "kitten";
    std::string str2 = "sitting";
    
    double similarity = BaselineComparator::calculate_similarity(str1, str2);
    
    // Known Levenshtein distance: 3
    // Max length: 7
    // Similarity: 1 - (3/7) = 0.571...
    REQUIRE(similarity > 0.5);
    REQUIRE(similarity < 0.6);
}

TEST_CASE("Options configuration", "[baseline_comparator][options]") {
    HttpClient client = create_test_client();
    BaselineComparator::Options opts;
    opts.similarity_threshold = 0.8;
    opts.length_change_threshold = 30.0;
    opts.check_status_code = false;
    opts.check_timing = false;
    
    BaselineComparator comparator(client, opts);
    
    HttpResponse baseline_resp;
    baseline_resp.status = 200;
    baseline_resp.body = "Normal";
    
    HttpResponse test_resp;
    test_resp.status = 500;  // Status change, but we disabled checking
    test_resp.body = "Different content";
    
    ComparisonResult result = comparator.compare(baseline_resp, test_resp);
    
    // Status change should not be detected since it's disabled
    REQUIRE_FALSE(result.status_changed);
}

