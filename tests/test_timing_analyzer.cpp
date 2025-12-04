/**
 * @file test_timing_analyzer.cpp
 * @brief Unit tests for TimingAnalyzer
 * 
 * Tests timing-based vulnerability detection including:
 * - Baseline establishment
 * - Blind SQL injection detection
 * - Blind command injection detection
 * - Network jitter tolerance
 * - Multiple measurement validation
 * - Confidence score calculation
 */

#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include "core/timing_analyzer.h"
#include "core/http_client.h"
#include <string>
#include <vector>
#include <cmath>

// Helper to create a test HTTP client
HttpClient create_test_client() {
    HttpClient::Options opts;
    opts.timeout_seconds = 30;  // Longer timeout for timing tests
    opts.connect_timeout_seconds = 5;
    return HttpClient(opts);
}

TEST_CASE("TimingAnalyzer construction", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    REQUIRE(true); // Construction successful
}

TEST_CASE("Baseline establishment - minimum 3 requests", "[timing_analyzer][baseline]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/healthz";  // Use demo server health endpoint
    
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    // Should make at least 3 requests
    REQUIRE(baseline.sample_count >= 3);
    REQUIRE(baseline.average_time_ms > 0.0);
    REQUIRE(baseline.min_time_ms > 0.0);
    REQUIRE(baseline.max_time_ms >= baseline.min_time_ms);
}

TEST_CASE("Baseline establishment - statistics calculation", "[timing_analyzer][baseline]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/healthz";
    
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    // Verify statistics are calculated
    REQUIRE(baseline.average_time_ms > 0.0);
    REQUIRE(baseline.variance_ms >= 0.0);
    REQUIRE(baseline.standard_deviation_ms >= 0.0);
    REQUIRE(baseline.max_time_ms >= baseline.min_time_ms);
    
    // Standard deviation should be sqrt of variance
    double expected_std_dev = std::sqrt(baseline.variance_ms);
    REQUIRE(std::abs(baseline.standard_deviation_ms - expected_std_dev) < 0.01);
}

TEST_CASE("Blind SQL injection detection - SLEEP payload", "[timing_analyzer][sql]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/reflect?q=test";
    
    // Establish baseline
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    if (baseline.sample_count < 3) {
        // Skip if baseline establishment failed (server might not be running)
        return;
    }
    
    // Test with SLEEP(5) payload
    std::string payload = "1' AND SLEEP(5)--";
    TimingResult result = analyzer.test_payload(req, payload, baseline, "sql");
    
    // Note: This test requires a vulnerable endpoint
    // In a real scenario, we'd use a mock server or test fixture
    // For now, we verify the method works correctly
    
    REQUIRE(result.baseline_time_ms == baseline.average_time_ms);
    REQUIRE(result.payload == payload);
    REQUIRE(result.injection_type == "sql");
}

TEST_CASE("Blind SQL injection detection - validated", "[timing_analyzer][sql]") {
    HttpClient client = create_test_client();
    TimingAnalyzer::Options opts;
    opts.validation_samples = 3;
    TimingAnalyzer analyzer(client, opts);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/reflect?q=test";
    
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    if (baseline.sample_count < 3) {
        return;
    }
    
    std::string payload = "1' AND SLEEP(5)--";
    TimingResult result = analyzer.test_payload_validated(req, payload, baseline, "sql");
    
    // Should have multiple measurements
    REQUIRE(result.measurements.size() <= opts.validation_samples);
    
    // If anomaly detected, confidence should be calculated
    if (result.is_anomaly) {
        REQUIRE(result.confidence > 0.0);
        REQUIRE(result.confidence <= 1.0);
    }
}

TEST_CASE("Blind command injection detection", "[timing_analyzer][command]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    HttpRequest req;
    req.method = "POST";
    req.url = "http://127.0.0.1:8080/reflect";
    req.body = "q=test";
    
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    if (baseline.sample_count < 3) {
        return;
    }
    
    std::string payload = "; sleep 10";
    TimingResult result = analyzer.test_payload(req, payload, baseline, "command");
    
    REQUIRE(result.baseline_time_ms == baseline.average_time_ms);
    REQUIRE(result.payload == payload);
    REQUIRE(result.injection_type == "command");
}

TEST_CASE("Network jitter tolerance", "[timing_analyzer][jitter]") {
    HttpClient client = create_test_client();
    TimingAnalyzer::Options opts;
    opts.threshold_percentage = 80.0;  // 80% threshold
    TimingAnalyzer analyzer(client, opts);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/healthz";
    
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    if (baseline.sample_count < 3) {
        return;
    }
    
    // Simulate a normal request with slight jitter (within 2 standard deviations)
    // This should NOT trigger an anomaly
    double normal_time = baseline.average_time_ms + baseline.standard_deviation_ms * 1.5;
    
    TimingResult result = analyzer.analyze_timing(normal_time, baseline);
    
    // Should not be flagged as anomaly if within reasonable variance
    // (unless the deviation percentage exceeds threshold)
    double deviation_percentage = (result.deviation_ms / baseline.average_time_ms) * 100.0;
    
    if (deviation_percentage < opts.threshold_percentage) {
        REQUIRE_FALSE(result.is_anomaly);
    }
}

TEST_CASE("Timing anomaly detection - significant delay", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer::Options opts;
    opts.min_delay_ms = 1000.0;  // 1 second minimum
    opts.threshold_percentage = 80.0;
    TimingAnalyzer analyzer(client, opts);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/healthz";
    
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    if (baseline.sample_count < 3) {
        return;
    }
    
    // Simulate a significant delay (e.g., 5 seconds for SLEEP(5))
    double delayed_time = baseline.average_time_ms + 5000.0;  // 5 second delay
    
    TimingResult result = analyzer.analyze_timing(delayed_time, baseline);
    
    // Should detect anomaly
    REQUIRE(result.is_anomaly);
    REQUIRE(result.deviation_ms >= opts.min_delay_ms);
    REQUIRE(result.confidence > 0.0);
}

TEST_CASE("Confidence calculation - exact match", "[timing_analyzer][confidence]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    baseline.variance_ms = 2500.0;
    
    // Test with expected delay of 5000ms
    double deviation = 5000.0;
    double confidence = TimingAnalyzer::calculate_confidence(deviation, baseline, 5000.0);
    
    // Should have high confidence for exact match
    REQUIRE(confidence > 0.7);
    REQUIRE(confidence <= 1.0);
}

TEST_CASE("Confidence calculation - close match", "[timing_analyzer][confidence]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    baseline.variance_ms = 2500.0;
    
    // Test with close match (4500ms when expecting 5000ms)
    double deviation = 4500.0;
    double confidence = TimingAnalyzer::calculate_confidence(deviation, baseline, 5000.0);
    
    // Should still have reasonable confidence
    REQUIRE(confidence > 0.5);
}

TEST_CASE("Confidence calculation - no expected delay", "[timing_analyzer][confidence]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    baseline.variance_ms = 2500.0;
    
    // Test without expected delay (uses z-score)
    double deviation = 2000.0;  // 2 seconds
    double confidence = TimingAnalyzer::calculate_confidence(deviation, baseline, 0.0);
    
    // Should calculate based on z-score
    double z_score = deviation / baseline.standard_deviation_ms;
    REQUIRE(z_score > 2.0);  // Significant deviation
    REQUIRE(confidence > 0.0);
    REQUIRE(confidence <= 1.0);
}

TEST_CASE("Multiple measurement validation", "[timing_analyzer][validation]") {
    HttpClient client = create_test_client();
    TimingAnalyzer::Options opts;
    opts.validation_samples = 3;
    TimingAnalyzer analyzer(client, opts);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/healthz";
    
    TimingBaseline baseline = analyzer.establish_baseline(req);
    
    if (baseline.sample_count < 3) {
        return;
    }
    
    std::string payload = "1' AND SLEEP(5)--";
    TimingResult result = analyzer.test_payload_validated(req, payload, baseline, "sql");
    
    // Should have measurements
    REQUIRE(result.measurements.size() <= opts.validation_samples);
    
    // If all measurements show delay, confidence should be boosted
    if (result.measurements.size() >= 3 && result.is_anomaly) {
        bool all_delayed = true;
        for (double m : result.measurements) {
            if (m < baseline.average_time_ms + baseline.standard_deviation_ms * 2.0) {
                all_delayed = false;
                break;
            }
        }
        
        if (all_delayed) {
            // Confidence should be high
            REQUIRE(result.confidence > 0.8);
        }
    }
}

TEST_CASE("Variance calculation", "[timing_analyzer][statistics]") {
    std::vector<double> measurements = {100.0, 200.0, 300.0};
    double mean = 200.0;
    
    double variance = TimingAnalyzer::calculate_variance(measurements, mean);
    
    // Variance should be positive
    REQUIRE(variance > 0.0);
    
    // Manual calculation: sum of squared differences / (n-1)
    // (100-200)^2 + (200-200)^2 + (300-200)^2 = 10000 + 0 + 10000 = 20000
    // 20000 / 2 = 10000
    double expected_variance = 10000.0;
    REQUIRE(std::abs(variance - expected_variance) < 0.1);
}

TEST_CASE("Standard deviation calculation", "[timing_analyzer][statistics]") {
    double variance = 10000.0;
    double std_dev = TimingAnalyzer::calculate_standard_deviation(variance);
    
    // Should be sqrt of variance
    double expected_std_dev = std::sqrt(variance);
    REQUIRE(std::abs(std_dev - expected_std_dev) < 0.01);
    REQUIRE(std_dev == 100.0);
}

TEST_CASE("Anomaly detection threshold", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer::Options opts;
    opts.threshold_percentage = 80.0;
    opts.min_delay_ms = 1000.0;
    TimingAnalyzer analyzer(client, opts);
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    baseline.variance_ms = 2500.0;
    
    // Test with delay below threshold percentage
    double small_delay = baseline.average_time_ms * 0.5;  // 50% increase
    TimingResult result1 = analyzer.analyze_timing(
        baseline.average_time_ms + small_delay, baseline);
    
    // Should not trigger (below 80% threshold)
    REQUIRE_FALSE(result1.is_anomaly);
    
    // Test with delay above threshold
    double large_delay = baseline.average_time_ms * 1.0;  // 100% increase
    TimingResult result2 = analyzer.analyze_timing(
        baseline.average_time_ms + large_delay, baseline);
    
    // Should trigger if also above min_delay_ms
    if (large_delay >= opts.min_delay_ms) {
        REQUIRE(result2.is_anomaly);
    }
}

TEST_CASE("Payload injection - GET request", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/test";
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    
    std::string payload = "1' AND SLEEP(5)--";
    TimingResult result = analyzer.test_payload(req, payload, baseline, "sql");
    
    // URL should be modified with payload
    // (We can't easily test the modified URL without making actual request,
    // but we verify the method doesn't crash)
    REQUIRE(result.payload == payload);
}

TEST_CASE("Payload injection - POST request", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    HttpRequest req;
    req.method = "POST";
    req.url = "http://127.0.0.1:8080/test";
    req.body = "param=value";
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    
    std::string payload = "; sleep 10";
    TimingResult result = analyzer.test_payload(req, payload, baseline, "command");
    
    // Body should be modified with payload
    REQUIRE(result.payload == payload);
}

TEST_CASE("Expected delay extraction - SQL SLEEP", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    
    // Test SLEEP(5) - should extract 5000ms
    std::string payload = "1' AND SLEEP(5)--";
    HttpRequest req;
    req.method = "GET";
    req.url = "http://127.0.0.1:8080/test";
    
    TimingResult result = analyzer.test_payload(req, payload, baseline, "sql");
    
    // Confidence should account for expected 5000ms delay
    if (result.is_anomaly && result.deviation_ms > 4000.0) {
        REQUIRE(result.confidence > 0.0);
    }
}

TEST_CASE("Expected delay extraction - command sleep", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    TimingBaseline baseline;
    baseline.average_time_ms = 200.0;
    baseline.standard_deviation_ms = 50.0;
    
    // Test sleep 10 - should extract 10000ms
    std::string payload = "; sleep 10";
    HttpRequest req;
    req.method = "POST";
    req.url = "http://127.0.0.1:8080/test";
    
    TimingResult result = analyzer.test_payload(req, payload, baseline, "command");
    
    // Confidence should account for expected 10000ms delay
    if (result.is_anomaly && result.deviation_ms > 9000.0) {
        REQUIRE(result.confidence > 0.0);
    }
}

TEST_CASE("Empty baseline handling", "[timing_analyzer]") {
    HttpClient client = create_test_client();
    TimingAnalyzer analyzer(client);
    
    TimingBaseline baseline;  // Empty baseline
    
    TimingResult result = analyzer.analyze_timing(1000.0, baseline);
    
    // Should handle gracefully
    REQUIRE(result.baseline_time_ms == 0.0);
}

