#pragma once
#include "http_client.h"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <cmath>

// Timing analysis for detecting blind SQL injection and command injection vulnerabilities.
// Establishes baseline response times and detects timing anomalies caused by
// time-based injection payloads (e.g., SLEEP(5), sleep 10).

struct TimingBaseline {
    double average_time_ms;      // Average response time in milliseconds
    double variance_ms;           // Variance in milliseconds
    double standard_deviation_ms; // Standard deviation in milliseconds
    double min_time_ms;           // Minimum response time
    double max_time_ms;           // Maximum response time
    size_t sample_count;          // Number of samples used
    
    TimingBaseline()
        : average_time_ms(0.0),
          variance_ms(0.0),
          standard_deviation_ms(0.0),
          min_time_ms(0.0),
          max_time_ms(0.0),
          sample_count(0)
    {}
};

struct TimingResult {
    double measured_time_ms;      // Measured response time
    double baseline_time_ms;      // Baseline average time
    double deviation_ms;          // Deviation from baseline
    double deviation_percentage;  // Percentage deviation
    double confidence;            // Confidence score (0.0-1.0)
    bool is_anomaly;              // Whether timing anomaly detected
    std::string payload;           // Payload that caused the timing
    std::string injection_type;    // "sql" or "command"
    std::vector<double> measurements; // Multiple measurements for validation
    
    TimingResult()
        : measured_time_ms(0.0),
          baseline_time_ms(0.0),
          deviation_ms(0.0),
          deviation_percentage(0.0),
          confidence(0.0),
          is_anomaly(false)
    {}
};

class TimingAnalyzer {
public:
    struct Options {
        size_t baseline_samples;      // Number of requests for baseline (minimum 3)
        double threshold_percentage;  // Threshold for anomaly detection (default 80%)
        size_t validation_samples;    // Number of measurements per payload for validation
        double min_delay_ms;          // Minimum delay to consider (default 1000ms)
        
        Options()
            : baseline_samples(3),
              threshold_percentage(80.0),
              validation_samples(3),
              min_delay_ms(1000.0)
        {}
    };
    
    /**
     * @brief Create a timing analyzer with options
     * @param client HTTP client for making requests
     * @param opts Timing analysis options
     */
    TimingAnalyzer(const HttpClient& client, const Options& opts = Options());
    
    /**
     * @brief Establish baseline response time for an endpoint
     * @param req HTTP request to use for baseline
     * @return Baseline statistics
     */
    TimingBaseline establish_baseline(const HttpRequest& req);
    
    /**
     * @brief Test a payload for timing anomalies
     * @param req Base HTTP request (will be modified with payload)
     * @param payload Payload to inject
     * @param baseline Baseline timing statistics
     * @param injection_type Type of injection: "sql" or "command"
     * @return Timing result with anomaly detection
     */
    TimingResult test_payload(const HttpRequest& req,
                             const std::string& payload,
                             const TimingBaseline& baseline,
                             const std::string& injection_type = "sql");
    
    /**
     * @brief Test a payload with multiple measurements for validation
     * @param req Base HTTP request
     * @param payload Payload to inject
     * @param baseline Baseline timing statistics
     * @param injection_type Type of injection
     * @return Timing result with validated confidence
     */
    TimingResult test_payload_validated(const HttpRequest& req,
                                       const std::string& payload,
                                       const TimingBaseline& baseline,
                                       const std::string& injection_type = "sql");
    
    /**
     * @brief Check if a measured time indicates an anomaly
     * @param measured_time Measured response time in milliseconds
     * @param baseline Baseline timing statistics
     * @return Timing result with anomaly detection
     */
    TimingResult analyze_timing(double measured_time_ms, const TimingBaseline& baseline);
    
    /**
     * @brief Calculate confidence score based on timing deviation
     * @param deviation_ms Deviation from baseline in milliseconds
     * @param baseline Baseline timing statistics
     * @param expected_delay_ms Expected delay from payload (e.g., 5000ms for SLEEP(5))
     * @return Confidence score (0.0-1.0)
     */
    static double calculate_confidence(double deviation_ms,
                                      const TimingBaseline& baseline,
                                      double expected_delay_ms = 0.0);
    
    /**
     * @brief Calculate variance from a vector of measurements (public for testing)
     * @param measurements Vector of timing measurements
     * @param mean Mean value
     * @return Variance
     */
    static double calculate_variance(const std::vector<double>& measurements, double mean);
    
    /**
     * @brief Calculate standard deviation from variance (public for testing)
     * @param variance Variance value
     * @return Standard deviation
     */
    static double calculate_standard_deviation(double variance);

private:
    const HttpClient& client_;
    Options opts_;
    
    /**
     * @brief Make a request and measure response time
     * @param req HTTP request
     * @return Response time in milliseconds, or -1.0 on error
     */
    double measure_request_time(const HttpRequest& req) const;
    
    /**
     * @brief Check if timing deviation exceeds threshold
     * @param deviation_ms Deviation in milliseconds
     * @param baseline Baseline statistics
     * @return true if anomaly detected
     */
    bool is_anomaly_detected(double deviation_ms, const TimingBaseline& baseline) const;
};

