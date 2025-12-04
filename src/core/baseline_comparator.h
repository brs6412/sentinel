#pragma once
#include "http_client.h"
#include "timing_analyzer.h"
#include "response_analyzer.h"
#include <string>
#include <vector>
#include <map>
#include <set>

// Baseline comparison for detecting vulnerabilities based on behavioral differences.
// Compares normal responses against payload-injected responses to identify
// anomalies in status codes, content, length, errors, and timing.

struct ComparisonResult {
    // Status code comparison
    bool status_changed;
    long baseline_status;
    long test_status;
    
    // Response length comparison
    bool length_changed;
    size_t baseline_length;
    size_t test_length;
    long length_difference;
    double length_change_percentage;
    
    // Content similarity
    double similarity_score;  // 0.0 (completely different) to 1.0 (identical)
    
    // Error detection
    bool has_new_errors;
    std::vector<std::string> new_errors;  // Error messages found in test but not baseline
    
    // Timing comparison
    bool timing_anomaly;
    double baseline_time_ms;
    double test_time_ms;
    double timing_deviation_ms;
    
    // Overall vulnerability indication
    bool indicates_vulnerability;
    double confidence;  // 0.0 to 1.0
    std::string vulnerability_type;  // e.g., "sql_injection", "command_injection"
    
    ComparisonResult()
        : status_changed(false),
          baseline_status(0),
          test_status(0),
          length_changed(false),
          baseline_length(0),
          test_length(0),
          length_difference(0),
          length_change_percentage(0.0),
          similarity_score(1.0),
          has_new_errors(false),
          timing_anomaly(false),
          baseline_time_ms(0.0),
          test_time_ms(0.0),
          timing_deviation_ms(0.0),
          indicates_vulnerability(false),
          confidence(0.0)
    {}
};

class BaselineComparator {
public:
    struct Options {
        double similarity_threshold;      // Below this = significant difference (default 0.7)
        double length_change_threshold;   // Percentage change to flag (default 50.0)
        bool check_status_code;           // Whether to check status code changes
        bool check_length;                // Whether to check length changes
        bool check_similarity;            // Whether to check content similarity
        bool check_errors;                // Whether to check for new errors
        bool check_timing;                // Whether to check timing anomalies
        double timing_threshold_ms;       // Minimum timing deviation to flag (default 1000.0)
        
        Options()
            : similarity_threshold(0.7),
              length_change_threshold(50.0),
              check_status_code(true),
              check_length(true),
              check_similarity(true),
              check_errors(true),
              check_timing(true),
              timing_threshold_ms(1000.0)
        {}
    };
    
    /**
     * @brief Create a baseline comparator with options
     * @param client HTTP client for making requests
     * @param opts Comparison options
     */
    BaselineComparator(const HttpClient& client, const Options& opts = Options());
    
    /**
     * @brief Compare baseline and test responses
     * @param baseline_response Baseline HTTP response
     * @param test_response Test HTTP response (with payload injected)
     * @param baseline_timing Optional baseline timing statistics
     * @param test_timing Optional test timing in milliseconds
     * @param payload Payload that was injected (for context)
     * @return Comparison result with all metrics
     */
    ComparisonResult compare(const HttpResponse& baseline_response,
                           const HttpResponse& test_response,
                           const TimingBaseline& baseline_timing = TimingBaseline(),
                           double test_timing_ms = 0.0,
                           const std::string& payload = "");
    
    /**
     * @brief Calculate string similarity using Levenshtein distance
     * @param str1 First string
     * @param str2 Second string
     * @return Similarity score (0.0 to 1.0)
     */
    static double calculate_similarity(const std::string& str1, const std::string& str2);
    
    /**
     * @brief Calculate Jaccard similarity (alternative method)
     * @param str1 First string
     * @param str2 Second string
     * @return Similarity score (0.0 to 1.0)
     */
    static double calculate_jaccard_similarity(const std::string& str1, const std::string& str2);
    
    /**
     * @brief Extract error messages from response body
     * @param response_body Response body content
     * @return Vector of error message strings
     */
    static std::vector<std::string> extract_errors(const std::string& response_body);
    
    /**
     * @brief Determine if comparison result indicates a vulnerability
     * @param result Comparison result
     * @return true if vulnerability is indicated, false otherwise
     */
    bool indicates_vulnerability(const ComparisonResult& result) const;
    
    /**
     * @brief Calculate confidence score for vulnerability indication
     * @param result Comparison result
     * @return Confidence score (0.0 to 1.0)
     */
    double calculate_confidence(const ComparisonResult& result) const;

private:
    const HttpClient& client_;
    Options opts_;
    std::unique_ptr<ResponseAnalyzer> response_analyzer_;
    
    /**
     * @brief Calculate Levenshtein distance between two strings
     * @param str1 First string
     * @param str2 Second string
     * @return Levenshtein distance
     */
    static size_t levenshtein_distance(const std::string& str1, const std::string& str2);
    
    /**
     * @brief Normalize strings for comparison (remove whitespace, lowercase, etc.)
     * @param str String to normalize
     * @return Normalized string
     */
    static std::string normalize_string(const std::string& str);
    
    /**
     * @brief Compare status codes
     * @param baseline_status Baseline status code
     * @param test_status Test status code
     * @return true if status changed significantly
     */
    bool compare_status_codes(long baseline_status, long test_status) const;
    
    /**
     * @brief Compare response lengths
     * @param baseline_length Baseline length
     * @param test_length Test length
     * @param result Comparison result to update
     */
    void compare_lengths(size_t baseline_length, size_t test_length, ComparisonResult& result) const;
    
    /**
     * @brief Compare content similarity
     * @param baseline_body Baseline response body
     * @param test_body Test response body
     * @param result Comparison result to update
     */
    void compare_content(const std::string& baseline_body, const std::string& test_body, ComparisonResult& result) const;
    
    /**
     * @brief Compare error messages
     * @param baseline_body Baseline response body
     * @param test_body Test response body
     * @param result Comparison result to update
     */
    void compare_errors(const std::string& baseline_body, const std::string& test_body, ComparisonResult& result) const;
    
    /**
     * @brief Compare timing
     * @param baseline_timing Baseline timing statistics
     * @param test_timing_ms Test timing in milliseconds
     * @param result Comparison result to update
     */
    void compare_timing(const TimingBaseline& baseline_timing, double test_timing_ms, ComparisonResult& result) const;
};

