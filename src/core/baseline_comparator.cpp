// Baseline comparison implementation

#include "baseline_comparator.h"
#include <algorithm>
#include <cmath>
#include <regex>
#include <sstream>
#include <set>
#include <unordered_set>

BaselineComparator::BaselineComparator(const HttpClient& client, const Options& opts)
    : client_(client), opts_(opts) {
    response_analyzer_ = std::make_unique<ResponseAnalyzer>();
}

ComparisonResult BaselineComparator::compare(const HttpResponse& baseline_response,
                                            const HttpResponse& test_response,
                                            const TimingBaseline& baseline_timing,
                                            double test_timing_ms,
                                            const std::string& payload) {
    ComparisonResult result;
    
    // Compare status codes
    if (opts_.check_status_code) {
        result.baseline_status = baseline_response.status;
        result.test_status = test_response.status;
        result.status_changed = compare_status_codes(baseline_response.status, test_response.status);
    }
    
    // Compare response lengths
    if (opts_.check_length) {
        compare_lengths(baseline_response.body.size(), test_response.body.size(), result);
    }
    
    // Compare content similarity
    if (opts_.check_similarity) {
        compare_content(baseline_response.body, test_response.body, result);
    }
    
    // Compare error messages
    if (opts_.check_errors) {
        compare_errors(baseline_response.body, test_response.body, result);
    }
    
    // Compare timing
    if (opts_.check_timing && test_timing_ms > 0.0) {
        compare_timing(baseline_timing, test_timing_ms, result);
    }
    
    // Determine vulnerability indication
    result.indicates_vulnerability = indicates_vulnerability(result);
    result.confidence = calculate_confidence(result);
    
    // Determine vulnerability type based on payload and indicators
    if (result.indicates_vulnerability) {
        if (payload.find("SLEEP") != std::string::npos || 
            payload.find("sleep") != std::string::npos ||
            payload.find("pg_sleep") != std::string::npos ||
            payload.find("WAITFOR") != std::string::npos) {
            result.vulnerability_type = "sql_injection";
        } else if (payload.find("sleep ") != std::string::npos ||
                   payload.find("timeout") != std::string::npos) {
            result.vulnerability_type = "command_injection";
        } else if (result.has_new_errors) {
            // Check error types
            bool sql_error = false;
            for (const auto& error : result.new_errors) {
                std::string lower_error = error;
                std::transform(lower_error.begin(), lower_error.end(), lower_error.begin(), ::tolower);
                if (lower_error.find("sql") != std::string::npos ||
                    lower_error.find("database") != std::string::npos ||
                    lower_error.find("mysql") != std::string::npos ||
                    lower_error.find("postgresql") != std::string::npos) {
                    sql_error = true;
                    break;
                }
            }
            result.vulnerability_type = sql_error ? "sql_injection" : "injection";
        } else {
            result.vulnerability_type = "injection";
        }
    }
    
    return result;
}

double BaselineComparator::calculate_similarity(const std::string& str1, const std::string& str2) {
    if (str1.empty() && str2.empty()) {
        return 1.0;
    }
    if (str1.empty() || str2.empty()) {
        return 0.0;
    }
    
    // Use Levenshtein distance
    size_t distance = levenshtein_distance(str1, str2);
    size_t max_len = std::max(str1.length(), str2.length());
    
    if (max_len == 0) {
        return 1.0;
    }
    
    // Similarity = 1 - (distance / max_length)
    double similarity = 1.0 - (static_cast<double>(distance) / static_cast<double>(max_len));
    return std::max(0.0, std::min(1.0, similarity));
}

double BaselineComparator::calculate_jaccard_similarity(const std::string& str1, const std::string& str2) {
    if (str1.empty() && str2.empty()) {
        return 1.0;
    }
    if (str1.empty() || str2.empty()) {
        return 0.0;
    }
    
    // Create sets of words (tokens)
    std::unordered_set<std::string> set1, set2;
    
    std::istringstream iss1(str1);
    std::string word;
    while (iss1 >> word) {
        // Normalize word
        std::transform(word.begin(), word.end(), word.begin(), ::tolower);
        set1.insert(word);
    }
    
    std::istringstream iss2(str2);
    while (iss2 >> word) {
        std::transform(word.begin(), word.end(), word.begin(), ::tolower);
        set2.insert(word);
    }
    
    // Calculate intersection and union
    size_t intersection = 0;
    for (const auto& w : set1) {
        if (set2.count(w) > 0) {
            intersection++;
        }
    }
    
    size_t union_size = set1.size() + set2.size() - intersection;
    
    if (union_size == 0) {
        return 1.0;
    }
    
    return static_cast<double>(intersection) / static_cast<double>(union_size);
}

std::vector<std::string> BaselineComparator::extract_errors(const std::string& response_body) {
    std::vector<std::string> errors;
    
    // Common error patterns
    std::vector<std::regex> error_patterns = {
        std::regex(R"(SQLException[^\n]*)", std::regex::icase),
        std::regex(R"(SQL.*?Error[^\n]*)", std::regex::icase),
        std::regex(R"(Database.*?Error[^\n]*)", std::regex::icase),
        std::regex(R"(MySQL.*?Error[^\n]*)", std::regex::icase),
        std::regex(R"(PostgreSQL.*?Error[^\n]*)", std::regex::icase),
        std::regex(R"(ORA-\d+[^\n]*)", std::regex::icase),
        std::regex(R"(Warning:.*?in.*?on line \d+)", std::regex::icase),
        std::regex(R"(Fatal error:.*?in.*?on line \d+)", std::regex::icase),
        std::regex(R"(Error \d+:.*?)", std::regex::icase),
        std::regex(R"(Exception in thread[^\n]*)", std::regex::icase),
        std::regex(R"(Traceback.*?Error[^\n]*)", std::regex::icase),
        std::regex(R"(Stack trace[^\n]*)", std::regex::icase),
    };
    
    for (const auto& pattern : error_patterns) {
        std::sregex_iterator iter(response_body.begin(), response_body.end(), pattern);
        std::sregex_iterator end;
        
        for (; iter != end; ++iter) {
            std::string error = iter->str();
            // Trim whitespace
            error.erase(0, error.find_first_not_of(" \t\r\n"));
            error.erase(error.find_last_not_of(" \t\r\n") + 1);
            
            if (!error.empty()) {
                errors.push_back(error);
            }
        }
    }
    
    // Remove duplicates
    std::set<std::string> unique_errors(errors.begin(), errors.end());
    return std::vector<std::string>(unique_errors.begin(), unique_errors.end());
}

bool BaselineComparator::indicates_vulnerability(const ComparisonResult& result) const {
    int indicators = 0;
    
    // Status code change (especially to error codes)
    if (result.status_changed) {
        if (result.test_status >= 500 || 
            (result.baseline_status == 200 && result.test_status != 200)) {
            indicators += 2;  // Strong indicator
        } else {
            indicators += 1;  // Weak indicator
        }
    }
    
    // Significant length change
    if (result.length_changed && std::abs(result.length_change_percentage) > opts_.length_change_threshold) {
        indicators += 2;
    }
    
    // Low similarity score
    if (result.similarity_score < opts_.similarity_threshold) {
        indicators += 2;
    }
    
    // New error messages
    if (result.has_new_errors && !result.new_errors.empty()) {
        indicators += 3;  // Strong indicator
    }
    
    // Timing anomaly
    if (result.timing_anomaly) {
        indicators += 2;
    }
    
    // Require at least 3 indicator points to flag as vulnerable
    // This reduces false positives while catching real vulnerabilities
    return indicators >= 3;
}

double BaselineComparator::calculate_confidence(const ComparisonResult& result) const {
    if (!result.indicates_vulnerability) {
        return 0.0;
    }
    
    double confidence = 0.0;
    double weight_sum = 0.0;
    
    // Status code change (weight: 0.2)
    if (result.status_changed) {
        double status_weight = 0.2;
        if (result.test_status >= 500) {
            confidence += 0.9 * status_weight;  // High confidence for server errors
        } else if (result.baseline_status == 200 && result.test_status != 200) {
            confidence += 0.6 * status_weight;  // Medium confidence
        } else {
            confidence += 0.3 * status_weight;  // Low confidence
        }
        weight_sum += status_weight;
    }
    
    // Length change (weight: 0.15)
    if (result.length_changed) {
        double length_weight = 0.15;
        double length_confidence = std::min(1.0, std::abs(result.length_change_percentage) / 200.0);
        confidence += length_confidence * length_weight;
        weight_sum += length_weight;
    }
    
    // Similarity (weight: 0.25)
    if (result.similarity_score < opts_.similarity_threshold) {
        double similarity_weight = 0.25;
        double similarity_confidence = 1.0 - result.similarity_score;
        confidence += similarity_confidence * similarity_weight;
        weight_sum += similarity_weight;
    }
    
    // Error messages (weight: 0.3)
    if (result.has_new_errors && !result.new_errors.empty()) {
        double error_weight = 0.3;
        // Higher confidence for more errors
        double error_confidence = std::min(1.0, 0.7 + (result.new_errors.size() * 0.1));
        confidence += error_confidence * error_weight;
        weight_sum += error_weight;
    }
    
    // Timing anomaly (weight: 0.1)
    if (result.timing_anomaly) {
        double timing_weight = 0.1;
        double timing_confidence = std::min(1.0, result.timing_deviation_ms / 5000.0);
        confidence += timing_confidence * timing_weight;
        weight_sum += timing_weight;
    }
    
    // Normalize by weight sum
    if (weight_sum > 0.0) {
        confidence = confidence / weight_sum;
    }
    
    // Boost confidence if multiple strong indicators
    int strong_indicators = 0;
    if (result.test_status >= 500) strong_indicators++;
    if (result.has_new_errors && !result.new_errors.empty()) strong_indicators++;
    if (result.similarity_score < 0.5) strong_indicators++;
    if (result.timing_anomaly && result.timing_deviation_ms > 3000.0) strong_indicators++;
    
    if (strong_indicators >= 2) {
        confidence = std::min(1.0, confidence * 1.15);  // 15% boost
    }
    
    return std::max(0.0, std::min(1.0, confidence));
}

size_t BaselineComparator::levenshtein_distance(const std::string& str1, const std::string& str2) {
    const size_t len1 = str1.size();
    const size_t len2 = str2.size();
    
    if (len1 == 0) return len2;
    if (len2 == 0) return len1;
    
    // Create matrix
    std::vector<std::vector<size_t>> matrix(len1 + 1, std::vector<size_t>(len2 + 1));
    
    // Initialize first row and column
    for (size_t i = 0; i <= len1; ++i) {
        matrix[i][0] = i;
    }
    for (size_t j = 0; j <= len2; ++j) {
        matrix[0][j] = j;
    }
    
    // Fill matrix
    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            size_t cost = (str1[i - 1] == str2[j - 1]) ? 0 : 1;
            
            matrix[i][j] = std::min({
                matrix[i - 1][j] + 1,      // deletion
                matrix[i][j - 1] + 1,      // insertion
                matrix[i - 1][j - 1] + cost // substitution
            });
        }
    }
    
    return matrix[len1][len2];
}

std::string BaselineComparator::normalize_string(const std::string& str) {
    std::string normalized = str;
    
    // Convert to lowercase
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    
    // Remove extra whitespace
    std::string result;
    bool last_was_space = false;
    for (char c : normalized) {
        if (std::isspace(c)) {
            if (!last_was_space) {
                result += ' ';
                last_was_space = true;
            }
        } else {
            result += c;
            last_was_space = false;
        }
    }
    
    // Trim
    result.erase(0, result.find_first_not_of(" \t\r\n"));
    result.erase(result.find_last_not_of(" \t\r\n") + 1);
    
    return result;
}

bool BaselineComparator::compare_status_codes(long baseline_status, long test_status) const {
    // Status changed if different
    if (baseline_status != test_status) {
        return true;
    }
    return false;
}

void BaselineComparator::compare_lengths(size_t baseline_length, size_t test_length, ComparisonResult& result) const {
    result.baseline_length = baseline_length;
    result.test_length = test_length;
    
    if (baseline_length == 0) {
        result.length_difference = static_cast<long>(test_length);
        result.length_change_percentage = (test_length > 0) ? 100.0 : 0.0;
    } else {
        result.length_difference = static_cast<long>(test_length) - static_cast<long>(baseline_length);
        result.length_change_percentage = (static_cast<double>(result.length_difference) / static_cast<double>(baseline_length)) * 100.0;
    }
    
    result.length_changed = std::abs(result.length_change_percentage) > opts_.length_change_threshold;
}

void BaselineComparator::compare_content(const std::string& baseline_body, const std::string& test_body, ComparisonResult& result) const {
    result.similarity_score = calculate_similarity(baseline_body, test_body);
}

void BaselineComparator::compare_errors(const std::string& baseline_body, const std::string& test_body, ComparisonResult& result) const {
    std::vector<std::string> baseline_errors = extract_errors(baseline_body);
    std::vector<std::string> test_errors = extract_errors(test_body);
    
    // Find errors in test that are not in baseline
    std::set<std::string> baseline_error_set(baseline_errors.begin(), baseline_errors.end());
    
    for (const auto& error : test_errors) {
        if (baseline_error_set.find(error) == baseline_error_set.end()) {
            result.new_errors.push_back(error);
        }
    }
    
    result.has_new_errors = !result.new_errors.empty();
}

void BaselineComparator::compare_timing(const TimingBaseline& baseline_timing, double test_timing_ms, ComparisonResult& result) const {
    if (baseline_timing.sample_count == 0 || test_timing_ms <= 0.0) {
        return;
    }
    
    result.baseline_time_ms = baseline_timing.average_time_ms;
    result.test_time_ms = test_timing_ms;
    result.timing_deviation_ms = test_timing_ms - baseline_timing.average_time_ms;
    
    // Check if deviation exceeds threshold
    if (result.timing_deviation_ms >= opts_.timing_threshold_ms) {
        // Also check if it's significant relative to standard deviation
        double z_score = result.timing_deviation_ms / baseline_timing.standard_deviation_ms;
        if (z_score >= 2.0) {
            result.timing_anomaly = true;
        }
    }
}

