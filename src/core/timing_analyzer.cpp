// Timing analysis implementation

#include "timing_analyzer.h"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <thread>
#include <chrono>

TimingAnalyzer::TimingAnalyzer(const HttpClient& client, const Options& opts)
    : client_(client), opts_(opts)
{
    // Ensure minimum baseline samples
    if (opts_.baseline_samples < 3) {
        opts_.baseline_samples = 3;
    }
}

TimingBaseline TimingAnalyzer::establish_baseline(const HttpRequest& req) {
    TimingBaseline baseline;
    std::vector<double> measurements;
    
    // Make multiple requests to establish baseline
    for (size_t i = 0; i < opts_.baseline_samples; ++i) {
        double time_ms = measure_request_time(req);
        if (time_ms > 0.0) {
            measurements.push_back(time_ms);
        }
    }
    
    if (measurements.empty()) {
        return baseline;
    }
    
    // Calculate statistics
    baseline.sample_count = measurements.size();
    
    // Calculate mean
    double sum = std::accumulate(measurements.begin(), measurements.end(), 0.0);
    baseline.average_time_ms = sum / measurements.size();
    
    // Find min and max
    auto minmax = std::minmax_element(measurements.begin(), measurements.end());
    baseline.min_time_ms = *minmax.first;
    baseline.max_time_ms = *minmax.second;
    
    // Calculate variance
    baseline.variance_ms = calculate_variance(measurements, baseline.average_time_ms);
    
    // Calculate standard deviation
    baseline.standard_deviation_ms = calculate_standard_deviation(baseline.variance_ms);
    
    return baseline;
}

TimingResult TimingAnalyzer::test_payload(const HttpRequest& req,
                                          const std::string& payload,
                                          const TimingBaseline& baseline,
                                          const std::string& injection_type) {
    TimingResult result;
    result.baseline_time_ms = baseline.average_time_ms;
    result.payload = payload;
    result.injection_type = injection_type;
    
    // Create modified request with payload
    HttpRequest modified_req = req;
    
    // Inject payload into request
    if (req.method == "GET" || req.method == "HEAD") {
        // Inject into URL parameters
        size_t param_pos = modified_req.url.find('?');
        if (param_pos != std::string::npos) {
            // Append to existing parameters
            modified_req.url += "&test=" + payload;
        } else {
            modified_req.url += "?test=" + payload;
        }
    } else {
        // Inject into body for POST/PUT/etc
        if (modified_req.body.empty()) {
            modified_req.body = "test=" + payload;
        } else {
            modified_req.body += "&test=" + payload;
        }
    }
    
    // Measure response time
    result.measured_time_ms = measure_request_time(modified_req);
    
    if (result.measured_time_ms <= 0.0) {
        return result;
    }
    
    // Calculate deviation
    result.deviation_ms = result.measured_time_ms - baseline.average_time_ms;
    result.deviation_percentage = (result.deviation_ms / baseline.average_time_ms) * 100.0;
    
    // Check for anomaly
    result.is_anomaly = is_anomaly_detected(result.deviation_ms, baseline);
    
    // Calculate confidence
    // For SQL injection, estimate expected delay (e.g., SLEEP(5) = 5000ms)
    double expected_delay = 0.0;
    if (injection_type == "sql") {
        // Try to extract delay from payload (e.g., SLEEP(5) or WAITFOR DELAY '00:00:05')
        if (payload.find("SLEEP(") != std::string::npos || 
            payload.find("sleep(") != std::string::npos) {
            // Extract number from SLEEP(n)
            size_t start = payload.find("(");
            size_t end = payload.find(")");
            if (start != std::string::npos && end != std::string::npos) {
                try {
                    std::string delay_str = payload.substr(start + 1, end - start - 1);
                    expected_delay = std::stod(delay_str) * 1000.0; // Convert to milliseconds
                } catch (...) {
                    // Default to 5000ms if parsing fails
                    expected_delay = 5000.0;
                }
            }
        } else if (payload.find("WAITFOR DELAY") != std::string::npos) {
            // SQL Server delay format
            expected_delay = 5000.0; // Default
        } else if (payload.find("pg_sleep") != std::string::npos) {
            // PostgreSQL delay
            size_t start = payload.find("(");
            size_t end = payload.find(")");
            if (start != std::string::npos && end != std::string::npos) {
                try {
                    std::string delay_str = payload.substr(start + 1, end - start - 1);
                    expected_delay = std::stod(delay_str) * 1000.0;
                } catch (...) {
                    expected_delay = 5000.0;
                }
            }
        }
    } else if (injection_type == "command") {
        // Extract delay from command (e.g., sleep 10)
        if (payload.find("sleep ") != std::string::npos) {
            size_t start = payload.find("sleep ");
            if (start != std::string::npos) {
                try {
                    std::string delay_str = payload.substr(start + 6);
                    // Remove any trailing characters
                    size_t space_pos = delay_str.find(' ');
                    if (space_pos != std::string::npos) {
                        delay_str = delay_str.substr(0, space_pos);
                    }
                    expected_delay = std::stod(delay_str) * 1000.0;
                } catch (...) {
                    expected_delay = 10000.0; // Default 10 seconds
                }
            }
        } else if (payload.find("timeout") != std::string::npos) {
            expected_delay = 5000.0; // Default
        }
    }
    
    result.confidence = calculate_confidence(result.deviation_ms, baseline, expected_delay);
    
    return result;
}

TimingResult TimingAnalyzer::test_payload_validated(const HttpRequest& req,
                                                   const std::string& payload,
                                                   const TimingBaseline& baseline,
                                                   const std::string& injection_type) {
    TimingResult result;
    result.baseline_time_ms = baseline.average_time_ms;
    result.payload = payload;
    result.injection_type = injection_type;
    
    // Make multiple measurements
    for (size_t i = 0; i < opts_.validation_samples; ++i) {
        TimingResult single_result = test_payload(req, payload, baseline, injection_type);
        if (single_result.measured_time_ms > 0.0) {
            result.measurements.push_back(single_result.measured_time_ms);
        }
        
        // Small delay between measurements to avoid overwhelming server
        if (i < opts_.validation_samples - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    if (result.measurements.empty()) {
        return result;
    }
    
    // Calculate average of measurements
    double sum = std::accumulate(result.measurements.begin(), result.measurements.end(), 0.0);
    result.measured_time_ms = sum / result.measurements.size();
    
    // Calculate deviation
    result.deviation_ms = result.measured_time_ms - baseline.average_time_ms;
    result.deviation_percentage = (result.deviation_ms / baseline.average_time_ms) * 100.0;
    
    // Check for anomaly
    result.is_anomaly = is_anomaly_detected(result.deviation_ms, baseline);
    
    // Calculate confidence with validation boost
    double expected_delay = 0.0;
    if (injection_type == "sql") {
        if (payload.find("SLEEP(") != std::string::npos || payload.find("sleep(") != std::string::npos) {
            size_t start = payload.find("(");
            size_t end = payload.find(")");
            if (start != std::string::npos && end != std::string::npos) {
                try {
                    std::string delay_str = payload.substr(start + 1, end - start - 1);
                    expected_delay = std::stod(delay_str) * 1000.0;
                } catch (...) {
                    expected_delay = 5000.0;
                }
            }
        } else {
            expected_delay = 5000.0;
        }
    } else if (injection_type == "command") {
        if (payload.find("sleep ") != std::string::npos) {
            size_t start = payload.find("sleep ");
            if (start != std::string::npos) {
                try {
                    std::string delay_str = payload.substr(start + 6);
                    size_t space_pos = delay_str.find(' ');
                    if (space_pos != std::string::npos) {
                        delay_str = delay_str.substr(0, space_pos);
                    }
                    expected_delay = std::stod(delay_str) * 1000.0;
                } catch (...) {
                    expected_delay = 10000.0;
                }
            }
        } else {
            expected_delay = 10000.0;
        }
    }
    
    double base_confidence = calculate_confidence(result.deviation_ms, baseline, expected_delay);
    
    // Boost confidence if measurements are consistent
    if (result.measurements.size() >= 2) {
        double min_measurement = *std::min_element(result.measurements.begin(), result.measurements.end());
        double max_measurement = *std::max_element(result.measurements.begin(), result.measurements.end());
        double range = max_measurement - min_measurement;
        
        // If measurements are consistent (low variance), boost confidence
        if (range < baseline.standard_deviation_ms * 2.0) {
            base_confidence = std::min(1.0, base_confidence * 1.1); // 10% boost
        }
        
        // If all measurements show delay, increase confidence further
        bool all_delayed = true;
        for (double m : result.measurements) {
            if (m < baseline.average_time_ms + baseline.standard_deviation_ms * 2.0) {
                all_delayed = false;
                break;
            }
        }
        if (all_delayed && result.measurements.size() >= 3) {
            base_confidence = std::min(1.0, base_confidence * 1.15); // Additional 15% boost
        }
    }
    
    result.confidence = base_confidence;
    
    return result;
}

TimingResult TimingAnalyzer::analyze_timing(double measured_time_ms, const TimingBaseline& baseline) {
    TimingResult result;
    result.measured_time_ms = measured_time_ms;
    result.baseline_time_ms = baseline.average_time_ms;
    
    if (measured_time_ms <= 0.0) {
        return result;
    }
    
    result.deviation_ms = measured_time_ms - baseline.average_time_ms;
    result.deviation_percentage = (result.deviation_ms / baseline.average_time_ms) * 100.0;
    
    result.is_anomaly = is_anomaly_detected(result.deviation_ms, baseline);
    result.confidence = calculate_confidence(result.deviation_ms, baseline, 0.0);
    
    return result;
}

double TimingAnalyzer::calculate_confidence(double deviation_ms,
                                            const TimingBaseline& baseline,
                                            double expected_delay_ms) {
    if (deviation_ms <= 0.0) {
        return 0.0;
    }
    
    // Base confidence on deviation magnitude relative to baseline
    double deviation_ratio = deviation_ms / baseline.average_time_ms;
    
    // If we have an expected delay, compare against it
    if (expected_delay_ms > 0.0) {
        double match_ratio = deviation_ms / expected_delay_ms;
        
        // If deviation is close to expected delay, high confidence
        if (match_ratio >= 0.8 && match_ratio <= 1.2) {
            return std::min(0.99, 0.7 + (match_ratio - 0.8) * 0.5);
        }
        
        // If deviation is significantly less than expected, lower confidence
        if (match_ratio < 0.5) {
            return std::max(0.3, match_ratio * 0.6);
        }
        
        // If deviation is more than expected, still high confidence but cap it
        if (match_ratio > 1.2) {
            return std::min(0.95, 0.9 + (1.2 / match_ratio) * 0.05);
        }
    }
    
    // Confidence based on deviation relative to standard deviation
    double z_score = deviation_ms / baseline.standard_deviation_ms;
    
    // Higher z-score = higher confidence (more significant deviation)
    if (z_score < 2.0) {
        return 0.3 + (z_score / 2.0) * 0.3; // 0.3 to 0.6
    } else if (z_score < 5.0) {
        return 0.6 + ((z_score - 2.0) / 3.0) * 0.3; // 0.6 to 0.9
    } else {
        return 0.9 + std::min(0.1, (z_score - 5.0) / 10.0); // 0.9 to 1.0
    }
}

double TimingAnalyzer::measure_request_time(const HttpRequest& req) const {
    HttpResponse resp;
    
    auto start = std::chrono::high_resolution_clock::now();
    bool success = client_.perform(req, resp);
    auto end = std::chrono::high_resolution_clock::now();
    
    if (!success) {
        return -1.0;
    }
    
    // Use actual measured time (more accurate than resp.total_time)
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    return static_cast<double>(duration.count());
}

double TimingAnalyzer::calculate_variance(const std::vector<double>& measurements, double mean) {
    if (measurements.size() < 2) {
        return 0.0;
    }
    
    double sum_squared_diff = 0.0;
    for (double value : measurements) {
        double diff = value - mean;
        sum_squared_diff += diff * diff;
    }
    
    return sum_squared_diff / (measurements.size() - 1); // Sample variance
}

double TimingAnalyzer::calculate_standard_deviation(double variance) {
    return std::sqrt(variance);
}

bool TimingAnalyzer::is_anomaly_detected(double deviation_ms, const TimingBaseline& baseline) const {
    // Must exceed minimum delay threshold
    if (deviation_ms < opts_.min_delay_ms) {
        return false;
    }
    
    // Check if deviation exceeds threshold percentage
    double deviation_percentage = (deviation_ms / baseline.average_time_ms) * 100.0;
    if (deviation_percentage < opts_.threshold_percentage) {
        return false;
    }
    
    // Also check if deviation is significant relative to standard deviation
    // Anomaly if deviation > 2 * standard_deviation (approximately 95% confidence)
    double z_score = deviation_ms / baseline.standard_deviation_ms;
    if (z_score < 2.0) {
        return false;
    }
    
    return true;
}

