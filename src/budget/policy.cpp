/**
 * @file policy.cpp
 * @brief Implementation of risk budget and policy evaluation
 */

#include "policy.h"
#include <fstream>
#include <iostream>
#include <iomanip>

namespace budget {

using json = nlohmann::json;

// Get default policy
Policy Policy::get_default() {
    Policy p;
    p.category_scores["missing_security_header"] = 2;
    p.category_scores["unsafe_cookie"] = 1;
    p.category_scores["cors_misconfiguration"] = 3;
    p.category_scores["reflected_xss"] = 5;
    p.category_scores["csrf"] = 4;
    p.category_scores["idor"] = 4;
    
    p.warn_threshold = 3;
    p.block_threshold = 5;
    
    return p;
}

// Load policy from file
Policy Policy::load(const std::string& policy_path) {
    std::ifstream in(policy_path);
    if (!in.is_open()) {
        std::cerr << "Warning: Could not open policy file, using defaults\n";
        return get_default();
    }
    
    try {
        json j;
        in >> j;
        
        Policy p;
        
        // Load category scores
        if (j.contains("category_scores")) {
            for (auto& [key, value] : j["category_scores"].items()) {
                p.category_scores[key] = value.get<int>();
            }
        }
        
        // Load thresholds
        p.warn_threshold = j.value("warn_threshold", 3);
        p.block_threshold = j.value("block_threshold", 5);
        
        return p;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing policy file: " << e.what() << "\n";
        std::cerr << "Using default policy\n";
        return get_default();
    }
}

// Constructor
BudgetEvaluator::BudgetEvaluator(const Policy& policy) 
    : policy_(policy) {}

// Evaluate from log file
BudgetResult BudgetEvaluator::evaluate(const std::string& log_path) const {
    std::ifstream in(log_path);
    if (!in.is_open()) {
        std::cerr << "Error: Could not open log file: " << log_path << "\n";
        return BudgetResult{};
    }
    
    std::vector<json> findings;
    std::string line;
    
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        
        try {
            json entry = json::parse(line);
            
            // Extract findings from log entries
            if (entry.value("event_type", "") == "finding_recorded") {
                if (entry.contains("payload")) {
                    findings.push_back(entry["payload"]);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to parse log line: " << e.what() << "\n";
        }
    }
    
    return evaluate_findings(findings);
}

// Evaluate from findings
BudgetResult BudgetEvaluator::evaluate_findings(const std::vector<json>& findings) const {
    BudgetResult result;
    result.total_score = 0;
    result.exceeds_warn = false;
    result.exceeds_block = false;
    
    // Count findings by category and compute scores
    for (const auto& finding : findings) {
        std::string category = finding.value("category", "unknown");
        
        // Increment count
        result.category_counts[category]++;
        
        // Get score for this category
        int score = 0;
        if (policy_.category_scores.count(category)) {
            score = policy_.category_scores.at(category);
        }
        
        // Add to category score
        result.category_scores[category] += score;
        
        // Add to total
        result.total_score += score;
    }
    
    // Check thresholds
    result.exceeds_warn = result.total_score >= policy_.warn_threshold;
    result.exceeds_block = result.total_score >= policy_.block_threshold;
    
    return result;
}

// Print report
void BudgetEvaluator::print_report(const BudgetResult& result) {
    std::cout << "\n=== Risk Budget Report ===\n\n";
    
    // Category breakdown
    std::cout << "Findings by Category:\n";
    for (const auto& [category, count] : result.category_counts) {
        int score = result.category_scores.count(category) 
            ? result.category_scores.at(category) : 0;
        std::cout << "  " << std::left << std::setw(30) << category 
                  << " Count: " << std::setw(3) << count
                  << " Score: " << score << "\n";
    }
    
    std::cout << "\n";
    std::cout << "Total Score: " << result.total_score << "\n";
    std::cout << "Status: " << result.status_string() << "\n";
    
    if (result.exceeds_block) {
        std::cout << "\n   BLOCKED: Risk score exceeds threshold\n";
    } else if (result.exceeds_warn) {
        std::cout << "\n   WARNING: Risk score approaching threshold\n";
    } else {
        std::cout << "\n   PASS: Risk within acceptable limits\n";
    }
    
    std::cout << "\n";
}

} // namespace budget