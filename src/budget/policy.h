#pragma once
#include <string>
#include <map>
#include <vector>
#include <nlohmann/json.hpp>

namespace budget {

/**
 * @brief Risk policy configuration
 */
struct Policy {
    // Score per finding category
    std::map<std::string, int> category_scores;
    
    // Thresholds
    int warn_threshold;
    int block_threshold;
    
    // Load from YAML/JSON file
    static Policy load(const std::string& policy_path);
    
    // Get default policy
    static Policy get_default();
};

/**
 * @brief Result of budget evaluation
 */
struct BudgetResult {
    int total_score;
    std::map<std::string, int> category_counts;
    std::map<std::string, int> category_scores;
    bool exceeds_warn;
    bool exceeds_block;
    
    enum class Status {
        PASS,
        WARN,
        BLOCK
    };
    
    Status status() const {
        if (exceeds_block) return Status::BLOCK;
        if (exceeds_warn) return Status::WARN;
        return Status::PASS;
    }
    
    int exit_code() const {
        switch (status()) {
            case Status::PASS:  return 0;
            case Status::WARN:  return 1;
            case Status::BLOCK: return 2;
        }
        return 0;
    }
    
    std::string status_string() const {
        switch (status()) {
            case Status::PASS:  return "PASS";
            case Status::WARN:  return "WARN";
            case Status::BLOCK: return "BLOCK";
        }
        return "UNKNOWN";
    }
};

/**
 * @brief Evaluates risk budget from scan findings
 */
class BudgetEvaluator {
public:
    /**
     * @brief Construct evaluator with policy
     * @param policy Risk policy to apply
     */
    explicit BudgetEvaluator(const Policy& policy);
    
    /**
     * @brief Evaluate findings from a log file
     * @param log_path Path to scan.log.jsonl
     * @return Budget evaluation result
     */
    BudgetResult evaluate(const std::string& log_path) const;
    
    /**
     * @brief Evaluate findings from parsed entries
     * @param findings Vector of finding objects
     * @return Budget evaluation result
     */
    BudgetResult evaluate_findings(const std::vector<nlohmann::json>& findings) const;
    
    /**
     * @brief Print budget report to stdout
     * @param result Budget result to report
     */
    static void print_report(const BudgetResult& result);

private:
    Policy policy_;
};

} // namespace budget