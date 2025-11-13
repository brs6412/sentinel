#pragma once
#include <string>
#include <map>
#include <vector>
#include <nlohmann/json.hpp>

namespace budget {

/**
 * @file policy.h
 * @brief Risk budget evaluation for security findings
 *
 * Assigns scores to findings based on their category and checks if the
 * total risk exceeds warning or blocking thresholds. Used to gate CI/CD
 * pipelines based on scan results.
 */

/**
 * Risk scoring policy configuration
 * @policy.h (12-25)
 */
struct Policy {
    // Score per finding category
    std::map<std::string, int> category_scores;

    // Thresholds
    int warn_threshold;
    int block_threshold;

    /**
     * Load policy from a YAML or JSON file
     * @policy.h (21)
     * @param policy_path Path to policy file
     * @return Loaded policy
     */
    static Policy load(const std::string& policy_path);

    /**
     * Get a default policy with reasonable scores
     * @policy.h (24)
     * @return Default policy
     */
    static Policy get_default();
};

/**
 * Result of evaluating findings against a risk budget
 * @policy.h (30-66)
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
 * Evaluates security findings against a risk budget
 * @policy.h (71-101)
 */
class BudgetEvaluator {
public:
    /**
     * Create an evaluator with a specific policy
     * @policy.h (77)
     * @param policy Risk policy to use for scoring
     */
    explicit BudgetEvaluator(const Policy& policy);

    /**
     * Evaluate findings from a log file
     * @policy.h (84)
     * @param log_path Path to scan.log.jsonl file
     * @return Evaluation result with scores and status
     */
    BudgetResult evaluate(const std::string& log_path) const;

    /**
     * Evaluate findings from already-parsed JSON objects
     * @policy.h (91)
     * @param findings List of finding JSON objects
     * @return Evaluation result with scores and status
     */
    BudgetResult evaluate_findings(const std::vector<nlohmann::json>& findings) const;

    /**
     * Print a human-readable budget report
     * @policy.h (97)
     * @param result Result to print
     */
    static void print_report(const BudgetResult& result);

private:
    Policy policy_;
};

} // namespace budget
