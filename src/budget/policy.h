#pragma once
#include <string>
#include <map>
#include <vector>
#include <nlohmann/json.hpp>

namespace budget {

// Risk budget evaluation for security findings.
// Assigns scores to findings based on their category and checks if the
// total risk exceeds warning or blocking thresholds. Used to gate CI/CD
// pipelines based on scan results.

struct Policy {
    // Score per finding category
    std::map<std::string, int> category_scores;

    // Thresholds
    int warn_threshold;
    int block_threshold;

    /**
     * @brief Load policy from a YAML or JSON file
     * @param policy_path Path to policy file
     * @return Loaded policy
     */
    static Policy load(const std::string& policy_path);

    /**
     * @brief Get a default policy with reasonable scores
     * @return Default policy
     */
    static Policy get_default();
};

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

class BudgetEvaluator {
public:
    /**
     * @brief Create an evaluator with a specific policy
     * @param policy Risk policy to use for scoring
     */
    explicit BudgetEvaluator(const Policy& policy);

    /**
     * @brief Evaluate findings from a log file
     * @param log_path Path to scan.log.jsonl file
     * @return Evaluation result with scores and status
     */
    BudgetResult evaluate(const std::string& log_path) const;

    /**
     * @brief Evaluate findings from already-parsed JSON objects
     * @param findings List of finding JSON objects
     * @return Evaluation result with scores and status
     */
    BudgetResult evaluate_findings(const std::vector<nlohmann::json>& findings) const;

    /**
     * @brief Print a human-readable budget report
     * @param result Result to print
     */
    static void print_report(const BudgetResult& result);

private:
    Policy policy_;
};

} // namespace budget
