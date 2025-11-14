/**
 * @file test_budget.cpp
 * @brief Unit tests for risk budget evaluation
 *
 * Tests policy loading, score calculation, threshold checking, and
 * evaluation from log files. Verifies that findings are scored correctly
 * and thresholds trigger the right status.
 */

#include <catch2/catch.hpp>
#include "budget/policy.h"
#include <filesystem>
#include <fstream>

using namespace budget;
namespace fs = std::filesystem;

/**
 * Test that the default policy has reasonable scores and thresholds
 * @test_budget.cpp (22-41)
 */
TEST_CASE("Default policy has expected values", "[budget]") {
    auto policy = Policy::get_default();

    SECTION("Category scores are defined") {
        REQUIRE(policy.category_scores.count("missing_security_header") > 0);
        REQUIRE(policy.category_scores.count("unsafe_cookie") > 0);
        REQUIRE(policy.category_scores.count("cors_misconfiguration") > 0);

        REQUIRE(policy.category_scores["missing_security_header"] == 2);
        REQUIRE(policy.category_scores["unsafe_cookie"] == 1);
        REQUIRE(policy.category_scores["cors_misconfiguration"] == 3);
    }

    SECTION("Thresholds are reasonable") {
        REQUIRE(policy.warn_threshold > 0);
        REQUIRE(policy.block_threshold > policy.warn_threshold);
        REQUIRE(policy.warn_threshold == 3);
        REQUIRE(policy.block_threshold == 5);
    }
}

/**
 * Test loading a policy from a JSON file
 * @test_budget.cpp (47-75)
 */
TEST_CASE("Policy loads from JSON file", "[budget]") {
    std::string policy_file = "test_policy.json";

    // Create test policy file
    {
        nlohmann::json policy_json;
        policy_json["category_scores"] = {
            {"test_category", 5},
            {"another_category", 10}
        };
        policy_json["warn_threshold"] = 15;
        policy_json["block_threshold"] = 25;

        std::ofstream out(policy_file);
        out << policy_json.dump(2);
    }

    SECTION("Policy is loaded correctly") {
        auto policy = Policy::load(policy_file);

        REQUIRE(policy.category_scores["test_category"] == 5);
        REQUIRE(policy.category_scores["another_category"] == 10);
        REQUIRE(policy.warn_threshold == 15);
        REQUIRE(policy.block_threshold == 25);
    }

    // Cleanup
    fs::remove(policy_file);
}

/**
 * Test that loading a non-existent file returns default policy
 * @test_budget.cpp (81-88)
 */
TEST_CASE("Policy handles missing file gracefully", "[budget]") {
    auto policy = Policy::load("nonexistent_file.json");

    // Should return default policy
    REQUIRE(policy.category_scores.size() > 0);
    REQUIRE(policy.warn_threshold == 3);
    REQUIRE(policy.block_threshold == 5);
}

/**
 * Test score calculation for various finding combinations
 * @test_budget.cpp (94-195)
 */
TEST_CASE("BudgetEvaluator calculates scores correctly", "[budget]") {
    Policy policy = Policy::get_default();
    BudgetEvaluator evaluator(policy);

    SECTION("Empty findings result in zero score") {
        std::vector<nlohmann::json> findings;
        auto result = evaluator.evaluate_findings(findings);

        REQUIRE(result.total_score == 0);
        REQUIRE(result.status() == BudgetResult::Status::PASS);
        REQUIRE(result.exit_code() == 0);
        REQUIRE_FALSE(result.exceeds_warn);
        REQUIRE_FALSE(result.exceeds_block);
    }

    SECTION("Single finding is scored") {
        std::vector<nlohmann::json> findings;
        nlohmann::json f1;
        f1["category"] = "missing_security_header";
        f1["severity"] = "medium";
        findings.push_back(f1);

        auto result = evaluator.evaluate_findings(findings);

        REQUIRE(result.total_score == 2); // Default score for this category
        REQUIRE(result.category_counts["missing_security_header"] == 1);
        REQUIRE(result.category_scores["missing_security_header"] == 2);
    }

    SECTION("Multiple findings accumulate scores") {
        std::vector<nlohmann::json> findings;

        // Add multiple findings
        for (int i = 0; i < 3; i++) {
            nlohmann::json f;
            f["category"] = "unsafe_cookie";
            findings.push_back(f);
        }

        nlohmann::json f2;
        f2["category"] = "cors_misconfiguration";
        findings.push_back(f2);

        auto result = evaluator.evaluate_findings(findings);

        // 3 * 1 (unsafe_cookie) + 1 * 3 (cors) = 6
        REQUIRE(result.total_score == 6);
        REQUIRE(result.category_counts["unsafe_cookie"] == 3);
        REQUIRE(result.category_counts["cors_misconfiguration"] == 1);
        REQUIRE(result.category_scores["unsafe_cookie"] == 3);
        REQUIRE(result.category_scores["cors_misconfiguration"] == 3);
    }

    SECTION("Thresholds trigger correct status") {
        std::vector<nlohmann::json> findings;

        // Add enough to exceed warn but not block (default: warn=3, block=5)
        nlohmann::json f1;
        f1["category"] = "missing_security_header"; // score = 2
        findings.push_back(f1);

        nlohmann::json f2;
        f2["category"] = "unsafe_cookie"; // score = 1
        findings.push_back(f2);

        auto result = evaluator.evaluate_findings(findings);

        // Total = 3, should trigger WARN
        REQUIRE(result.total_score == 3);
        REQUIRE(result.status() == BudgetResult::Status::WARN);
        REQUIRE(result.exit_code() == 1);
        REQUIRE(result.exceeds_warn);
        REQUIRE_FALSE(result.exceeds_block);

        // Add one more to exceed block threshold
        nlohmann::json f3;
        f3["category"] = "cors_misconfiguration"; // score = 3
        findings.push_back(f3);

        result = evaluator.evaluate_findings(findings);

        // Total = 6, should trigger BLOCK
        REQUIRE(result.total_score == 6);
        REQUIRE(result.status() == BudgetResult::Status::BLOCK);
        REQUIRE(result.exit_code() == 2);
        REQUIRE(result.exceeds_warn);
        REQUIRE(result.exceeds_block);
    }

    SECTION("Unknown categories are not scored") {
        std::vector<nlohmann::json> findings;
        nlohmann::json f;
        f["category"] = "unknown_vulnerability_type";
        findings.push_back(f);

        auto result = evaluator.evaluate_findings(findings);

        REQUIRE(result.total_score == 0);
        REQUIRE(result.category_counts["unknown_vulnerability_type"] == 1);
        REQUIRE(result.status() == BudgetResult::Status::PASS);
    }
}

/**
 * Test evaluating findings from a JSONL log file
 * @test_budget.cpp (201-275)
 */
TEST_CASE("BudgetEvaluator evaluates from log file", "[budget]") {
    std::string log_file = "test_budget.jsonl";

    // Create test log with findings
    {
        std::ofstream out(log_file);

        // Log entry 1: scan start
        nlohmann::json entry1;
        entry1["event_type"] = "scan_start";
        entry1["run_id"] = "test_run";
        entry1["timestamp"] = "2025-01-01T00:00:00Z";
        entry1["prev_hash"] = "sha256:genesis";
        entry1["entry_hash"] = "sha256:hash1";
        entry1["payload"] = nlohmann::json::object();
        out << entry1.dump() << "\n";

        // Log entry 2: finding
        nlohmann::json entry2;
        entry2["event_type"] = "finding_recorded";
        entry2["run_id"] = "test_run";
        entry2["timestamp"] = "2025-01-01T00:01:00Z";
        entry2["prev_hash"] = "sha256:hash1";
        entry2["entry_hash"] = "sha256:hash2";
        entry2["payload"]["category"] = "missing_security_header";
        entry2["payload"]["severity"] = "medium";
        out << entry2.dump() << "\n";

        // Log entry 3: another finding
        nlohmann::json entry3;
        entry3["event_type"] = "finding_recorded";
        entry3["run_id"] = "test_run";
        entry3["timestamp"] = "2025-01-01T00:02:00Z";
        entry3["prev_hash"] = "sha256:hash2";
        entry3["entry_hash"] = "sha256:hash3";
        entry3["payload"]["category"] = "cors_misconfiguration";
        entry3["payload"]["severity"] = "high";
        out << entry3.dump() << "\n";

        // Log entry 4: non-finding event
        nlohmann::json entry4;
        entry4["event_type"] = "scan_complete";
        entry4["run_id"] = "test_run";
        entry4["timestamp"] = "2025-01-01T00:03:00Z";
        entry4["prev_hash"] = "sha256:hash3";
        entry4["entry_hash"] = "sha256:hash4";
        entry4["payload"]["pages"] = 10;
        out << entry4.dump() << "\n";
    }

    SECTION("Evaluates findings from log") {
        Policy policy = Policy::get_default();
        BudgetEvaluator evaluator(policy);

        auto result = evaluator.evaluate(log_file);

        // Should have 2 findings: header (2) + cors (3) = 5
        REQUIRE(result.total_score == 5);
        REQUIRE(result.category_counts.size() == 2);
        REQUIRE(result.status() == BudgetResult::Status::BLOCK);
    }

    SECTION("Handles non-existent file") {
        Policy policy = Policy::get_default();
        BudgetEvaluator evaluator(policy);

        auto result = evaluator.evaluate("nonexistent.jsonl");

        // Should return empty result
        REQUIRE(result.total_score == 0);
    }

    // Cleanup
    fs::remove(log_file);
}

/**
 * Test that status methods return correct values for each state
 * @test_budget.cpp (281-313)
 */
TEST_CASE("BudgetResult status methods work correctly", "[budget]") {
    BudgetResult result;

    SECTION("PASS status") {
        result.total_score = 2;
        result.exceeds_warn = false;
        result.exceeds_block = false;

        REQUIRE(result.status() == BudgetResult::Status::PASS);
        REQUIRE(result.status_string() == "PASS");
        REQUIRE(result.exit_code() == 0);
    }

    SECTION("WARN status") {
        result.total_score = 4;
        result.exceeds_warn = true;
        result.exceeds_block = false;

        REQUIRE(result.status() == BudgetResult::Status::WARN);
        REQUIRE(result.status_string() == "WARN");
        REQUIRE(result.exit_code() == 1);
    }

    SECTION("BLOCK status") {
        result.total_score = 10;
        result.exceeds_warn = true;
        result.exceeds_block = true;

        REQUIRE(result.status() == BudgetResult::Status::BLOCK);
        REQUIRE(result.status_string() == "BLOCK");
        REQUIRE(result.exit_code() == 2);
    }
}

/**
 * Test evaluation with a custom policy that has different thresholds
 * @test_budget.cpp (319-365)
 */
TEST_CASE("Custom policy with different thresholds", "[budget]") {
    std::string policy_file = "test_custom_policy.json";

    {
        nlohmann::json policy_json;
        policy_json["category_scores"] = {
            {"critical_vuln", 100},
            {"minor_issue", 1}
        };
        policy_json["warn_threshold"] = 50;
        policy_json["block_threshold"] = 100;

        std::ofstream out(policy_file);
        out << policy_json.dump(2);
    }

    auto policy = Policy::load(policy_file);
    BudgetEvaluator evaluator(policy);

    SECTION("Critical vuln triggers block") {
        std::vector<nlohmann::json> findings;
        nlohmann::json f;
        f["category"] = "critical_vuln";
        findings.push_back(f);

        auto result = evaluator.evaluate_findings(findings);

        REQUIRE(result.total_score == 100);
        REQUIRE(result.status() == BudgetResult::Status::BLOCK);
    }

    SECTION("Minor issues don't trigger warn") {
        std::vector<nlohmann::json> findings;
        for (int i = 0; i < 10; i++) {
            nlohmann::json f;
            f["category"] = "minor_issue";
            findings.push_back(f);
        }

        auto result = evaluator.evaluate_findings(findings);

        REQUIRE(result.total_score == 10);
        REQUIRE(result.status() == BudgetResult::Status::PASS);
    }

    fs::remove(policy_file);
}

/**
 * Test that malformed log entries are skipped gracefully
 * @test_budget.cpp (371-390)
 */
TEST_CASE("BudgetEvaluator handles malformed log entries", "[budget]") {
    std::string log_file = "test_malformed.jsonl";

    {
        std::ofstream out(log_file);
        out << "not valid json\n";
        out << "{\"event_type\": \"finding_recorded\", \"payload\": {\"category\": \"test\"}}\n";
        out << "another bad line\n";
    }

    Policy policy = Policy::get_default();
    BudgetEvaluator evaluator(policy);

    auto result = evaluator.evaluate(log_file);

    // Should skip malformed lines and process valid one
    REQUIRE(result.category_counts.size() == 1);

    fs::remove(log_file);
}
