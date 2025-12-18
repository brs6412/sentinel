#include "core/http_client.h"
#include "core/crawler.h"
#include "core/vuln_engine.h"
#include "logging/chain.h"
#include "artifacts/artifacts.h"
#include "budget/policy.h"
#include <schema/finding.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

/**
 * @brief Generates a unique identifier for a program run based on current UTC datetime
 * @return A string representing the run identifier
 */
std::string generate_run_id() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "run_" << std::put_time(std::gmtime(&time_t), "%Y%m%d_%H%M%S");
    return oss.str();
}

/**
 * @brief Analyzes crawl results to generate vulnerability findings and related artifacts
 * @param client Reference to an HTTP client used for analysis
 * @param run_id Identifier for the current program run
 * @param results Vector of crawl results to be analyzed
 * @return Status code (0 on success)
 */
/**
 * @brief Read callback URL from scanner.yaml configuration file
 * @param config_path Path to scanner.yaml file
 * @return Callback URL string, or empty string if not configured or file not found
 */
std::string read_callback_url(const std::string& config_path) {
    std::ifstream in(config_path);
    if (!in.is_open()) {
        return "";
    }
    
    std::string line;
    bool in_oob_section = false;
    while (std::getline(in, line)) {
        // Remove comments
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        if (line.empty()) continue;
        
        // Check for callback_url field
        if (line.find("callback_url:") == 0) {
            std::string value = line.substr(12);  // Skip "callback_url:"
            // Trim whitespace and remove quotes
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            if (value.size() >= 2 && value[0] == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }
            return value;
        }
    }
    
    return "";
}

int generate_findings(HttpClient& client, std::string run_id, std::vector<CrawlResult>& results) {
    // Create output directories
    std::filesystem::create_directories("./out/reports");
    logging::ChainLogger logger("./out/reports/sentinel_chain.jsonl", run_id);

    VulnEngine vulnEngine(client);
    
    // Read callback URL from scanner.yaml if configured
    std::string callback_url = read_callback_url("config/scanner.yaml");
    if (!callback_url.empty()) {
        vulnEngine.setCallbackUrl(callback_url);
        std::cout << "OOB detection enabled with callback URL: " << callback_url << "\n";
    }
    
    std::vector<Finding> findings = vulnEngine.analyze(results);

    std::cout << "Generated " << findings.size() << " findings\n";

    // Create output directories
    std::filesystem::create_directories("./out/tests");
    std::filesystem::create_directories("./out/reports");

    // Write results to JSON and create mapping of aggregated URLs to findings
    std::map<std::string, std::vector<std::pair<std::string, nlohmann::json>>> grouped;
    nlohmann::json out = nlohmann::json::array();
    for (auto &f : findings) {
        const std::string& url = f.url;
        const std::string& category = f.category;
        const nlohmann::json& evidence = f.evidence;
        grouped[url].push_back({category, evidence});

        // Log finding to chain logger
        nlohmann::json finding_payload;
        finding_payload["id"] = f.id;
        finding_payload["url"] = f.url;
        finding_payload["category"] = f.category;
        finding_payload["severity"] = f.severity;
        finding_payload["confidence"] = f.confidence;
        finding_payload["method"] = f.method;
        finding_payload["evidence"] = f.evidence;
        logger.append("finding_recorded", finding_payload);

        // Generate markdown test file for this finding
        std::string test_file = "./out/tests/" + f.id + ".md";
        std::ofstream test_out(test_file);
        if (test_out.is_open()) {
            test_out << "# Test: " << f.category << "\n\n";
            test_out << "**Finding ID:** " << f.id << "\n\n";
            test_out << "**Target URL:** " << f.url << "\n\n";
            test_out << "**Severity:** " << f.severity << "\n\n";
            test_out << "**Category:** " << f.category << "\n\n";

            // Generate test snippet from evidence if available
            std::string test_snippet;
            if (f.category == "missing_security_header") {
                std::string header = evidence.value("header_checked", "X-Frame-Options");
                test_snippet = "curl -s -D - " + f.url + " | grep -iE '^" + header + ":'";
            } else if (f.category == "unsafe_cookie") {
                test_snippet = "curl -s -D - " + f.url + " | grep -i 'Set-Cookie:'";
            } else if (f.category == "cors_misconfiguration") {
                test_snippet = "curl -s -D - -H 'Origin: https://evil.com' " + f.url + " | grep -i 'Access-Control-Allow-Origin:'";
            } else {
                test_snippet = "curl -s -D - " + f.url;
            }

            test_out << "## Test Command\n\n";
            test_out << "```bash\n";
            test_out << test_snippet << "\n";
            test_out << "```\n\n";

            // Remediation summary
            test_out << "## Remediation\n\n";
            if (f.category == "missing_security_header") {
                std::string header = evidence.value("header_checked", "X-Frame-Options");
                test_out << "Add the `" << header << "` header to responses.\n\n";
                if (header == "X-Frame-Options") {
                    test_out << "Example: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`\n";
                } else if (header == "Content-Security-Policy") {
                    test_out << "Example: `Content-Security-Policy: frame-ancestors 'none'`\n";
                }
            } else if (f.category == "unsafe_cookie") {
                test_out << "Ensure cookies have `Secure`, `HttpOnly`, and `SameSite` attributes set appropriately.\n";
            } else if (f.category == "cors_misconfiguration") {
                test_out << "Restrict CORS `Access-Control-Allow-Origin` to specific trusted origins, avoid wildcards.\n";
            } else {
                test_out << "Review and fix the security issue identified.\n";
            }

            test_out.close();
        }

        nlohmann::json j;
        j["id"] = f.id;
        j["url"] = f.url;
        j["category"] = f.category;
        j["method"] = f.method;
        j["headers"] = nlohmann::json::array();
        for (const auto& [name,value] : f.headers) {
            j["headers"].push_back({name, value});
        }
        j["body"] = f.body;
        j["evidence"] = f.evidence;
        j["severity"] = f.severity;
        j["confidence"] = f.confidence;
        j["remediation_id"] = f.remediation_id;
        out.push_back(j);
    }

    std::ofstream ofs("./artifacts/vuln_findings.jsonl");
    ofs << out.dump(2);
    ofs.close();


    // Generate artifacts
    std::cout << "Generating reproduction artifacts...\n";

    // Generate repro.sh
    if (artifacts::ArtifactGenerator::generate_repro_script(
        findings, "./artifacts/repro.sh")) {
        std::cout << "  ✓ repro.sh\n";
    }

    // Generate Catch2 tests
    if (artifacts::ArtifactGenerator::generate_catch2_tests(
        findings, run_id, "./artifacts/repro_" + run_id + ".cpp")) {
        std::cout << "  ✓ repro_" << run_id << ".cpp\n";
    }

    // Generate markdown test files
    std::cout << "Generating test files...\n";
    int test_files_generated = 0;
    for (const auto& f : findings) {
        std::string test_file = "./out/tests/" + f.id + ".md";
        if (std::filesystem::exists(test_file)) {
            test_files_generated++;
        }
    }
    if (test_files_generated > 0) {
        std::cout << "  ✓ " << test_files_generated << " test file(s) in out/tests/\n";
    }

    // Verify chain integrity
    if (!logging::ChainLogger::verify("./out/reports/sentinel_chain.jsonl")) {
        std::cerr << "Warning: Chain verification failed - log may have been tampered with\n";
    }

    // Evaluate budget
    try {
        auto policy = budget::Policy::load("config/policy.yaml");
        budget::BudgetEvaluator evaluator(policy);

        std::vector<nlohmann::json> jfindings;
        for (const auto& f : findings) {
            nlohmann::json j;
            j["id"] = f.id;
            j["url"] = f.url;
            j["category"] = f.category;
            j["severity"] = f.severity;
            j["confidence"] = f.confidence;
            jfindings.push_back(j);
        }

        auto result = evaluator.evaluate_findings(jfindings);
        std::cout << "Total risk points: " << result.total_score << " (warn: " << policy.warn_threshold << ", block: " << policy.block_threshold << ")\n";

        // Return appropriate exit code based on budget
        return result.exit_code();
    } catch (const std::exception& e) {
        std::cerr << "Warning: Budget evaluation failed: " << e.what() << "\n";
        return 0; // Continue with success if budget evaluation fails
    }
}

/**
 * @brief Executes a full scan workflow on a specified target
 * @param argc Argument count from command line
 * @param argv Argument values from command line
 * @return 0 on success, 2 if required arguments are missing
 */
int run_scan(int argc, char** argv) {
    std::string target;
    std::string outfile = "scan_results.jsonl";
    std::string openapi;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--target" && i + 1 < argc) {
            target = argv[++i];
            continue;
        }
        if (a == "--out" && i + 1 < argc) {
            outfile = argv[++i];
            continue;
        }
        if (a == "--openapi" && i + 1 < argc) {
            openapi = argv[++i];
            continue;
        }
    }

    if (target.empty()) {
        std::cerr << "Error: --target required\n";
        return 2;
    }

    std::filesystem::create_directories("./artifacts");
    std::filesystem::create_directories("./logs");

    std::string run_id = generate_run_id();
    std::cout << "Starting scan: " << run_id << "\n";
    std::cout << "Target: " << target << "\n";

    HttpClient::Options opts;
    opts.follow_redirects = true;
    opts.timeout_seconds = 15;
    opts.connect_timeout_seconds = 5;
    HttpClient client(opts);

    Crawler crawler(client);
    crawler.add_seed(target);

    if (!openapi.empty()) {
        crawler.load_openapi_file(openapi);
    }

    std::cout << "Crawling...\n";
    auto results = crawler.run();
    std::cout << "Finished crawl.\n";

    // Write results to JSON
    nlohmann::json out = nlohmann::json::array();
    for (auto &r : results) {
        nlohmann::json j;
        j["url"] = r.url;
        j["method"] = r.method;
        j["params"] = nlohmann::json::array();
        for (const auto& [name,value] : r.params) {
            j["params"].push_back({name, value});
        }
        j["headers"] = nlohmann::json::array();
        for (const auto& [name,value] : r.headers) {
            j["headers"].push_back({name, value});
        }
        j["cookies"] = r.cookies;
        j["source"] = r.source;
        j["discovery_path"] = r.discovery_path;
        j["timestamp"] = r.timestamp;
        j["hash"] = r.hash;
        out.push_back(j);
    }

    std::ofstream ofs("./artifacts/" + outfile);
    ofs << out.dump(2);
    ofs.close();

    std::cout << "Generating findings...\n";
    int exit_code = generate_findings(client, run_id, results);

    return exit_code;
}

/**
 * @brief Verifies the integrity of a JSONL log file
 * @param argc Argument count from the command line
 * @param argv Argument values from the command line; argv[2] should be the log file path
 * @return 0 if verification succeeds, 1 if it fails, 2 if usage is incorrect
 */
int cmd_verify(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: sentinel verify <log-file.jsonl>\n";
        return 2;
    }

    std::string log_path = argv[2];

    std::cout << "Verifying log: " << log_path << "\n";

    if (logging::ChainLogger::verify(log_path)) {
        return 0;
    } else {
        std::cerr << "Verification failed\n";
        return 1;
    }
}

/**
 * @brief Evaluates scan budget compliance against a log file and optional policy
 * @param argc Argument count from the command line
 * @param argv Argument values from the command line; argv[2] and beyond specify policy and log file
 * @return Exit code reflecting budget compliance (0 for compliant, non-zero for violations, 2 for usage errors)
 */
int cmd_budget(int argc, char** argv) {
    std::string policy_path;
    std::string log_path;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--policy" && i+1 < argc) {
            policy_path = argv[++i];
        } else if (log_path.empty()) {
            log_path = arg;
        }
    }

    if (log_path.empty()) {
        std::cerr << "Usage: sentinel budget [--policy policy.yml] <log-file.jsonl>\n";
        return 2;
    }

    // Load policy
    budget::Policy policy;
    if (!policy_path.empty()) {
        std::cout << "Loading policy: " << policy_path << "\n";
        policy = budget::Policy::load(policy_path);
    } else {
        std::cout << "Using default policy\n";
    }

    // Evaluate budget
    budget::BudgetEvaluator evaluator(policy);
    auto result = evaluator.evaluate(log_path);

    // Print report
    budget::BudgetEvaluator::print_report(result);

    // Return appropriate exit code
    return result.exit_code();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage:\n";
        std::cerr << "  sentinel scan --target URL [--out FILE] [--openapi FILE]\n";
        std::cerr << "  sentinel verify <log-file.jsonl>\n";
        std::cerr << "  sentinel budget [--policy FILE] <log-file.jsonl>\n";
        return 2;
    }

    std::string command = argv[1];

    if (command == "scan") {
        return run_scan(argc, argv);
    } else if (command == "verify") {
        return cmd_verify(argc, argv);
    } else if (command == "budget") {
        return cmd_budget(argc, argv);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        return 2;
    }
}
