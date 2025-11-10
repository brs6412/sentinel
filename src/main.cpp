#include "core/http_client.h"
#include "core/crawler.h"
#include "logging/chain.h"
#include "artifacts/artifacts.h"
#include "artifacts/vuln_engine.h"
#include "budget/policy.h"
#include <schema/finding.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

std::string generate_run_id() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "run_" << std::put_time(std::gmtime(&time_t), "%Y%m%d_%H%M%S");
    return oss.str();
}

int generate_findings(std::string run_id, std::vector<CrawlResult>& results) {
    logging::ChainLogger logger("./logs/scan.log.jsonl", run_id);

    VulnEngine vulnEngine;
    std::vector<Finding> findings = vulnEngine.analyze(results);
       
    std::cout << "Generated " << findings.size() << " findings\n";

    // Write results to JSON
    nlohmann::json out = nlohmann::json::array();
    for (auto &f : findings) {
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
    return 0;
}

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
    generate_findings(run_id, results); 
    
    return 0;
}

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
