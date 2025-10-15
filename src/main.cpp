#include "core/http_client.h"
#include "core/crawler.h"
#include "logging/chain.h"
#include "artifacts/artifacts.h"
#include "budget/policy.h"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

// Generate unique run ID
std::string generate_run_id() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "run_" << std::put_time(std::gmtime(&time_t), "%Y%m%d_%H%M%S");
    return oss.str();
}

// Command: scan
int cmd_scan(int argc, char** argv) {
    std::string target;
    std::string outdir = "./artifacts";
    std::string openapi;
    
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--target" && i+1 < argc) {
            target = argv[++i];
        } else if (arg == "--out" && i+1 < argc) {
            outdir = argv[++i];
        } else if (arg == "--openapi" && i+1 < argc) {
            openapi = argv[++i];
        }
    }
    
    if (target.empty()) {
        std::cerr << "Error: --target required\n";
        return 2;
    }
    
    // Create output directory
    std::filesystem::create_directories(outdir);
    
    // Generate run ID
    std::string run_id = generate_run_id();
    std::cout << "Starting scan: " << run_id << "\n";
    std::cout << "Target: " << target << "\n";
    
    // Initialize hash-chained logger
    logging::ChainLogger logger(outdir + "/scan.log.jsonl", run_id);
    
    // Log scan start
    nlohmann::json scan_start;
    scan_start["target"] = target;
    scan_start["run_id"] = run_id;
    logger.append("scan_start", scan_start);
    
    // Setup HTTP client
    HttpClient::Options http_opts;
    http_opts.follow_redirects = true;
    http_opts.timeout_seconds = 15;
    http_opts.connect_timeout_seconds = 5;
    HttpClient client(http_opts);
    
    // Setup crawler
    Crawler crawler(client);
    crawler.add_seed(target);
    
    if (!openapi.empty()) {
        if (crawler.load_openapi_file(openapi)) {
            std::cout << "Loaded OpenAPI spec: " << openapi << "\n";
        } else {
            std::cerr << "Warning: Could not load OpenAPI file\n";
        }
    }
    
    // Run crawler
    std::cout << "Crawling...\n";
    auto results = crawler.run();
    std::cout << "Found " << results.size() << " pages\n";
    
    // Process results and generate findings
    std::vector<artifacts::Finding> findings;
    
    for (auto& r : results) {
        // Simple oracles (Person A's work would provide these)
        // For now, we'll create dummy findings to demonstrate Person B features
        
        // Check for missing security headers (dummy check)
        if (r.status >= 200 && r.status < 300) {
            artifacts::Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = r.url;
            f.category = "missing_security_header";
            f.method = "GET";
            f.headers["Accept"] = "text/html";
            f.evidence["header_checked"] = "X-Frame-Options";
            f.evidence["observed_value"] = nullptr;
            f.severity = "medium";
            f.confidence = 0.95;
            f.remediation_id = "headers";
            
            findings.push_back(f);
            
            // Log finding
            nlohmann::json finding_json;
            finding_json["id"] = f.id;
            finding_json["url"] = f.url;
            finding_json["category"] = f.category;
            finding_json["severity"] = f.severity;
            finding_json["confidence"] = f.confidence;
            finding_json["evidence"] = f.evidence;
            
            logger.append("finding_recorded", finding_json);
        }
    }
    
    std::cout << "Generated " << findings.size() << " findings\n";
    
    // Generate artifacts
    std::cout << "Generating reproduction artifacts...\n";
    
    // Generate repro.sh
    if (artifacts::ArtifactGenerator::generate_repro_script(
        findings, outdir + "/repro.sh")) {
        std::cout << "  ✓ repro.sh\n";
    }
    
    // Generate Catch2 tests
    if (artifacts::ArtifactGenerator::generate_catch2_tests(
        findings, run_id, outdir + "/repro_" + run_id + ".cpp")) {
        std::cout << "  ✓ repro_" << run_id << ".cpp\n";
    }
    
    // Write traditional scan results JSON
    nlohmann::json out = nlohmann::json::array();
    for (auto& r : results) {
        nlohmann::json j;
        j["url"] = r.url;
        j["status"] = r.status;
        j["links"] = nlohmann::json::array();
        for (auto& link : r.links) {
            j["links"].push_back(link);
        }
        j["forms"] = nlohmann::json::array();
        for (auto& form : r.forms) {
            nlohmann::json form_json;
            form_json["action"] = form.action;
            form_json["method"] = form.method;
            form_json["inputs"] = nlohmann::json::array();
            for (auto& iv : form.inputs) {
                form_json["inputs"].push_back({
                    {"name", iv.first}, 
                    {"value", iv.second}
                });
            }
            j["forms"].push_back(form_json);
        }
        out.push_back(j);
    }
    
    std::ofstream ofs(outdir + "/scan_results.json");
    ofs << out.dump(2);
    ofs.close();
    
    // Generate manifest
    if (artifacts::ArtifactGenerator::generate_manifest(
        outdir, outdir + "/assets.manifest.json")) {
        std::cout << "  ✓ assets.manifest.json\n";
    }
    
    // Log scan completion
    nlohmann::json scan_end;
    scan_end["pages_crawled"] = results.size();
    scan_end["findings_count"] = findings.size();
    logger.append("scan_complete", scan_end);
    
    std::cout << "\nScan complete. Artifacts in: " << outdir << "/\n";
    return 0;
}

// Command: verify
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
        std::cerr << "❌ Verification failed\n";
        return 1;
    }
}

// Command: budget
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
        policy = budget::Policy::get_default();
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
        std::cerr << "  sentinel scan --target URL [--out DIR] [--openapi FILE]\n";
        std::cerr << "  sentinel verify <log-file.jsonl>\n";
        std::cerr << "  sentinel budget [--policy FILE] <log-file.jsonl>\n";
        return 2;
    }
    
    std::string command = argv[1];
    
    if (command == "scan") {
        return cmd_scan(argc, argv);
    } else if (command == "verify") {
        return cmd_verify(argc, argv);
    } else if (command == "budget") {
        return cmd_budget(argc, argv);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        return 2;
    }
}