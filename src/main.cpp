#include "core/http_client.h"
#include "core/crawler.h"
#include <iostream>
#include <filesystem>
#include <fstream>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: sentinel scan --target URL --out artifacts/ [--openapi file.json]\n";
        return 2;
    }

    std::string target;
    std::string outfile = "scan_results.jsonl";
    std::string openapi;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[1];
        if (a == "--target" && i+1 < argc) {
            target = argv[++i];
            continue;
        } else if (a == "--out" && i + 1 < argc) {
            outfile = argv[++i];
            continue;
        } else if (a == "--openapi" && i + 1 < argc) {
            openapi = argv[++i];
            continue;
        }
    }
    if (target.empty()) {
        std::cerr << "missing --target\n";
        return 2;
    }

    std::filesystem::create_directories("./artifacts");

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

    auto results = crawler.run();

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
    return 0;
}
