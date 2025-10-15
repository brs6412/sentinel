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
    std::string outdir = "./artifacts";
    std::string openapi;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[1];
        if (a == "--target" && i+1 < argc) {
            target = argv[++i];
            continue;
        } else if (a == "--out" && i + 1 < argc) {
            outdir = argv[++i];
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

    std::filesystem::create_directories(outdir);

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
        j["status"] = r.status;
        j["links"] = nlohmann::json::array();
        for (auto &link : r.links) {
            j["links"].push_back(link);
        }
        j["forms"] = nlohmann::json::array();
        for (auto &form : r.forms) {
            nlohmann::json form_json;
            form_json["action"] = form.action;
            form_json["method"] = form.method;
            form_json["inputs"] = nlohmann::json::array();
            for (auto &iv : form.inputs) {
                form_json["inputs"].push_back({{"name", iv.first}, {"value", iv.second}});
            }
            j["forms"].push_back(form_json);
        }
        out.push_back(j);
    }

    std::ofstream ofs(outdir + "/scan_results.json");
    ofs << out.dump(2);
    ofs.close();
    return 0;
}
