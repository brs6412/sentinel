/**
 * @file main.cpp
 * @brief CLI tool for Ollama LLM integration
 */

#include "llm/ollama_client.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

static void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " --model <name> --prompt <text> [--json]\n"
              << "\n"
              << "Options:\n"
              << "  --model <name>    Model name (required, e.g., llama3:instruct)\n"
              << "  --prompt <text>   Prompt text (required)\n"
              << "  --json            Expect/print JSON response\n"
              << "\n"
              << "Environment:\n"
              << "  OLLAMA_HOST       Ollama server URL (default: http://127.0.0.1:11434)\n";
}

int main(int argc, char** argv) {
    std::string model;
    std::string prompt;
    bool expect_json = false;

    // Simple argv parsing (no external libs)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--model") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --model requires a value\n";
                print_usage(argv[0]);
                return 1;
            }
            model = argv[++i];
        } else if (std::strcmp(argv[i], "--prompt") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --prompt requires a value\n";
                print_usage(argv[0]);
                return 1;
            }
            prompt = argv[++i];
        } else if (std::strcmp(argv[i], "--json") == 0) {
            expect_json = true;
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (model.empty() || prompt.empty()) {
        std::cerr << "Error: --model and --prompt are required\n";
        print_usage(argv[0]);
        return 1;
    }

    try {
        // Create Ollama client (reads OLLAMA_HOST env var or defaults)
        llm::OllamaClient client;

        // Check health first
        if (!client.IsHealthy()) {
            std::cerr << "Error: Ollama server is not reachable. "
                      << "Check OLLAMA_HOST environment variable or ensure Ollama is running.\n";
            return 1;
        }

        // Generate response
        std::string response = client.Generate(model, prompt);

        // Output result
        if (expect_json) {
            // Try to parse and pretty-print JSON
            try {
                auto json_obj = nlohmann::json::parse(response);
                std::cout << json_obj.dump(2) << std::endl;
            } catch (...) {
                // Not JSON, wrap in JSON object
                nlohmann::json wrapper;
                wrapper["response"] = response;
                std::cout << wrapper.dump(2) << std::endl;
            }
        } else {
            std::cout << response << std::endl;
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

