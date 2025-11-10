#pragma once

#include <string>
#include <optional>
#include <chrono>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>

// httplib.h is a header-only library
#include "../../third_party/httplib.h"
#include <nlohmann/json.hpp>

namespace llm {

/**
 * @file ollama_client.h
 * @brief HTTP client for talking to Ollama LLM servers
 *
 * Handles health checks and text generation via Ollama's REST API.
 * Supports JSON schema for structured outputs and configurable timeouts.
 */

/**
 * HTTP client for Ollama API
 * @ollama_client.h (24-186)
 *
 * Talks to an Ollama server over HTTP. Can check if it's running and
 * generate text using any model the server has available.
 */
class OllamaClient {
public:
    /**
     * Create a client pointing to an Ollama server
     * @ollama_client.h (31-33)
     * @param host Server URL like "http://127.0.0.1:11434". If empty, uses OLLAMA_HOST
     *             env var or defaults to localhost:11434
     */
    explicit OllamaClient(const std::string& host = "") : host_(host.empty() ? get_default_host() : host) {
        parse_host();
    }

    /**
     * Check if the Ollama server is up and responding
     * @ollama_client.h (39-50)
     * @return true if server responds to /api/tags, false otherwise
     */
    bool IsHealthy() {
        try {
            httplib::Client cli(hostname_.c_str(), port_);
            cli.set_connection_timeout(2, 0);  // 2 second timeout
            cli.set_read_timeout(2, 0);

            auto res = cli.Get("/api/tags");
            return res && res->status == 200;
        } catch (...) {
            return false;
        }
    }

    /**
     * Generate text using the specified model
     * @ollama_client.h (62-131)
     * @param model Model name like "llama3.1" or "mistral"
     * @param prompt What to ask the model
     * @param json_schema Optional JSON schema if you want structured output
     * @param timeout How long to wait before giving up (default 5 seconds)
     * @param stream Whether to stream the response (not implemented yet)
     * @return The generated text
     * @throws std::runtime_error if network fails, server returns error, or response is invalid JSON
     */
    std::string Generate(
        const std::string& model,
        const std::string& prompt,
        std::optional<std::string> json_schema = std::nullopt,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000),
        bool stream = false
    ) {
        if (model.empty() || prompt.empty()) {
            throw std::runtime_error("model and prompt must be non-empty");
        }

        httplib::Client cli(hostname_.c_str(), port_);
        cli.set_connection_timeout(static_cast<int>(timeout.count() / 1000),
                                   static_cast<int>((timeout.count() % 1000) * 1000));
        cli.set_read_timeout(static_cast<int>(timeout.count() / 1000),
                            static_cast<int>((timeout.count() % 1000) * 1000));

        nlohmann::json request_body;
        request_body["model"] = model;
        request_body["prompt"] = prompt;
        request_body["stream"] = stream;

        nlohmann::json options;
        options["temperature"] = 0.0;
        request_body["options"] = options;

        // Handle JSON schema if provided
        if (json_schema.has_value() && !json_schema->empty()) {
            try {
                // Try to parse schema to validate it
                auto schema_obj = nlohmann::json::parse(*json_schema);
                request_body["format"] = "json";
                request_body["options"]["json_schema"] = schema_obj;
            } catch (const nlohmann::json::parse_error& e) {
                std::cerr << "[OllamaClient] Warning: Invalid JSON schema, falling back to raw text: "
                          << e.what() << std::endl;
            }
        }

        httplib::Headers headers;
        headers.emplace("Content-Type", "application/json");

        auto res = cli.Post("/api/generate", headers, request_body.dump(), "application/json");

        if (!res) {
            throw std::runtime_error("Network error: failed to connect to Ollama server");
        }

        if (res->status != 200) {
            std::ostringstream err;
            err << "HTTP error " << res->status << ": " << res->body;
            throw std::runtime_error(err.str());
        }

        try {
            auto response_json = nlohmann::json::parse(res->body);

            // Ollama /api/generate returns {"response": "...", "done": true, ...}
            if (response_json.contains("response") && response_json["response"].is_string()) {
                return response_json["response"].get<std::string>();
            }

            // Fallback: if no "response" field, return entire body as string
            return res->body;
        } catch (const nlohmann::json::parse_error& e) {
            std::ostringstream err;
            err << "JSON parse error: " << e.what() << " (response body: " << res->body << ")";
            throw std::runtime_error(err.str());
        }
    }

private:
    std::string host_;
    std::string hostname_;
    int port_;

    static std::string get_default_host() {
        const char* env_host = std::getenv("OLLAMA_HOST");
        if (env_host && std::strlen(env_host) > 0) {
            return std::string(env_host);
        }
        return "http://127.0.0.1:11434";
    }

    void parse_host() {
        // Simple URL parsing: extract hostname and port
        // Supports http://hostname:port or just hostname:port
        std::string url = host_;

        // Remove http:// or https:// prefix
        size_t scheme_pos = url.find("://");
        if (scheme_pos != std::string::npos) {
            url = url.substr(scheme_pos + 3);
        }

        // Extract hostname and port
        size_t colon_pos = url.find(':');
        if (colon_pos != std::string::npos) {
            hostname_ = url.substr(0, colon_pos);
            std::string port_str = url.substr(colon_pos + 1);
            // Remove any trailing path
            size_t slash_pos = port_str.find('/');
            if (slash_pos != std::string::npos) {
                port_str = port_str.substr(0, slash_pos);
            }
            try {
                port_ = std::stoi(port_str);
            } catch (...) {
                port_ = 11434;  // default Ollama port
            }
        } else {
            hostname_ = url;
            // Remove any trailing path
            size_t slash_pos = hostname_.find('/');
            if (slash_pos != std::string::npos) {
                hostname_ = hostname_.substr(0, slash_pos);
            }
            port_ = 11434;  // default Ollama port
        }

        if (hostname_.empty()) {
            hostname_ = "127.0.0.1";
        }
    }
};

}  // namespace llm

