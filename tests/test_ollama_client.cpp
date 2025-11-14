/**
 * @file test_ollama_client.cpp
 * @brief Unit tests for OllamaClient using a mock HTTP server
 *
 * Tests the OllamaClient's ability to communicate with an Ollama server,
 * handle errors, timeouts, and various response formats. Uses httplib to
 * spin up a mock server so we don't need a real Ollama instance running.
 */

#include "catch2/catch_amalgamated.hpp"
#include "llm/ollama_client.h"
#include "third_party/httplib.h"
#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>
#include <random>
#include <cstdlib>
#include <memory>
#include <atomic>

using namespace httplib;

/**
 * Mock Ollama server that runs in a background thread
 * @test_ollama_client.cpp (29-120)
 *
 * Starts an HTTP server on a random available port and implements the
 * /api/tags and /api/generate endpoints to simulate an Ollama server.
 */
class MockOllamaServer {
public:
    MockOllamaServer() : port_(0), server_(nullptr), thread_(nullptr) {}

    ~MockOllamaServer() {
        stop();
    }

    int start() {
        // Find available port by trying to bind
        Server test_server;
        for (port_ = 18000; port_ < 19000; ++port_) {
            if (test_server.bind_to_port("127.0.0.1", port_)) {
                break;
            }
        }
        if (port_ >= 19000) {
            return -1;
        }

        server_ = std::make_unique<Server>();

        // Setup /api/tags endpoint
        server_->Get("/api/tags", [](const Request&, Response& res) {
            res.status = 200;
            res.set_content(R"({"models":[{"name":"test-model"}]})", "application/json");
        });

        // Setup /api/generate endpoint
        server_->Post("/api/generate", [](const Request& req, Response& res) {
            try {
                auto body_json = nlohmann::json::parse(req.body);

                // Check if JSON format requested
                bool wants_json = false;
                if (body_json.contains("format") && body_json["format"] == "json") {
                    wants_json = true;
                }
                if (body_json.contains("options") && body_json["options"].contains("json_schema")) {
                    wants_json = true;
                }

                if (wants_json) {
                    nlohmann::json response;
                    response["response"] = R"({"reproducer":"curl -X GET 'https://example.com/test' -v"})";
                    response["done"] = true;
                    res.status = 200;
                    res.set_content(response.dump(), "application/json");
                } else {
                    nlohmann::json response;
                    response["response"] = "Generated text response";
                    response["done"] = true;
                    res.status = 200;
                    res.set_content(response.dump(), "application/json");
                }
            } catch (...) {
                res.status = 400;
                res.set_content("Invalid JSON", "text/plain");
            }
        });

        // Bind to port first
        if (!server_->bind_to_port("127.0.0.1", port_)) {
            return -1;
        }

        // Start server in background thread using listen_after_bind
        // This is non-blocking and sets is_running() when ready
        std::atomic<bool> server_started{false};
        std::atomic<bool> server_failed{false};
        
        thread_ = std::make_unique<std::thread>([this, &server_started, &server_failed]() {
            if (server_->listen_after_bind()) {
                server_started = true;
            } else {
                server_failed = true;
            }
        });

        // Wait for server to start - check is_running() and connection
        // Give it up to 10 seconds to start
        bool server_ready = false;
        for (int i = 0; i < 100; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // Check if server failed to start
            if (server_failed.load()) {
                return -1;
            }
            
            // Check if server is running
            if (server_->is_running()) {
                // Verify with actual connection
                httplib::Client test_client("127.0.0.1", port_);
                test_client.set_connection_timeout(1, 0);
                test_client.set_read_timeout(1, 0);
                if (auto res = test_client.Get("/api/tags")) {
                    if (res->status == 200) {
                        server_ready = true;
                        break;
                    }
                }
            }
        }
        
        if (!server_ready) {
            // Server didn't start in time
            return -1;
        }
        
        return port_;
    }

    void stop() {
        if (server_) {
            server_->stop();
        }
        if (thread_ && thread_->joinable()) {
            thread_->join();
        }
        server_.reset();
        thread_.reset();
    }

    int port() const { return port_; }
    std::string url() const {
        return "http://127.0.0.1:" + std::to_string(port_);
    }

private:
    int port_;
    std::unique_ptr<Server> server_;
    std::unique_ptr<std::thread> thread_;
};

/**
 * Test that IsHealthy() returns true when the server responds
 * @test_ollama_client.cpp (126-137)
 */
TEST_CASE("OllamaClient IsHealthy returns true when server is reachable", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    std::string host = "http://127.0.0.1:" + std::to_string(port);
    llm::OllamaClient client(host);

    REQUIRE(client.IsHealthy() == true);

    mock.stop();
}

/**
 * Test that Generate() returns a non-empty response
 * @test_ollama_client.cpp (143-152)
 */
TEST_CASE("OllamaClient Generate returns non-empty string", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    std::string host = "http://127.0.0.1:" + std::to_string(port);
    llm::OllamaClient client(host);

    std::string response = client.Generate("test-model", "test prompt");
    REQUIRE_FALSE(response.empty());
    REQUIRE(response.find("Generated text response") != std::string::npos);

    mock.stop();
}

/**
 * Test that Generate() with a JSON schema returns structured output
 * @test_ollama_client.cpp (162-181)
 */
TEST_CASE("OllamaClient Generate with json_schema returns JSON with reproducer", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    std::string host = "http://127.0.0.1:" + std::to_string(port);
    llm::OllamaClient client(host);

    std::string json_schema = R"({"type":"object","properties":{"reproducer":{"type":"string"}}})";
    std::string response = client.Generate("test-model", "test prompt", json_schema);

    REQUIRE_FALSE(response.empty());
    // Response should contain the reproducer field
    REQUIRE(response.find("reproducer") != std::string::npos);
    REQUIRE(response.find("curl") != std::string::npos);

    mock.stop();
}

/**
 * Test that Generate() throws when server returns an error status
 * @test_ollama_client.cpp (185-215)
 */
TEST_CASE("OllamaClient Generate throws on non-200 status", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    // Create a server that returns 500
    Server error_server;
    error_server.Post("/api/generate", [](const Request&, Response& res) {
        res.status = 500;
        res.set_content("Internal Server Error", "text/plain");
    });

    std::thread error_thread([&error_server, port]() {
        error_server.listen("127.0.0.1", port + 1);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::string host = "http://127.0.0.1:" + std::to_string(port + 1);
    llm::OllamaClient client(host);

    REQUIRE_THROWS_AS(
        client.Generate("test-model", "test prompt"),
        std::runtime_error
    );

    error_server.stop();
    if (error_thread.joinable()) {
        error_thread.join();
    }

    mock.stop();
}

/**
 * Test that Generate() times out when server is too slow
 * @test_ollama_client.cpp (222-251)
 */
TEST_CASE("OllamaClient Generate handles timeout", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    // Create a server that delays response
    Server slow_server;
    slow_server.Post("/api/generate", [](const Request&, Response& res) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        nlohmann::json response;
        response["response"] = "delayed";
        response["done"] = true;
        res.set_content(response.dump(), "application/json");
    });

    std::thread slow_thread([&slow_server, port]() {
        slow_server.listen("127.0.0.1", port + 2);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::string host = "http://127.0.0.1:" + std::to_string(port + 2);
    llm::OllamaClient client(host);

    // Use very short timeout
    REQUIRE_THROWS_AS(
        client.Generate("test-model", "test prompt", std::nullopt, std::chrono::milliseconds(100)),
        std::runtime_error
    );

    slow_server.stop();
    if (slow_thread.joinable()) {
        slow_thread.join();
    }

    mock.stop();
}

/**
 * Test that IsHealthy() returns false when server doesn't exist
 * @test_ollama_client.cpp (263-266)
 */
TEST_CASE("OllamaClient IsHealthy returns false when server is unreachable", "[llm]") {
    llm::OllamaClient client("http://127.0.0.1:99999");
    REQUIRE(client.IsHealthy() == false);
}

/**
 * Test that Generate() rejects empty model names
 * @test_ollama_client.cpp (272-285)
 */
TEST_CASE("OllamaClient Generate throws on empty model", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    std::string host = "http://127.0.0.1:" + std::to_string(port);
    llm::OllamaClient client(host);

    REQUIRE_THROWS_AS(
        client.Generate("", "test prompt"),
        std::runtime_error
    );

    mock.stop();
}

/**
 * Test that Generate() rejects empty prompts
 * @test_ollama_client.cpp (292-305)
 */
TEST_CASE("OllamaClient Generate throws on empty prompt", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    std::string host = "http://127.0.0.1:" + std::to_string(port);
    llm::OllamaClient client(host);

    REQUIRE_THROWS_AS(
        client.Generate("test-model", ""),
        std::runtime_error
    );

    mock.stop();
}

/**
 * Test that Generate() throws when server returns invalid JSON
 * @test_ollama_client.cpp (312-341)
 */
TEST_CASE("OllamaClient Generate handles malformed JSON response", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    Server malformed_server;
    malformed_server.Post("/api/generate", [](const Request&, Response& res) {
        res.status = 200;
        res.set_content("not valid json{", "application/json");
    });

    std::thread malformed_thread([&malformed_server, port]() {
        malformed_server.listen("127.0.0.1", port + 3);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::string host = "http://127.0.0.1:" + std::to_string(port + 3);
    llm::OllamaClient client(host);

    REQUIRE_THROWS_AS(
        client.Generate("test-model", "test prompt"),
        std::runtime_error
    );

    malformed_server.stop();
    if (malformed_thread.joinable()) {
        malformed_thread.join();
    }

    mock.stop();
}

/**
 * Test that Generate() falls back to returning the whole body when response field is missing
 * @test_ollama_client.cpp (348-375)
 */
TEST_CASE("OllamaClient Generate handles response without response field", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    Server no_response_server;
    no_response_server.Post("/api/generate", [](const Request&, Response& res) {
        nlohmann::json response;
        response["done"] = true;
        response["other_field"] = "value";
        res.status = 200;
        res.set_content(response.dump(), "application/json");
    });

    std::thread no_response_thread([&no_response_server, port]() {
        no_response_server.listen("127.0.0.1", port + 4);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::string host = "http://127.0.0.1:" + std::to_string(port + 4);
    llm::OllamaClient client(host);

    // When response field is missing, we fall back to returning the whole body
    std::string result = client.Generate("test-model", "test prompt");
    REQUIRE_FALSE(result.empty());
    REQUIRE(result.find("other_field") != std::string::npos);

    no_response_server.stop();
    if (no_response_thread.joinable()) {
        no_response_thread.join();
    }

    mock.stop();
}

/**
 * Test that Generate() ignores invalid JSON schemas and falls back to text mode
 * @test_ollama_client.cpp (387-404)
 */
TEST_CASE("OllamaClient Generate handles invalid JSON schema gracefully", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    // Give server extra time to be ready
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::string host = "http://127.0.0.1:" + std::to_string(port);
    llm::OllamaClient client(host);

    // Bad JSON schema gets ignored and we fall back to regular text mode
    std::string invalid_schema = "{invalid json";
    std::string response = client.Generate("test-model", "test prompt", invalid_schema);

    REQUIRE_FALSE(response.empty());
    // Still works, just without JSON formatting
    REQUIRE(response.find("Generated text response") != std::string::npos);

    mock.stop();
}

/**
 * Test that Generate() throws with a proper error message for 404 responses
 * @test_ollama_client.cpp (410-443)
 */
TEST_CASE("OllamaClient Generate handles 404 status", "[llm]") {
    MockOllamaServer mock;
    int port = mock.start();
    REQUIRE(port > 0);

    Server not_found_server;
    not_found_server.Post("/api/generate", [](const Request&, Response& res) {
        res.status = 404;
        res.set_content("Not Found", "text/plain");
    });

    std::thread not_found_thread([&not_found_server, port]() {
        not_found_server.listen("127.0.0.1", port + 5);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::string host = "http://127.0.0.1:" + std::to_string(port + 5);
    llm::OllamaClient client(host);

    REQUIRE_THROWS_AS(
        client.Generate("test-model", "test prompt"),
        std::runtime_error
    );

    // Make sure the error message actually mentions the 404
    try {
        client.Generate("test-model", "test prompt");
        REQUIRE(false); // This shouldn't happen
    } catch (const std::runtime_error& e) {
        std::string err_msg = e.what();
        REQUIRE(err_msg.find("404") != std::string::npos);
    }

    not_found_server.stop();
    if (not_found_thread.joinable()) {
        not_found_thread.join();
    }

    mock.stop();
}


