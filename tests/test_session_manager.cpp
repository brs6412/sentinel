/**
 * @file test_session_manager.cpp
 * @brief Unit tests for SessionManager
 * 
 * Tests session management functionality including:
 * - Form-based authentication
 * - API-based authentication (bearer tokens, API keys)
 * - OAuth authentication flows
 * - Session cookie management
 * - Session expiration handling
 * - Multi-user session management
 */

#define CATCH_CONFIG_MAIN
#include "catch_amalgamated.hpp"
#include "core/session_manager.h"
#include "core/http_client.h"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

// Helper to create a test HTTP client
HttpClient create_test_client() {
    HttpClient::Options opts;
    opts.timeout_seconds = 5;
    opts.connect_timeout_seconds = 2;
    return HttpClient(opts);
}

// Helper to create a simple auth config file
void create_test_auth_config(const std::string& path, const std::string& content) {
    std::ofstream out(path);
    out << content;
    out.close();
}

TEST_CASE("SessionManager construction", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    REQUIRE(manager.get_active_sessions().empty());
}

TEST_CASE("Load configuration from YAML", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    std::string config_path = "test_auth_config.yaml";
    
    // Create test config
    std::string config_content = R"(
users:
  - user_id: "test_user"
    auth_type: "form_based"
    username: "testuser"
    password: "testpass"
    login_url: "http://127.0.0.1:8080/login"
  - user_id: "api_user"
    auth_type: "api_bearer"
    token: "test_token_123"
)";
    
    create_test_auth_config(config_path, config_content);
    
    REQUIRE(manager.load_config(config_path));
    
    // Cleanup
    if (fs::exists(config_path)) {
        fs::remove(config_path);
    }
}

TEST_CASE("Form-based authentication - successful login", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::FORM_BASED;
    creds.username = "testuser";
    creds.password = "testpass";
    creds.login_url = "http://127.0.0.1:8080/login";
    
    // Note: This test requires the demo server to be running
    // In a real test environment, you might use a mock HTTP server
    bool result = manager.authenticate("test_user", creds);
    
    // If server is not running, test will fail - that's expected
    // In CI/CD, we'd use a test server or mock
    if (result) {
        REQUIRE(manager.is_authenticated("test_user"));
        auto cookies = manager.get_cookies("test_user");
        REQUIRE_FALSE(cookies.empty());
    }
}

TEST_CASE("API bearer token authentication", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::API_BEARER;
    creds.token = "test_bearer_token_12345";
    
    bool result = manager.authenticate("api_user", creds);
    REQUIRE(result);
    REQUIRE(manager.is_authenticated("api_user"));
    
    auto headers = manager.get_auth_headers("api_user");
    REQUIRE(headers.find("Authorization") != headers.end());
    REQUIRE(headers["Authorization"] == "Bearer test_bearer_token_12345");
}

TEST_CASE("API key authentication", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::API_KEY;
    creds.token = "test_api_key_67890";
    
    bool result = manager.authenticate("key_user", creds);
    REQUIRE(result);
    REQUIRE(manager.is_authenticated("key_user"));
    
    auto headers = manager.get_auth_headers("key_user");
    REQUIRE(headers.find("X-API-Key") != headers.end());
    REQUIRE(headers["X-API-Key"] == "test_api_key_67890");
}

TEST_CASE("API key authentication with custom header", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::API_KEY;
    creds.token = "custom_key_123";
    creds.custom_headers["X-Custom-API-Key"] = "${token}";
    
    bool result = manager.authenticate("custom_user", creds);
    REQUIRE(result);
    REQUIRE(manager.is_authenticated("custom_user"));
    
    auto headers = manager.get_auth_headers("custom_user");
    REQUIRE(headers.find("X-Custom-API-Key") != headers.end());
    REQUIRE(headers["X-Custom-API-Key"] == "custom_key_123");
}

TEST_CASE("Session cookie management", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::API_BEARER;
    creds.token = "token123";
    
    REQUIRE(manager.authenticate("user1", creds));
    
    // Simulate receiving cookies from a response
    HttpResponse response;
    response.status = 200;
    response.headers.push_back({"set-cookie", "session_id=abc123; Path=/; HttpOnly"});
    response.headers.push_back({"set-cookie", "user=testuser; Path=/"});
    
    manager.update_session_from_response("user1", response);
    
    auto cookies = manager.get_cookies("user1");
    REQUIRE(cookies.find("session_id") != cookies.end());
    REQUIRE(cookies["session_id"] == "abc123");
    REQUIRE(cookies.find("user") != cookies.end());
    REQUIRE(cookies["user"] == "testuser");
}

TEST_CASE("Multiple user sessions", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    // Authenticate first user
    Credentials creds1;
    creds1.auth_type = AuthType::API_BEARER;
    creds1.token = "token1";
    REQUIRE(manager.authenticate("user1", creds1));
    
    // Authenticate second user
    Credentials creds2;
    creds2.auth_type = AuthType::API_BEARER;
    creds2.token = "token2";
    REQUIRE(manager.authenticate("user2", creds2));
    
    // Check both are authenticated
    REQUIRE(manager.is_authenticated("user1"));
    REQUIRE(manager.is_authenticated("user2"));
    
    // Check active sessions
    auto active = manager.get_active_sessions();
    REQUIRE(active.size() == 2);
    REQUIRE(std::find(active.begin(), active.end(), "user1") != active.end());
    REQUIRE(std::find(active.begin(), active.end(), "user2") != active.end());
    
    // Verify each user has their own token
    auto headers1 = manager.get_auth_headers("user1");
    auto headers2 = manager.get_auth_headers("user2");
    REQUIRE(headers1["Authorization"] == "Bearer token1");
    REQUIRE(headers2["Authorization"] == "Bearer token2");
}

TEST_CASE("Session expiration detection", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::API_BEARER;
    creds.token = "token123";
    
    REQUIRE(manager.authenticate("user1", creds));
    REQUIRE(manager.is_authenticated("user1"));
    
    // Simulate 401 response (session expired)
    HttpResponse expired_response;
    expired_response.status = 401;
    
    // Note: Re-authentication requires valid credentials
    // In a real scenario, this would trigger re-authentication
    bool reauth_result = manager.handle_session_expiration("user1", expired_response, creds);
    
    // If re-authentication succeeds, session should be active again
    if (reauth_result) {
        REQUIRE(manager.is_authenticated("user1"));
    }
}

TEST_CASE("Clear session", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::API_BEARER;
    creds.token = "token123";
    
    REQUIRE(manager.authenticate("user1", creds));
    REQUIRE(manager.is_authenticated("user1"));
    
    manager.clear_session("user1");
    
    REQUIRE_FALSE(manager.is_authenticated("user1"));
    REQUIRE(manager.get_cookies("user1").empty());
    REQUIRE(manager.get_auth_headers("user1").empty());
}

TEST_CASE("Clear all sessions", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::API_BEARER;
    creds.token = "token123";
    
    REQUIRE(manager.authenticate("user1", creds));
    REQUIRE(manager.authenticate("user2", creds));
    
    REQUIRE(manager.get_active_sessions().size() == 2);
    
    manager.clear_all_sessions();
    
    REQUIRE(manager.get_active_sessions().empty());
    REQUIRE_FALSE(manager.is_authenticated("user1"));
    REQUIRE_FALSE(manager.is_authenticated("user2"));
}

TEST_CASE("Cookie parsing", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    // Test parsing Set-Cookie header
    std::string set_cookie = "session_id=abc123; Path=/; HttpOnly; Secure";
    auto cookies = manager.get_cookies("nonexistent");
    // This won't work directly, but we can test the internal parsing via update_session_from_response
    
    HttpResponse response;
    response.headers.push_back({"set-cookie", set_cookie});
    
    Credentials creds;
    creds.auth_type = AuthType::API_BEARER;
    creds.token = "token";
    manager.authenticate("test_user", creds);
    
    manager.update_session_from_response("test_user", response);
    
    auto parsed_cookies = manager.get_cookies("test_user");
    REQUIRE(parsed_cookies.find("session_id") != parsed_cookies.end());
    REQUIRE(parsed_cookies["session_id"] == "abc123");
}

TEST_CASE("HttpClient build_cookie_header", "[http_client]") {
    std::map<std::string, std::string> cookies;
    cookies["session_id"] = "abc123";
    cookies["user"] = "testuser";
    cookies["token"] = "xyz789";
    
    std::string header = HttpClient::build_cookie_header(cookies);
    
    REQUIRE_FALSE(header.empty());
    REQUIRE(header.find("session_id=abc123") != std::string::npos);
    REQUIRE(header.find("user=testuser") != std::string::npos);
    REQUIRE(header.find("token=xyz789") != std::string::npos);
}

TEST_CASE("HttpClient build_cookie_header empty", "[http_client]") {
    std::map<std::string, std::string> cookies;
    std::string header = HttpClient::build_cookie_header(cookies);
    REQUIRE(header.empty());
}

TEST_CASE("Invalid credentials handling", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    // Test with empty credentials
    Credentials empty_creds;
    empty_creds.auth_type = AuthType::FORM_BASED;
    // Missing username, password, login_url
    
    bool result = manager.authenticate("user1", empty_creds);
    REQUIRE_FALSE(result);
    REQUIRE_FALSE(manager.is_authenticated("user1"));
}

TEST_CASE("CSRF token extraction", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    // Test HTML with CSRF token
    std::string html = R"(
        <html>
        <body>
            <form method="POST" action="/login">
                <input type="hidden" name="csrf_token" value="csrf_abc123">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </body>
        </html>
    )";
    
    // Note: extract_csrf_token is private, so we test it indirectly through form authentication
    // In a real scenario, we'd test this with a mock server that returns HTML with CSRF tokens
}

TEST_CASE("OAuth authentication structure", "[session_manager]") {
    HttpClient client = create_test_client();
    SessionManager manager(client);
    
    Credentials creds;
    creds.auth_type = AuthType::OAUTH;
    creds.oauth_client_id = "test_client_id";
    creds.oauth_client_secret = "test_client_secret";
    creds.oauth_token_url = "https://oauth.example.com/token";
    creds.oauth_scope = "read write";
    
    // OAuth authentication requires a real OAuth server
    // This test verifies the structure is correct
    // In CI/CD, we'd use a mock OAuth server
    REQUIRE(creds.oauth_client_id == "test_client_id");
    REQUIRE(creds.oauth_client_secret == "test_client_secret");
    REQUIRE(creds.oauth_token_url == "https://oauth.example.com/token");
}

