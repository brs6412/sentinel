#pragma once
#include "http_client.h"
#include <string>
#include <map>
#include <vector>
#include <memory>
#include <optional>

// Session management for authenticated web application scanning.
// Supports form-based authentication, API-based authentication (bearer tokens, API keys),
// and OAuth flows. Maintains session cookies/tokens and automatically re-authenticates
// when sessions expire.

enum class AuthType {
    FORM_BASED,      // Form-based authentication (username/password)
    API_BEARER,      // Bearer token authentication
    API_KEY,         // API key authentication
    OAUTH            // OAuth authentication flow
};

struct Credentials {
    std::string username;
    std::string password;
    std::string token;           // Bearer token or API key
    AuthType auth_type;
    std::string login_url;       // URL for form-based login
    std::string api_endpoint;    // API endpoint for token-based auth
    std::map<std::string, std::string> custom_headers;  // Custom headers for API auth
    std::string oauth_client_id;
    std::string oauth_client_secret;
    std::string oauth_token_url;
    std::string oauth_scope;
    
    Credentials()
        : auth_type(AuthType::FORM_BASED)
    {}
};

// Represents a single user session with cookies and tokens
struct UserSession {
    std::string user_id;                    // Identifier for this user
    std::map<std::string, std::string> cookies;  // Cookie name -> value
    std::string bearer_token;                // Bearer token if applicable
    std::map<std::string, std::string> headers;  // Additional auth headers
    bool is_authenticated;
    std::string last_auth_time;             // ISO timestamp of last authentication
    
    UserSession() : is_authenticated(false) {}
};

class SessionManager {
public:
    /**
     * @brief Create a session manager with HTTP client
     * @param client HTTP client for making authentication requests
     */
    explicit SessionManager(const HttpClient& client);
    
    /**
     * @brief Load authentication configuration from YAML file
     * @param config_path Path to auth_config.yaml
     * @return true if loaded successfully, false otherwise
     */
    bool load_config(const std::string& config_path);
    
    /**
     * @brief Authenticate a user with the given credentials
     * @param user_id Identifier for this user session
     * @param creds Credentials to use for authentication
     * @return true if authentication succeeded, false otherwise
     */
    bool authenticate(const std::string& user_id, const Credentials& creds);
    
    /**
     * @brief Check if a user session is currently authenticated
     * @param user_id User identifier
     * @return true if authenticated, false otherwise
     */
    bool is_authenticated(const std::string& user_id) const;
    
    /**
     * @brief Get session cookies for a user to inject into requests
     * @param user_id User identifier
     * @return Map of cookie name -> value, empty if not authenticated
     */
    std::map<std::string, std::string> get_cookies(const std::string& user_id) const;
    
    /**
     * @brief Get authentication headers for a user to inject into requests
     * @param user_id User identifier
     * @return Map of header name -> value (e.g., Authorization: Bearer token)
     */
    std::map<std::string, std::string> get_auth_headers(const std::string& user_id) const;
    
    /**
     * @brief Add cookies/headers from a response to a user session
     * @param user_id User identifier
     * @param response HTTP response containing Set-Cookie headers
     */
    void update_session_from_response(const std::string& user_id, const HttpResponse& response);
    
    /**
     * @brief Check if a response indicates session expiration and re-authenticate if needed
     * @param user_id User identifier
     * @param response HTTP response to check
     * @param creds Credentials to use for re-authentication
     * @return true if re-authentication was successful, false otherwise
     */
    bool handle_session_expiration(const std::string& user_id, const HttpResponse& response, const Credentials& creds);
    
    /**
     * @brief Get all active user sessions
     * @return Vector of user IDs with active sessions
     */
    std::vector<std::string> get_active_sessions() const;
    
    /**
     * @brief Clear a user session
     * @param user_id User identifier
     */
    void clear_session(const std::string& user_id);
    
    /**
     * @brief Clear all sessions
     */
    void clear_all_sessions();

private:
    const HttpClient& client_;
    std::map<std::string, UserSession> sessions_;  // user_id -> session
    std::map<std::string, Credentials> credentials_;  // user_id -> credentials
    
    /**
     * @brief Authenticate using form-based login
     * @param creds Credentials with username/password
     * @param session Session to populate with cookies
     * @return true if authentication succeeded
     */
    bool authenticate_form(const Credentials& creds, UserSession& session);
    
    /**
     * @brief Authenticate using bearer token
     * @param creds Credentials with token
     * @param session Session to populate
     * @return true if authentication succeeded
     */
    bool authenticate_api_bearer(const Credentials& creds, UserSession& session);
    
    /**
     * @brief Authenticate using API key
     * @param creds Credentials with API key
     * @param session Session to populate
     * @return true if authentication succeeded
     */
    bool authenticate_api_key(const Credentials& creds, UserSession& session);
    
    /**
     * @brief Authenticate using OAuth flow
     * @param creds Credentials with OAuth parameters
     * @param session Session to populate
     * @return true if authentication succeeded
     */
    bool authenticate_oauth(const Credentials& creds, UserSession& session);
    
    /**
     * @brief Extract CSRF token from HTML form
     * @param html HTML content containing form
     * @return CSRF token if found, empty string otherwise
     */
    std::string extract_csrf_token(const std::string& html) const;
    
    /**
     * @brief Extract CSRF token using Gumbo parser (helper for extract_csrf_token)
     * @param node Gumbo node to search
     * @return CSRF token if found, empty string otherwise
     */
    std::string extract_csrf_from_gumbo(void* node) const;  // GumboNode* but avoiding include
    
    /**
     * @brief Parse Set-Cookie header and extract cookie name/value
     * @param set_cookie_header Set-Cookie header value
     * @return Map of cookie name -> value
     */
    std::map<std::string, std::string> parse_cookies(const std::string& set_cookie_header) const;
    
    /**
     * @brief Get current timestamp in ISO format
     * @return ISO timestamp string
     */
    std::string get_current_timestamp() const;
};

