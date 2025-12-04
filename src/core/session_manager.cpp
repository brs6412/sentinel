// Session management implementation

#include "session_manager.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <gumbo.h>
#include <nlohmann/json.hpp>

SessionManager::SessionManager(const HttpClient& client)
    : client_(client)
{}

bool SessionManager::load_config(const std::string& config_path) {
    std::ifstream in(config_path);
    if (!in.is_open()) {
        return false;
    }
    
    // Simple YAML parser for auth config
    // Expected format:
    // users:
    //   - user_id: "user1"
    //     auth_type: "form_based"  # or "api_bearer", "api_key", "oauth"
    //     username: "testuser"
    //     password: "testpass"
    //     login_url: "https://example.com/login"
    //   - user_id: "user2"
    //     auth_type: "api_bearer"
    //     token: "bearer_token_here"
    //     api_endpoint: "https://api.example.com/auth"
    
    std::string line;
    std::string current_user_id;
    Credentials current_creds;
    bool in_users = false;
    bool in_user = false;
    int indent_level = 0;
    
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
        
        // Count leading spaces for indentation
        size_t leading_spaces = 0;
        while (leading_spaces < line.length() && line[leading_spaces] == ' ') {
            leading_spaces++;
        }
        int current_indent = leading_spaces / 2;  // Assuming 2-space indentation
        
        // Parse key-value pairs
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) continue;
        
        std::string key = line.substr(0, colon_pos);
        key.erase(key.find_last_not_of(" \t") + 1);
        
        std::string value = line.substr(colon_pos + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        // Remove quotes if present
        if (value.size() >= 2 && value[0] == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }
        
        if (key == "users" && current_indent == 0) {
            in_users = true;
            continue;
        }
        
        if (in_users) {
            if (key == "user_id" || (key == "-" && value == "user_id")) {
                // Start of new user entry
                if (!current_user_id.empty() && in_user) {
                    credentials_[current_user_id] = current_creds;
                }
                current_creds = Credentials();
                in_user = true;
                if (key == "user_id") {
                    current_user_id = value;
                }
            } else if (in_user && !current_user_id.empty()) {
                if (key == "auth_type" || key == "type") {
                    if (value == "form_based" || value == "form") {
                        current_creds.auth_type = AuthType::FORM_BASED;
                    } else if (value == "api_bearer" || value == "bearer") {
                        current_creds.auth_type = AuthType::API_BEARER;
                    } else if (value == "api_key" || value == "key") {
                        current_creds.auth_type = AuthType::API_KEY;
                    } else if (value == "oauth") {
                        current_creds.auth_type = AuthType::OAUTH;
                    }
                } else if (key == "username" || key == "user") {
                    current_creds.username = value;
                } else if (key == "password" || key == "pass") {
                    current_creds.password = value;
                } else if (key == "token") {
                    current_creds.token = value;
                } else if (key == "login_url" || key == "login") {
                    current_creds.login_url = value;
                } else if (key == "api_endpoint" || key == "endpoint") {
                    current_creds.api_endpoint = value;
                } else if (key == "oauth_client_id" || key == "client_id") {
                    current_creds.oauth_client_id = value;
                } else if (key == "oauth_client_secret" || key == "client_secret") {
                    current_creds.oauth_client_secret = value;
                } else if (key == "oauth_token_url" || key == "token_url") {
                    current_creds.oauth_token_url = value;
                } else if (key == "oauth_scope" || key == "scope") {
                    current_creds.oauth_scope = value;
                } else if (key.find("header_") == 0) {
                    // Custom header: header_X-API-Key: value
                    std::string header_name = key.substr(7);  // Remove "header_" prefix
                    current_creds.custom_headers[header_name] = value;
                }
            }
        }
    }
    
    // Save last user if any
    if (!current_user_id.empty() && in_user) {
        credentials_[current_user_id] = current_creds;
    }
    
    return !credentials_.empty();
}

bool SessionManager::authenticate(const std::string& user_id, const Credentials& creds) {
    UserSession session;
    session.user_id = user_id;
    bool success = false;
    
    switch (creds.auth_type) {
        case AuthType::FORM_BASED:
            success = authenticate_form(creds, session);
            break;
        case AuthType::API_BEARER:
            success = authenticate_api_bearer(creds, session);
            break;
        case AuthType::API_KEY:
            success = authenticate_api_key(creds, session);
            break;
        case AuthType::OAUTH:
            success = authenticate_oauth(creds, session);
            break;
    }
    
    if (success) {
        session.is_authenticated = true;
        session.last_auth_time = get_current_timestamp();
        sessions_[user_id] = session;
        credentials_[user_id] = creds;  // Store credentials for re-authentication
    }
    
    return success;
}

bool SessionManager::is_authenticated(const std::string& user_id) const {
    auto it = sessions_.find(user_id);
    return it != sessions_.end() && it->second.is_authenticated;
}

std::map<std::string, std::string> SessionManager::get_cookies(const std::string& user_id) const {
    auto it = sessions_.find(user_id);
    if (it != sessions_.end() && it->second.is_authenticated) {
        return it->second.cookies;
    }
    return {};
}

std::map<std::string, std::string> SessionManager::get_auth_headers(const std::string& user_id) const {
    auto it = sessions_.find(user_id);
    if (it != sessions_.end() && it->second.is_authenticated) {
        std::map<std::string, std::string> headers = it->second.headers;
        if (!it->second.bearer_token.empty()) {
            headers["Authorization"] = "Bearer " + it->second.bearer_token;
        }
        return headers;
    }
    return {};
}

void SessionManager::update_session_from_response(const std::string& user_id, const HttpResponse& response) {
    auto it = sessions_.find(user_id);
    if (it == sessions_.end()) {
        return;
    }
    
    // Extract cookies from Set-Cookie headers
    for (const auto& header : response.headers) {
        if (header.first == "set-cookie") {
            auto cookies = parse_cookies(header.second);
            for (const auto& cookie : cookies) {
                it->second.cookies[cookie.first] = cookie.second;
            }
        }
    }
}

bool SessionManager::handle_session_expiration(const std::string& user_id, const HttpResponse& response, const Credentials& creds) {
    // Check if response indicates authentication failure
    if (response.status == 401 || response.status == 403) {
        // Mark session as unauthenticated
        auto it = sessions_.find(user_id);
        if (it != sessions_.end()) {
            it->second.is_authenticated = false;
        }
        
        // Attempt re-authentication
        return authenticate(user_id, creds);
    }
    
    return false;
}

std::vector<std::string> SessionManager::get_active_sessions() const {
    std::vector<std::string> active;
    for (const auto& [user_id, session] : sessions_) {
        if (session.is_authenticated) {
            active.push_back(user_id);
        }
    }
    return active;
}

void SessionManager::clear_session(const std::string& user_id) {
    sessions_.erase(user_id);
    credentials_.erase(user_id);
}

void SessionManager::clear_all_sessions() {
    sessions_.clear();
    credentials_.clear();
}

bool SessionManager::authenticate_form(const Credentials& creds, UserSession& session) {
    if (creds.login_url.empty() || creds.username.empty() || creds.password.empty()) {
        return false;
    }
    
    // Step 1: Fetch login page to get CSRF token
    HttpRequest req;
    req.method = "GET";
    req.url = creds.login_url;
    req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    HttpResponse resp;
    if (!client_.perform(req, resp) || resp.status != 200) {
        return false;
    }
    
    // Extract CSRF token from form
    std::string csrf_token = extract_csrf_token(resp.body);
    
    // Step 2: Submit login form
    HttpRequest login_req;
    login_req.method = "POST";
    login_req.url = creds.login_url;
    login_req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    login_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    login_req.headers["Referer"] = creds.login_url;
    
    // Build form data
    std::ostringstream form_data;
    form_data << "username=" << creds.username;
    form_data << "&password=" << creds.password;
    if (!csrf_token.empty()) {
        form_data << "&csrf_token=" << csrf_token;
        form_data << "&_token=" << csrf_token;  // Common alternative name
    }
    
    login_req.body = form_data.str();
    
    HttpResponse login_resp;
    if (!client_.perform(login_req, login_resp)) {
        return false;
    }
    
    // Check if login was successful (typically 200 or 302 redirect)
    if (login_resp.status == 200 || login_resp.status == 302 || login_resp.status == 303) {
        // Extract cookies from response
        for (const auto& header : login_resp.headers) {
            if (header.first == "set-cookie") {
                auto cookies = parse_cookies(header.second);
                for (const auto& cookie : cookies) {
                    session.cookies[cookie.first] = cookie.second;
                }
            }
        }
        
        // Also check if we got cookies from the initial GET request
        for (const auto& header : resp.headers) {
            if (header.first == "set-cookie") {
                auto cookies = parse_cookies(header.second);
                for (const auto& cookie : cookies) {
                    session.cookies[cookie.first] = cookie.second;
                }
            }
        }
        
        return true;
    }
    
    return false;
}

bool SessionManager::authenticate_api_bearer(const Credentials& creds, UserSession& session) {
    if (creds.token.empty()) {
        return false;
    }
    
    session.bearer_token = creds.token;
    session.headers["Authorization"] = "Bearer " + creds.token;
    
    // Optionally validate token by making a test request
    if (!creds.api_endpoint.empty()) {
        HttpRequest req;
        req.method = "GET";
        req.url = creds.api_endpoint;
        req.headers["Authorization"] = "Bearer " + creds.token;
        
        for (const auto& custom_header : creds.custom_headers) {
            req.headers[custom_header.first] = custom_header.second;
        }
        
        HttpResponse resp;
        if (client_.perform(req, resp)) {
            // Token is valid if we get 2xx response
            return resp.status >= 200 && resp.status < 300;
        }
        return false;
    }
    
    // If no endpoint provided, assume token is valid
    return true;
}

bool SessionManager::authenticate_api_key(const Credentials& creds, UserSession& session) {
    if (creds.token.empty()) {
        return false;
    }
    
    // API key can be sent in various ways - check custom headers first
    if (!creds.custom_headers.empty()) {
        session.headers = creds.custom_headers;
        // Replace placeholder with actual token
        for (auto& [key, value] : session.headers) {
            size_t pos = value.find("${token}");
            if (pos != std::string::npos) {
                value.replace(pos, 8, creds.token);
            }
        }
    } else {
        // Default: X-API-Key header
        session.headers["X-API-Key"] = creds.token;
    }
    
    // Optionally validate by making a test request
    if (!creds.api_endpoint.empty()) {
        HttpRequest req;
        req.method = "GET";
        req.url = creds.api_endpoint;
        
        for (const auto& header : session.headers) {
            req.headers[header.first] = header.second;
        }
        
        HttpResponse resp;
        if (client_.perform(req, resp)) {
            return resp.status >= 200 && resp.status < 300;
        }
        return false;
    }
    
    return true;
}

bool SessionManager::authenticate_oauth(const Credentials& creds, UserSession& session) {
    if (creds.oauth_token_url.empty() || creds.oauth_client_id.empty() || 
        creds.oauth_client_secret.empty()) {
        return false;
    }
    
    // OAuth 2.0 client credentials flow
    HttpRequest req;
    req.method = "POST";
    req.url = creds.oauth_token_url;
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    req.headers["Accept"] = "application/json";
    
    // Build OAuth request body
    std::ostringstream body;
    body << "grant_type=client_credentials";
    body << "&client_id=" << creds.oauth_client_id;
    body << "&client_secret=" << creds.oauth_client_secret;
    if (!creds.oauth_scope.empty()) {
        body << "&scope=" << creds.oauth_scope;
    }
    
    req.body = body.str();
    
    HttpResponse resp;
    if (!client_.perform(req, resp) || resp.status != 200) {
        return false;
    }
    
    // Parse JSON response to extract access token
    try {
        auto json = nlohmann::json::parse(resp.body);
        if (json.contains("access_token")) {
            std::string access_token = json["access_token"];
            session.bearer_token = access_token;
            session.headers["Authorization"] = "Bearer " + access_token;
            return true;
        }
    } catch (...) {
        // JSON parse error
        return false;
    }
    
    return false;
}

std::string SessionManager::extract_csrf_token(const std::string& html) const {
    // Try multiple common CSRF token patterns
    std::vector<std::regex> patterns = {
        std::regex(R"(<input[^>]*name=["']csrf_token["'][^>]*value=["']([^"']+)["'])", std::regex::icase),
        std::regex(R"(<input[^>]*name=["']_token["'][^>]*value=["']([^"']+)["'])", std::regex::icase),
        std::regex(R"(<input[^>]*name=["']authenticity_token["'][^>]*value=["']([^"']+)["'])", std::regex::icase),
        std::regex(R"(<meta[^>]*name=["']csrf-token["'][^>]*content=["']([^"']+)["'])", std::regex::icase),
        std::regex(R"delim("csrf_token"\s*:\s*"([^"]+)")delim", std::regex::icase),
    };
    
    for (const auto& pattern : patterns) {
        std::smatch match;
        if (std::regex_search(html, match, pattern) && match.size() > 1) {
            return match[1].str();
        }
    }
    
    // Also try using Gumbo parser for more robust HTML parsing
    GumboOutput* output = gumbo_parse(html.c_str());
    if (output) {
        std::string token = extract_csrf_from_gumbo(static_cast<void*>(output->root));
        gumbo_destroy_output(&kGumboDefaultOptions, output);
        if (!token.empty()) {
            return token;
        }
    }
    
    return "";
}

std::string SessionManager::extract_csrf_from_gumbo(void* node_ptr) const {
    GumboNode* node = static_cast<GumboNode*>(node_ptr);
    if (node->type != GUMBO_NODE_ELEMENT) {
        return "";
    }
    
    GumboElement* element = &node->v.element;
    
    // Check for input elements with CSRF token names
    if (element->tag == GUMBO_TAG_INPUT) {
        GumboAttribute* name_attr = gumbo_get_attribute(&element->attributes, "name");
        GumboAttribute* value_attr = gumbo_get_attribute(&element->attributes, "value");
        
        if (name_attr && value_attr) {
            std::string name = name_attr->value;
            std::string lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
            
            if (lower_name.find("csrf") != std::string::npos || 
                lower_name == "_token" || 
                lower_name == "authenticity_token") {
                return value_attr->value;
            }
        }
    }
    
    // Check for meta tags
    if (element->tag == GUMBO_TAG_META) {
        GumboAttribute* name_attr = gumbo_get_attribute(&element->attributes, "name");
        GumboAttribute* content_attr = gumbo_get_attribute(&element->attributes, "content");
        
        if (name_attr && content_attr) {
            std::string name = name_attr->value;
            std::string lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
            
            if (lower_name == "csrf-token") {
                return content_attr->value;
            }
        }
    }
    
    // Recursively search children
    GumboVector* children = &element->children;
    for (unsigned int i = 0; i < children->length; ++i) {
        std::string token = extract_csrf_from_gumbo(children->data[i]);
        if (!token.empty()) {
            return token;
        }
    }
    
    return "";
}

std::map<std::string, std::string> SessionManager::parse_cookies(const std::string& set_cookie_header) const {
    std::map<std::string, std::string> cookies;
    
    // Parse Set-Cookie header: name=value; Path=/; Domain=example.com; Secure; HttpOnly
    size_t eq_pos = set_cookie_header.find('=');
    if (eq_pos == std::string::npos) {
        return cookies;
    }
    
    std::string name = set_cookie_header.substr(0, eq_pos);
    // Trim whitespace
    name.erase(0, name.find_first_not_of(" \t"));
    name.erase(name.find_last_not_of(" \t") + 1);
    
    size_t semi_pos = set_cookie_header.find(';', eq_pos);
    std::string value;
    if (semi_pos != std::string::npos) {
        value = set_cookie_header.substr(eq_pos + 1, semi_pos - eq_pos - 1);
    } else {
        value = set_cookie_header.substr(eq_pos + 1);
    }
    
    // Trim whitespace from value
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t") + 1);
    
    if (!name.empty()) {
        cookies[name] = value;
    }
    
    return cookies;
}

std::string SessionManager::get_current_timestamp() const {
    auto now = std::time(nullptr);
    auto tm = *std::gmtime(&now);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

