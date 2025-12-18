/**
 * @file http_test_helpers.cpp
 * @brief Implementation of HTTP test helper functions
 */

#include "http_test_helpers.h"
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <regex>
#include <chrono>
#include <cstring>

namespace test_helpers {

std::string get_target_url(const std::string& default_url) {
    const char* env_url = std::getenv("TARGET_URL");
    if (env_url && strlen(env_url) > 0) {
        return std::string(env_url);
    }
    return default_url;
}

HttpClient create_test_client() {
    HttpClient::Options opts;
    opts.timeout_seconds = 15;
    opts.connect_timeout_seconds = 5;
    opts.follow_redirects = true;
    opts.max_redirects = 5;
    opts.user_agent = "Sentinel-Test/1.0";
    opts.accept_encoding = true;
    return HttpClient(opts);
}

CookieInfo parse_set_cookie(const std::string& set_cookie_header) {
    CookieInfo cookie;
    
    // Split by semicolon
    std::istringstream iss(set_cookie_header);
    std::string token;
    bool first = true;
    
    while (std::getline(iss, token, ';')) {
        // Trim whitespace
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        
        if (first) {
            // First token is name=value
            size_t eq_pos = token.find('=');
            if (eq_pos != std::string::npos) {
                cookie.name = token.substr(0, eq_pos);
                cookie.value = token.substr(eq_pos + 1);
            }
            first = false;
        } else {
            // Subsequent tokens are attributes
            std::string lower_token = token;
            std::transform(lower_token.begin(), lower_token.end(), lower_token.begin(), ::tolower);
            
            if (lower_token == "secure") {
                cookie.has_secure = true;
            } else if (lower_token == "httponly") {
                cookie.has_httponly = true;
            } else if (lower_token.find("samesite=") == 0) {
                cookie.has_samesite = true;
                cookie.samesite_value = token.substr(9);
                std::transform(cookie.samesite_value.begin(), cookie.samesite_value.end(),
                              cookie.samesite_value.begin(), ::tolower);
            } else if (lower_token.find("domain=") == 0) {
                cookie.domain = token.substr(7);
            } else if (lower_token.find("path=") == 0) {
                cookie.path = token.substr(5);
            } else if (lower_token.find("expires=") == 0) {
                cookie.has_expires = true;
                cookie.expires = token.substr(8);
            } else if (lower_token.find("max-age=") == 0) {
                cookie.has_max_age = true;
                try {
                    cookie.max_age = std::stol(token.substr(8));
                } catch (...) {
                    cookie.max_age = 0;
                }
            }
        }
    }
    
    return cookie;
}

std::map<std::string, CookieInfo> parse_cookies_from_response(const HttpResponse& response) {
    std::map<std::string, CookieInfo> cookies;
    
    for (const auto& [name, value] : response.headers) {
        if (name == "set-cookie") {
            CookieInfo cookie = parse_set_cookie(value);
            if (!cookie.name.empty()) {
                cookies[cookie.name] = cookie;
            }
        }
    }
    
    return cookies;
}

std::string get_header_value(const HttpResponse& response, const std::string& header_name) {
    std::string lower_name = header_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    for (const auto& [name, value] : response.headers) {
        std::string lower_resp_name = name;
        std::transform(lower_resp_name.begin(), lower_resp_name.end(), lower_resp_name.begin(), ::tolower);
        if (lower_resp_name == lower_name) {
            return value;
        }
    }
    
    return "";
}

bool has_header(const HttpResponse& response, const std::string& header_name) {
    return !get_header_value(response, header_name).empty();
}

bool verify_security_header(const HttpResponse& response,
                          const std::string& header_name,
                          const std::string& expected_value) {
    std::string value = get_header_value(response, header_name);
    if (value.empty()) {
        return false;
    }
    
    if (!expected_value.empty()) {
        // Case-insensitive comparison
        std::string lower_value = value;
        std::string lower_expected = expected_value;
        std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);
        std::transform(lower_expected.begin(), lower_expected.end(), lower_expected.begin(), ::tolower);
        return lower_value == lower_expected;
    }
    
    return true;  // Just check presence
}

bool cookie_has_flag(const CookieInfo& cookie, const std::string& flag_name) {
    std::string lower_flag = flag_name;
    std::transform(lower_flag.begin(), lower_flag.end(), lower_flag.begin(), ::tolower);
    
    if (lower_flag == "secure") {
        return cookie.has_secure;
    } else if (lower_flag == "httponly") {
        return cookie.has_httponly;
    } else if (lower_flag == "samesite") {
        return cookie.has_samesite;
    }
    
    return false;
}

HttpResponse cors_preflight_request(HttpClient& client,
                                   const std::string& url,
                                   const std::string& origin,
                                   const std::string& method) {
    HttpRequest req;
    req.method = "OPTIONS";
    req.url = url;
    req.headers["Origin"] = origin;
    req.headers["Access-Control-Request-Method"] = method;
    req.headers["Access-Control-Request-Headers"] = "Content-Type";
    
    HttpResponse resp;
    client.perform(req, resp);
    return resp;
}

bool verify_cors_misconfiguration(const HttpResponse& response) {
    std::string acao = get_header_value(response, "access-control-allow-origin");
    std::string acac = get_header_value(response, "access-control-allow-credentials");
    
    // Misconfiguration: wildcard origin with credentials
    std::string lower_acao = acao;
    std::transform(lower_acao.begin(), lower_acao.end(), lower_acao.begin(), ::tolower);
    
    if (lower_acao == "*" && acac == "true") {
        return true;  // Misconfiguration detected
    }
    
    return false;
}

bool contains_sql_error(const HttpResponse& response) {
    std::string lower_body = response.body;
    std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
    
    // Common SQL error patterns
    std::vector<std::string> patterns = {
        "sql syntax",
        "mysql error",
        "postgresql error",
        "sql server",
        "ora-",
        "sqlite error",
        "database error",
        "syntax error near",
        "unclosed quotation mark",
        "table doesn't exist",
        "column doesn't exist"
    };
    
    for (const auto& pattern : patterns) {
        if (lower_body.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool contains_command_output(const HttpResponse& response) {
    std::string body = response.body;
    
    // Check for common command output patterns
    // Unix passwd file format
    if (body.find("root:") != std::string::npos && 
        body.find(":x:") != std::string::npos) {
        return true;
    }
    
    // Command output indicators
    std::vector<std::string> patterns = {
        "uid=",
        "gid=",
        "total ",
        "drwx",
        "-rwx",
        "command not found",
        "permission denied"
    };
    
    std::string lower_body = body;
    std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
    
    for (const auto& pattern : patterns) {
        if (lower_body.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool contains_file_content(const HttpResponse& response) {
    std::string body = response.body;
    
    // Check for /etc/passwd content
    if (body.find("root:") != std::string::npos && 
        body.find(":x:") != std::string::npos &&
        body.find("/bin/") != std::string::npos) {
        return true;
    }
    
    // Check for Windows hosts file
    if (body.find("127.0.0.1") != std::string::npos &&
        body.find("localhost") != std::string::npos &&
        body.find("# localhost") != std::string::npos) {
        return true;
    }
    
    // Check for win.ini content
    if (body.find("[fonts]") != std::string::npos ||
        body.find("[extensions]") != std::string::npos) {
        return true;
    }
    
    return false;
}

double measure_response_time(HttpClient& client, const HttpRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    
    HttpResponse resp;
    client.perform(request, resp);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return static_cast<double>(duration.count());
}

bool response_time_exceeds(double response_time_ms, double threshold_ms) {
    return response_time_ms >= threshold_ms;
}

} // namespace test_helpers

