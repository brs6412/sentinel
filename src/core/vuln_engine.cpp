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

// Cookie information to report findings on
struct CookieFinding {
    std::string name;
    std::string attribute;
    std::string observed;
    bool missing;
};

VulnEngine::VulnEngine(const HttpClient& client, double confidence_threshold, SessionManager* session_manager)
    : client_(client), confidenceThreshold_(confidence_threshold), riskBudget_(100), session_manager_(session_manager) {
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

// Set max risk for vulnerabilities
void VulnEngine::setRiskBudget(int max_risk) {
    riskBudget_ = max_risk;
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
            std::string injected_curl = url_encode(make_marker(param));
            std::string curl_url = build_url_with_param(
                    result.url,
                    result.params,
                    param,
                    injected_curl
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

void VulnEngine::checkIDOR(const CrawlResult& result, std::vector<Finding>& findings) {}

void VulnEngine::checkResponsePatterns(const CrawlResult& result, std::vector<Finding>& findings) {
    if (!response_analyzer_) {
        return;
    }
    
    // Convert headers to map format
    std::map<std::string, std::string> headers_map;
    for (const auto& [key, value] : result.headers) {
        headers_map[key] = value;
    }
    
    // Analyze response body
    AnalysisResult analysis = response_analyzer_->analyze(result.body, headers_map);
    
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
    
    // Convert the header vector to a map for easier lookup
    // This makes it simpler to check for specific headers like X-Powered-By
    std::map<std::string, std::string> headers_map;
    for (const auto& [key, value] : result.headers) {
        headers_map[key] = value;
    }
    
    // Use the response analyzer to scan the response body for patterns
    // This will detect stack traces, internal paths, IPs, and other sensitive info
    AnalysisResult analysis = response_analyzer_->analyze(result.body, headers_map);
    
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
    HttpRequest req;
    req.method = result.method;
    req.url = result.url;
    req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    enhance_request_with_session(req);
    
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
        HttpRequest test_req = req;
        
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
                
                // Parse existing body
                std::map<std::string, std::string> body_params;
                std::istringstream body_iss(result.body);
                std::string pair;
                while (std::getline(body_iss, pair, '&')) {
                    size_t eq = pair.find('=');
                    if (eq != std::string::npos) {
                        std::string key = pair.substr(0, eq);
                        std::string value = pair.substr(eq + 1);
                        body_params[key] = value;
                    }
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
    
    // Check if current result looks like a directory listing
    bool is_directory_listing = false;
    std::string server_type;
    std::vector<std::string> detected_files;
    std::vector<std::string> sensitive_files;
    
    // Test Apache patterns
    for (const auto& pattern : apache_patterns) {
        std::smatch match;
        if (std::regex_search(result.body, match, pattern)) {
            is_directory_listing = true;
            server_type = "Apache";
            break;
        }
    }
    
    // Test Nginx patterns
    if (!is_directory_listing) {
        for (const auto& pattern : nginx_patterns) {
            std::smatch match;
            if (std::regex_search(result.body, match, pattern)) {
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
            if (std::regex_search(result.body, match, pattern)) {
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
        std::sregex_iterator file_iter(result.body.begin(), result.body.end(), file_link_pattern);
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
        if (result.body.find("Parent Directory") != std::string::npos ||
            result.body.find("..") != std::string::npos ||
            result.body.find("[DIR]") != std::string::npos ||
            result.body.find("[PARENTDIR]") != std::string::npos) {
            has_directory_indicators = true;
        }
        
        // Check for table-based listings (common in directory listings)
        bool has_table_listing = false;
        if (result.body.find("<table") != std::string::npos) {
            // Check if table contains file-related content
            std::regex table_file_pattern(R"(<td[^>]*>.*?\.\w{2,4}.*?</td>)");
            if (std::regex_search(result.body, table_file_pattern)) {
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
        std::sregex_iterator iter(result.body.begin(), result.body.end(), file_pattern);
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
        std::sregex_iterator table_iter(result.body.begin(), result.body.end(), table_row_pattern);
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
    }
    
    // Differentiate from custom directory pages
    // Custom pages usually have more styling, navigation, search, etc.
    bool is_custom_page = false;
    if (is_directory_listing) {
        // Check for custom page indicators
        if (result.body.find("search") != std::string::npos &&
            result.body.find("filter") != std::string::npos) {
            // Might be a custom file browser
            is_custom_page = true;
        }
        
        // Check for extensive styling (custom pages usually have more CSS)
        size_t style_count = 0;
        size_t pos = 0;
        while ((pos = result.body.find("<style", pos)) != std::string::npos) {
            style_count++;
            pos += 6;
        }
        
        // Check for JavaScript (custom pages often have JS)
        bool has_javascript = (result.body.find("<script") != std::string::npos);
        
        // If it has multiple style blocks and JavaScript, likely custom
        if (style_count > 2 && has_javascript && detected_files.size() < 10) {
            is_custom_page = true;
        }
        
        // Check for navigation menus (custom pages often have nav)
        if (result.body.find("<nav") != std::string::npos ||
            result.body.find("navigation") != std::string::npos) {
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
                if (std::regex_search(test_resp.body, pattern)) {
                    test_is_listing = true;
                    test_server_type = "Apache";
                    break;
                }
            }
            
            if (!test_is_listing) {
                for (const auto& pattern : nginx_patterns) {
                    if (std::regex_search(test_resp.body, pattern)) {
                        test_is_listing = true;
                        test_server_type = "Nginx";
                        break;
                    }
                }
            }
            
            if (!test_is_listing) {
                for (const auto& pattern : iis_patterns) {
                    if (std::regex_search(test_resp.body, pattern)) {
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
    }
}

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


