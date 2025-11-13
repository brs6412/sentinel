/**
 * @file vuln_engine.cpp
 * @brief Vulnerability engine using Crawler output
 */

#include "vuln_engine.h"
#include "http_client.h"
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

// Headers to check and their optional dangerous values
struct HeaderCheck {
    std::string name;
    std::string value;
};

// Cookie information to report findings on
struct CookieFinding {
    std::string name;
    std::string attribute;
    std::string observed;
    bool missing;
};

VulnEngine::VulnEngine(const HttpClient& client, double confidence_threshold)
    : client_(client), confidenceThreshold_(confidence_threshold), riskBudget_(100) {}

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
    std::vector<HeaderCheck> checks = {
        {"x-frame-options", "allow"},
        {"content-security-policy", ""},
        {"x-content-type-options", ""},
        {"strict-transport-security", ""}
    };

    for (const auto& check : checks) {
        auto valueOpt = getHeaderValue(result, check.name);
        bool flag = false;
        std::string evidence;

        if (!valueOpt) {
            flag = true;
            evidence = check.name + " missing";
        } else if (!check.value.empty() && *valueOpt == check.value) {
            flag = true;
            evidence = check.name + " set to dangerous value: " + *valueOpt;
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
                {"header", check.name},
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
    }

    findings.erase(
        std::remove_if(findings.begin(), findings.end(),
            [this](const Finding& f) { return f.confidence < confidenceThreshold_; }),
        findings.end()
    );

    return findings;
}


