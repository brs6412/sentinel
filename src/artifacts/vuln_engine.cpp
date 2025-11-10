/**
 * @file vuln_engine.cpp
 * @brief Vulnerability engine using Crawler output
 */

#include "vuln_engine.h"
#include <algorithm>
#include <string>
#include <vector>
#include <utility>
#include <optional>

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

VulnEngine::VulnEngine(double confidence_threshold)
    : confidenceThreshold_(confidence_threshold), riskBudget_(100) {}

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
            f.remediation_id = (item.missing && item.observed.empty())? "missing_cookie_attribute" : "misconfigured_cookie";

            findings.push_back(std::move(f));
        }
    }
}

void VulnEngine::checkCORS(const CrawlResult& result, std::vector<Finding>& findings) {}

void VulnEngine::checkReflectedXSS(const CrawlResult& result, std::vector<Finding>& findings) {}

void VulnEngine::checkCSRF(const CrawlResult& result, std::vector<Finding>& findings) {}

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


