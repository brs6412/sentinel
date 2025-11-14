#pragma once
#include "http_client.h"
#include <string>
#include <vector>
#include <schema/crawl_result.h>
#include <schema/finding.h>

// Analyzes crawled pages and generates security findings.
// Checks for common security issues like missing headers, unsafe cookies,
// CORS misconfigurations, XSS, CSRF, and IDOR vulnerabilities.

class VulnEngine {
public:
    /**
     * @brief Create a vulnerability engine with a confidence threshold
     * @param client HTTP client for making requests
     * @param confidence_threshold Minimum confidence to report a finding (0.0-1.0)
     */
    VulnEngine(const HttpClient& client, double confidence_threshold = 0.7);

    /**
     * @brief Analyze crawled pages and generate security findings
     * @param crawl_results Pages and endpoints discovered by the crawler
     * @return List of security findings
     */
    std::vector<Finding> analyze(const std::vector<CrawlResult>& crawl_results);

    /**
     * @brief Set the maximum acceptable risk score for CI/CD gating
     * @param max_risk Maximum risk score before blocking
     */
    void setRiskBudget(int max_risk);

private:
    const HttpClient& client_;
    double confidenceThreshold_;
    int riskBudget_;

    /**
     * @brief Check for missing or misconfigured security headers
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkSecurityHeaders(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for unsafe cookie settings
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkCookies(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for misconfigured CORS headers
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkCORS(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for reflected XSS vulnerabilities
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkReflectedXSS(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for missing CSRF protection on POST endpoints
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkCSRF(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for insecure direct object references (IDOR)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkIDOR(const CrawlResult& result, std::vector<Finding>& findings);
};
