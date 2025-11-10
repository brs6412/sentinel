#pragma once
#include <string>
#include <vector>
#include <schema/crawl_result.h>
#include <schema/finding.h>

/**
 * @file vuln_engine.h
 * @brief Analyzes crawled pages and generates security findings
 * 
 * Checks for common security issues like missing headers, unsafe cookies,
 * CORS misconfigurations, XSS, CSRF, and IDOR vulnerabilities.
 */

/**
 * Analyzes crawled pages for security vulnerabilities
 * @vuln_engine.h (10-75)
 */
class VulnEngine {
public:
    /**
     * Create a vulnerability engine with a confidence threshold
     * @vuln_engine.h (16)
     * @param confidence_threshold Minimum confidence to report a finding (0.0-1.0)
     */
    VulnEngine(double confidence_threshold = 0.7);

    /**
     * Analyze crawled pages and generate security findings
     * @vuln_engine.h (22)
     * @param crawl_results Pages and endpoints discovered by the crawler
     * @return List of security findings
     */
    std::vector<Finding> analyze(const std::vector<CrawlResult>& crawl_results);

    /**
     * Set the maximum acceptable risk score for CI/CD gating
     * @vuln_engine.h (28)
     * @param max_risk Maximum risk score before blocking
     */
    void setRiskBudget(int max_risk);

private:
    double confidenceThreshold_;
    int riskBudget_;

    /**
     * Check for missing or misconfigured security headers
     * @vuln_engine.h (39)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkSecurityHeaders(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * Check for unsafe cookie settings
     * @vuln_engine.h (46)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkCookies(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * Check for misconfigured CORS headers
     * @vuln_engine.h (53)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkCORS(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * Check for reflected XSS vulnerabilities
     * @vuln_engine.h (60)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkReflectedXSS(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * Check for missing CSRF protection on POST endpoints
     * @vuln_engine.h (67)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkCSRF(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * Check for insecure direct object references (IDOR)
     * @vuln_engine.h (74)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkIDOR(const CrawlResult& result, std::vector<Finding>& findings);
};
