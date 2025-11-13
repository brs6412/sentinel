#pragma once
#include "http_client.h"
#include <string>
#include <vector>
#include <schema/crawl_result.h>
#include <schema/finding.h>

/**
 @brief Vulnerability Engine Class
 */
class VulnEngine {
public:
    /**
     * @brief Constructs a VulnEngine object
     * @param confidence_threshold Threshold for vuln findings
     */
    VulnEngine(const HttpClient& client, double confidence_threshold = 0.7);

    /**
     * @brief Process a list of crawled results and generate findings
     * @param crawl_results Findings from Crawler
     */
    std::vector<Finding> analyze(const std::vector<CrawlResult>& crawl_results);

    /**
     * @brief Set CI risk budget threshold
     * @param max_risk Maximum acceptable risk
     */
    void setRiskBudget(int max_risk);

private:
    const HttpClient& client_;
    double confidenceThreshold_;
    int riskBudget_;

    /**
     * @brief Check for missing or misconfigured security headers
     * @param result CrawlResult to evaluate
     * @param findings List of findings to populate 
     */
    void checkSecurityHeaders(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for unsafe cookies 
     * @param result CrawlResult to evaluate
     * @param findings List of findings to populate 
     */
    void checkCookies(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for misconfigured CORS headers 
     * @param result CrawlResult to evaluate
     * @param findings List of findings to populate 
     */
    void checkCORS(const CrawlResult& result, std::vector<Finding>& findings);

    /**
     * @brief Check for reflected XSS vulnerabilities
     * @param result CrawlResult to evaluate
     * @param findings List of findings to populate 
     */
    void checkReflectedXSS(const CrawlResult& result, std::vector<Finding>& findings);

     /**
     * @brief Check for missing CSRF protection on POST endpoints 
     * @param result CrawlResult to evaluate
     * @param findings List of findings to populate 
     */
    void checkCSRF(const CrawlResult& result, std::vector<Finding>& findings);

     /**
     * @brief Check for IDORs 
     * @param result CrawlResult to evaluate
     * @param findings List of findings to populate 
     */
    void checkIDOR(const CrawlResult& result, std::vector<Finding>& findings);
};
