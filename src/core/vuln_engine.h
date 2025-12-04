#pragma once
#include "http_client.h"
#include <string>
#include <vector>
#include <schema/crawl_result.h>
#include <schema/finding.h>
#include <memory>

// Forward declaration
class SessionManager;
class ResponseAnalyzer;
class TimingAnalyzer;
class BaselineComparator;

// Analyzes crawled pages and generates security findings.
// Checks for common security issues like missing headers, unsafe cookies,
// CORS misconfigurations, XSS, CSRF, and IDOR vulnerabilities.

class VulnEngine {
public:
    /**
     * @brief Create a vulnerability engine with a confidence threshold
     * @param client HTTP client for making requests
     * @param confidence_threshold Minimum confidence to report a finding (0.0-1.0)
     * @param session_manager Optional session manager for authenticated requests
     */
    VulnEngine(const HttpClient& client, double confidence_threshold = 0.7, SessionManager* session_manager = nullptr);

    /**
     * @brief Destructor for VulnEngine
     * 
     * Explicitly defined to ensure proper destruction of unique_ptr members
     * (ResponseAnalyzer, TimingAnalyzer, BaselineComparator) in the .cpp file
     * where their full definitions are available.
     */
    ~VulnEngine();

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
    SessionManager* session_manager_;  // Optional session manager

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
    
    /**
     * @brief Check response for vulnerability indicators (SQL errors, stack traces, etc.)
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkResponsePatterns(const CrawlResult& result, std::vector<Finding>& findings);
    
    /**
     * @brief Check for blind SQL injection and command injection using timing analysis
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkBlindInjection(const CrawlResult& result, std::vector<Finding>& findings);
    
    /**
     * @brief Check for vulnerabilities using baseline comparison
     * @param result Page to check
     * @param findings List to add findings to
     */
    void checkBaselineComparison(const CrawlResult& result, std::vector<Finding>& findings);
    
    /**
     * @brief Scans HTTP responses for sensitive information that could aid attackers.
     * 
     * This function looks for various types of information disclosure vulnerabilities including:
     * - Stack traces from Java, .NET, Python, PHP, Node.js, and Ruby applications
     * - Internal file paths exposed in error messages or responses
     * - Private IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x) in response content
     * - Framework and server version information in HTTP headers (X-Powered-By, Server, etc.)
     * - Debug mode indicators and verbose error messages
     * 
     * The function also attempts to trigger verbose errors by sending error-triggering payloads
     * to detect applications that only show detailed information when errors occur.
     * 
     * @param result The crawl result containing the HTTP response to analyze
     * @param findings Output vector where discovered vulnerabilities will be added
     * 
     * @throws None - All exceptions are caught internally to prevent scan interruption
     * 
     * @note Findings are only added if the confidence threshold is met. Stack traces
     *       are reported as Medium severity, while debug info and version exposure
     *       may be reported as Low to Medium depending on the specific type detected.
     */
    void checkInformationDisclosure(const CrawlResult& result, std::vector<Finding>& findings);
    
    /**
     * @brief Detects open redirect vulnerabilities that could be exploited for phishing attacks.
     * 
     * Open redirects occur when an application accepts user-controlled input in redirect
     * parameters and redirects to external domains without proper validation. This can be
     * exploited to trick users into visiting malicious sites.
     * 
     * The function:
     * - Identifies common redirect parameter names (url, redirect, next, return, goto, etc.)
     * - Tests with external domain payloads (evil.com) to verify redirects work
     * - Detects both HTTP 3xx redirects and JavaScript-based redirects
     * - Tests bypass techniques like protocol-relative URLs (//evil.com) and encoded slashes
     * - Follows redirects to verify the final destination reaches the attacker-controlled domain
     * 
     * @param result The crawl result containing the endpoint to test
     * @param findings Output vector where discovered vulnerabilities will be added
     * 
     * @throws None - All exceptions are caught internally to prevent scan interruption
     * 
     * @note Only reports redirects that actually reach external domains. Whitelist-validated
     *       redirects that reject external domains are not flagged to avoid false positives.
     */
    void checkOpenRedirect(const CrawlResult& result, std::vector<Finding>& findings);
    
    /**
     * @brief Detects directory listing vulnerabilities that expose application structure.
     * 
     * Directory listings reveal the file structure of a web application, which can help
     * attackers find sensitive files, understand the application architecture, and discover
     * hidden endpoints. This function detects both automatic directory listings from web
     * servers and tests common directory paths.
     * 
     * The function:
     * - Detects Apache, Nginx, and IIS-style directory listings using pattern matching
     * - Extracts file names from directory listings for evidence
     * - Identifies sensitive files (SQL dumps, backups, config files, keys, logs)
     * - Tests common directory paths (/admin/, /backup/, /uploads/, /config/, etc.)
     * - Differentiates between raw directory listings and custom file browser applications
     * 
     * @param result The crawl result containing the response to analyze
     * @param findings Output vector where discovered vulnerabilities will be added
     * 
     * @throws None - All exceptions are caught internally to prevent scan interruption
     * 
     * @note Severity is elevated to High if sensitive files are detected in the listing.
     *       Custom file browsers with search/filter functionality are not flagged to
     *       reduce false positives from styled directory pages.
     */
    void checkDirectoryListing(const CrawlResult& result, std::vector<Finding>& findings);
    
    /**
     * @brief Tests for dangerous HTTP methods that could allow unauthorized actions.
     * 
     * Some HTTP methods like PUT, DELETE, and TRACE can be dangerous if enabled without
     * proper authentication or authorization. This function tests whether these methods
     * are not only allowed, but actually functional on the target endpoint.
     * 
     * The function:
     * - Uses OPTIONS to enumerate allowed HTTP methods from the Allow header
     * - Tests PUT method for unauthorized file upload capability (Critical if functional)
     * - Tests DELETE method for unauthorized resource deletion (Critical if functional)
     * - Tests TRACE method for XST (Cross-Site Tracing) vulnerability (Medium if functional)
     * - Tests PATCH method for unauthorized resource modification (High if functional)
     * - Verifies methods are actually functional, not just listed in OPTIONS response
     * 
     * @param result The crawl result containing the endpoint to test
     * @param findings Output vector where discovered vulnerabilities will be added
     * 
     * @throws None - All exceptions are caught internally to prevent scan interruption
     * 
     * @note Only reports methods that actually work. Methods that return 405 (Method Not
     *       Allowed), 403 (Forbidden), or 501 (Not Implemented) are not flagged to avoid
     *       false positives. PUT and DELETE are reported as Critical severity since they
     *       can lead to data loss or unauthorized file uploads.
     */
    void checkHTTPMethodVulnerabilities(const CrawlResult& result, std::vector<Finding>& findings);
    
    /**
     * @brief Adds session cookies and authentication headers to an HTTP request if available.
     * 
     * When a session manager is configured, this function automatically injects the
     * appropriate session cookies and authentication headers into the request. This allows
     * vulnerability tests to run against authenticated endpoints.
     * 
     * If no user_id is specified, the function uses the first available active session.
     * If no session manager is configured or no sessions are available, the request
     * is left unchanged.
     * 
     * @param req The HTTP request to enhance with session information (modified in-place)
     * @param user_id Optional user ID to use for session lookup. If empty, uses first active session
     * 
     * @throws None - All exceptions are caught internally
     * 
     * @note This is a no-op if session_manager_ is null or if no sessions are available
     *       for the specified user_id. The request is modified directly, so pass by reference.
     */
    void enhance_request_with_session(HttpRequest& req, const std::string& user_id = "") const;
    
private:
    std::unique_ptr<ResponseAnalyzer> response_analyzer_;  // Optional response analyzer
    std::unique_ptr<TimingAnalyzer> timing_analyzer_;  // Optional timing analyzer
    std::unique_ptr<BaselineComparator> baseline_comparator_;  // Optional baseline comparator
};
