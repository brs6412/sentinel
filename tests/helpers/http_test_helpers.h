/**
 * @file http_test_helpers.h
 * @brief Helper functions for HTTP-based Catch2 tests
 * 
 * This module provides utility functions that make it easier to write Catch2 tests
 * for security vulnerabilities. Instead of manually parsing headers and checking
 * response content, you can use these helpers to verify security headers, cookie
 * flags, CORS configurations, and detect common vulnerability indicators like SQL
 * errors or command output.
 * 
 * Example usage:
 * @code
 *   HttpClient client = create_test_client();
 *   HttpRequest req;
 *   req.url = get_target_url() + "/api/users";
 *   HttpResponse resp;
 *   client.perform(req, resp);
 *   
 *   REQUIRE(verify_security_header(resp, "x-frame-options"));
 * @endcode
 */

#pragma once

#include "core/http_client.h"
#include <string>
#include <map>
#include <vector>
#include <optional>

namespace test_helpers {

/**
 * @brief Cookie information extracted from a Set-Cookie header
 * 
 * This structure holds all the information parsed from a Set-Cookie header,
 * including the cookie name/value pair and all security-related flags.
 */
struct CookieInfo {
    std::string name;              ///< Cookie name
    std::string value;             ///< Cookie value
    bool has_secure = false;       ///< True if Secure flag is present
    bool has_httponly = false;     ///< True if HttpOnly flag is present
    bool has_samesite = false;     ///< True if SameSite attribute is present
    std::string samesite_value;    ///< SameSite value: "Strict", "Lax", or "None"
    std::string domain;            ///< Domain attribute value
    std::string path;              ///< Path attribute value
    bool has_expires = false;      ///< True if Expires attribute is present
    std::string expires;           ///< Expires attribute value
    bool has_max_age = false;      ///< True if Max-Age attribute is present
    long max_age = 0;              ///< Max-Age value in seconds
};

/**
 * @brief Gets the target URL for testing, either from environment or default
 * 
 * This function checks the TARGET_URL environment variable first. If it's set,
 * that value is returned. Otherwise, it falls back to the provided default URL.
 * This makes tests configurable without recompiling them.
 * 
 * @param default_url The URL to use if TARGET_URL environment variable is not set.
 *                    Defaults to "http://127.0.0.1:8080" for local testing.
 * 
 * @return The target URL to test against
 * 
 * @note Does not throw exceptions. Returns default_url if environment variable
 *       is not set or empty.
 */
std::string get_target_url(const std::string& default_url = "http://127.0.0.1:8080");

/**
 * @brief Creates an HTTP client configured for testing
 * 
 * Returns a pre-configured HttpClient with sensible defaults for testing:
 * - 15 second timeout
 * - 5 second connection timeout
 * - Follows redirects (up to 5)
 * - Standard user agent
 * 
 * @return A configured HttpClient instance ready for use in tests
 * 
 * @throws std::runtime_error if libcurl initialization fails
 */
HttpClient create_test_client();

/**
 * @brief Parses a Set-Cookie header value into structured cookie information
 * 
 * Takes a raw Set-Cookie header value (like "session=abc123; Secure; HttpOnly")
 * and extracts all the cookie attributes into a CookieInfo structure. Handles
 * all standard cookie attributes including Secure, HttpOnly, SameSite, Domain,
 * Path, Expires, and Max-Age.
 * 
 * @param set_cookie_header The value of the Set-Cookie header to parse
 * 
 * @return A CookieInfo structure containing all parsed cookie attributes.
 *         If parsing fails, the structure will have empty name/value.
 * 
 * @note Does not throw exceptions. Returns empty CookieInfo on parse errors.
 */
CookieInfo parse_set_cookie(const std::string& set_cookie_header);

/**
 * @brief Extracts all cookies from an HTTP response's Set-Cookie headers
 * 
 * Scans through all headers in the response looking for Set-Cookie headers,
 * parses each one, and returns a map of cookie names to their parsed information.
 * This is useful when you need to check multiple cookies in a single response.
 * 
 * @param response The HTTP response containing Set-Cookie headers
 * 
 * @return A map where keys are cookie names and values are CookieInfo structures.
 *         Empty map if no Set-Cookie headers are found.
 * 
 * @note Does not throw exceptions. Returns empty map if no cookies found.
 */
std::map<std::string, CookieInfo> parse_cookies_from_response(const HttpResponse& response);

/**
 * @brief Gets a header value from an HTTP response (case-insensitive lookup)
 * 
 * Searches through the response headers for a header with the given name,
 * performing a case-insensitive comparison. This is useful because HTTP headers
 * are case-insensitive, but implementations may vary in how they store them.
 * 
 * @param response The HTTP response to search
 * @param header_name The name of the header to find (case-insensitive)
 * 
 * @return The header value if found, empty string otherwise
 * 
 * @note Does not throw exceptions. Returns empty string if header not found.
 */
std::string get_header_value(const HttpResponse& response, const std::string& header_name);

/**
 * @brief Checks if an HTTP response contains a specific header
 * 
 * A convenience function that checks for header existence without needing
 * to check if the returned value is empty. Uses case-insensitive matching.
 * 
 * @param response The HTTP response to check
 * @param header_name The name of the header to look for (case-insensitive)
 * 
 * @return true if the header exists in the response, false otherwise
 * 
 * @note Does not throw exceptions.
 */
bool has_header(const HttpResponse& response, const std::string& header_name);

/**
 * @brief Verifies that a security header is present and optionally matches expected value
 * 
 * Checks if a security header (like X-Frame-Options, CSP, etc.) is present in
 * the response. If an expected_value is provided, also verifies that the header
 * value matches (case-insensitive). This is useful for testing that security
 * headers are properly configured.
 * 
 * @param response The HTTP response to check
 * @param header_name The name of the security header to verify (e.g., "x-frame-options")
 * @param expected_value Optional expected header value. If empty, only checks for presence.
 *                      If provided, performs case-insensitive comparison.
 * 
 * @return true if header is present and (if expected_value provided) matches,
 *         false otherwise
 * 
 * @note Does not throw exceptions.
 */
bool verify_security_header(const HttpResponse& response, 
                           const std::string& header_name,
                           const std::string& expected_value = "");

/**
 * @brief Checks if a cookie has a specific security flag set
 * 
 * Verifies that a cookie has a particular security-related flag. Supported flags
 * are "Secure", "HttpOnly", and "SameSite". This is useful for testing that
 * cookies are properly configured with security flags.
 * 
 * @param cookie The CookieInfo structure to check
 * @param flag_name The name of the flag to check: "Secure", "HttpOnly", or "SameSite"
 * 
 * @return true if the flag is present, false otherwise
 * 
 * @note Does not throw exceptions. Returns false for unknown flag names.
 */
bool cookie_has_flag(const CookieInfo& cookie, const std::string& flag_name);

/**
 * @brief Performs a CORS preflight (OPTIONS) request to test CORS configuration
 * 
 * Sends an OPTIONS request with the appropriate CORS preflight headers (Origin,
 * Access-Control-Request-Method, etc.) to test how the server handles CORS
 * requests. This is essential for detecting CORS misconfigurations.
 * 
 * @param client The HTTP client to use for the request
 * @param url The target URL to send the preflight request to
 * @param origin The Origin header value (e.g., "https://evil.example.com")
 * @param method The HTTP method being requested (defaults to "POST")
 * 
 * @return The HTTP response from the preflight request
 * 
 * @note Does not throw exceptions. Returns response with status 0 if request fails.
 */
HttpResponse cors_preflight_request(HttpClient& client,
                                   const std::string& url,
                                   const std::string& origin,
                                   const std::string& method = "POST");

/**
 * @brief Detects CORS misconfiguration (wildcard origin with credentials)
 * 
 * Checks if the CORS response indicates a dangerous misconfiguration where
 * Access-Control-Allow-Origin is set to "*" (wildcard) while
 * Access-Control-Allow-Credentials is "true". This combination is insecure
 * because it allows any origin to make credentialed requests.
 * 
 * @param response The CORS preflight response to check
 * 
 * @return true if misconfiguration is detected (wildcard + credentials),
 *         false if CORS is properly configured
 * 
 * @note Does not throw exceptions.
 */
bool verify_cors_misconfiguration(const HttpResponse& response);

/**
 * @brief Detects SQL error messages in an HTTP response body
 * 
 * Searches the response body for common SQL error patterns from various
 * database systems (MySQL, PostgreSQL, SQL Server, Oracle, SQLite). This is
 * useful for detecting SQL injection vulnerabilities where error messages
 * are reflected in the response.
 * 
 * @param response The HTTP response to check
 * 
 * @return true if SQL error patterns are found in the response body,
 *         false otherwise
 * 
 * @note Does not throw exceptions. Performs case-insensitive matching.
 */
bool contains_sql_error(const HttpResponse& response);

/**
 * @brief Detects command execution output in an HTTP response body
 * 
 * Searches for patterns that indicate command output was returned in the
 * response, such as Unix passwd file entries, command output indicators
 * (uid=, gid=, etc.), or file listing formats. This helps detect command
 * injection vulnerabilities.
 * 
 * @param response The HTTP response to check
 * 
 * @return true if command output patterns are detected, false otherwise
 * 
 * @note Does not throw exceptions. Performs case-insensitive matching.
 */
bool contains_command_output(const HttpResponse& response);

/**
 * @brief Detects sensitive file content in an HTTP response body
 * 
 * Checks for content that indicates sensitive files were successfully read,
 * such as /etc/passwd entries, Windows hosts file content, or win.ini sections.
 * This is useful for detecting path traversal vulnerabilities where file
 * contents are exposed.
 * 
 * @param response The HTTP response to check
 * 
 * @return true if file content patterns are detected, false otherwise
 * 
 * @note Does not throw exceptions.
 */
bool contains_file_content(const HttpResponse& response);

/**
 * @brief Measures the time taken to perform an HTTP request
 * 
 * Executes an HTTP request and measures the elapsed time from start to finish.
 * This is essential for detecting time-based blind injection vulnerabilities
 * (like SQL injection with SLEEP() or command injection with sleep commands)
 * where the vulnerability manifests as a delay rather than visible output.
 * 
 * @param client The HTTP client to use for the request
 * @param request The HTTP request to measure
 * 
 * @return The response time in milliseconds
 * 
 * @note Does not throw exceptions. Returns 0.0 if request fails.
 */
double measure_response_time(HttpClient& client, const HttpRequest& request);

/**
 * @brief Checks if a response time exceeds a threshold (for blind injection detection)
 * 
 * A simple threshold check to determine if a response took longer than expected.
 * Useful for time-based blind injection tests where a delay indicates a
 * vulnerability (e.g., SQL injection with SLEEP(5) should take ~5 seconds).
 * 
 * @param response_time_ms The measured response time in milliseconds
 * @param threshold_ms The threshold to compare against (defaults to 5000ms)
 * 
 * @return true if response_time_ms >= threshold_ms, false otherwise
 * 
 * @note Does not throw exceptions.
 */
bool response_time_exceeds(double response_time_ms, double threshold_ms = 5000.0);

} // namespace test_helpers

