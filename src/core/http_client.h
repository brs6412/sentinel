#pragma once
#include <string>
#include <map>
#include <vector>

/**
 * @file http_client.h
 * @brief HTTP client wrapper around libcurl
 * 
 * Provides a simple interface for making HTTP requests with configurable
 * timeouts, redirect handling, and custom headers.
 */

/**
 * HTTP request parameters
 * @http_client.h (9-14)
 */
struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

/**
 * HTTP response data
 * @http_client.h (19-27)
 */
struct HttpResponse {
    long status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string effective_url;
    std::string error;
    double total_time = 0.0;
    size_t body_bytes = 0;
};

/**
 * HTTP client using libcurl under the hood
 * @http_client.h (32-75)
 */
class HttpClient {
public:
    /**
     * Configuration options for the HTTP client
     * @http_client.h (37-54)
     */
    struct Options {
        long timeout_seconds;
        long connect_timeout_seconds;
        bool follow_redirects;
        long max_redirects;
        std::string user_agent;
        bool accept_encoding;

        Options()
            : timeout_seconds(15),
              connect_timeout_seconds(5),
              follow_redirects(true),
              max_redirects(5),
              user_agent("sentinel/0.1"),
              accept_encoding(true)
        {}
    };

    /**
     * Create an HTTP client with the given options
     * @http_client.h (60)
     * @param opts Client configuration (timeouts, redirects, etc.)
     */
    explicit HttpClient(const Options& opts = Options());
    
    /**
     * Clean up libcurl resources
     * @http_client.h (63)
     */
    ~HttpClient();

    /**
     * Make an HTTP request and fill in the response
     * @http_client.h (71)
     * @param req Request details (method, URL, headers, body)
     * @param resp Response object that gets populated
     * @return true if request succeeded, false on error
     */
    bool perform(const HttpRequest& req, HttpResponse& resp) const;

private:
    Options opts_;
};
