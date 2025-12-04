#pragma once
#include <string>
#include <map>
#include <vector>

// HTTP client wrapper around libcurl.
// Provides a simple interface for making HTTP requests with configurable
// timeouts, redirect handling, and custom headers.

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    long status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string effective_url;
    std::string error;
    double total_time = 0.0;
    size_t body_bytes = 0;
};

class HttpClient {
public:
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
     * @brief Create an HTTP client with the given options
     * @param opts Client configuration (timeouts, redirects, etc.)
     */
    explicit HttpClient(const Options& opts = Options());
    
    ~HttpClient();

    /**
     * @brief Make an HTTP request and fill in the response
     * @param req Request details (method, URL, headers, body)
     * @param resp Response object that gets populated
     * @return true if request succeeded, false on error
     */
    bool perform(const HttpRequest& req, HttpResponse& resp) const;
    
    /**
     * @brief Build a Cookie header string from a map of cookies
     * @param cookies Map of cookie name -> value
     * @return Cookie header value string (e.g., "name1=value1; name2=value2")
     */
    static std::string build_cookie_header(const std::map<std::string, std::string>& cookies);

private:
    Options opts_;
};
