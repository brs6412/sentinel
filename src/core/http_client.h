#pragma once
#include <string>
#include <map>
#include <vector>

/**
 * @brief Represents an HTTP request.
 */
struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

/**
 * @brief Stores HTTP response returned by client.
 */
struct HttpResponse {
    long status = 0;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string effective_url;
    std::string error;
    double total_time = 0.0;
    size_t body_bytes = 0;
};

/**
 * @brief HTTP client class using libcurl.
 */
class HttpClient {
public:
    /**
     * @brief Configuration opts for client behavior.
     */
    struct Options {
        long timeout_seconds;
        long connect_timeout_seconds;
        bool follow_redirects;
        long max_redirects;
        std::string user_agent;
        bool accept_encoding;

        /// Default constructor with defaults.
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
     * @brief Construct an HttpClient with optional configuration.
     * @param opts Configuration options
     */
    explicit HttpClient(const Options& opts = Options());
    
    /// Clean up libcurl global state.
    ~HttpClient();

    /**
     * @brief Execute an HTTP request and populate the response.
     * @param req Input request parameters (URL, method, headers, body).
     * @param resp Output response data.
     * @return true if the request succeeded, false otherwise
     */
    bool perform(const HttpRequest& req, HttpResponse& resp) const;

private:
    Options opts_;
};
