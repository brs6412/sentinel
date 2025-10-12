#pragma once
#include <string>
#include <map>
#include <vector>

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
}

struct HttpResponse {
    long status = 0;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string effective_url;
    std::string error;
    double total_time = 0.0;
    size_t body_bytes = 0;
}

class HttpClient {
public:
    struct Options {
        long timeout_seconds = 15;
        long connect_timeout_seconds = 5;
        bool follow_redirects = false;
        long max_redirects = 0;
        std::string user_agent = "sentinel/0.1";
        bool accept_encoding = true;
    };

    explicit HttpClient(const Options& opts = Options());
    ~HttpClient();

    bool perform(const HttpRequest& req, HttpResponse& resp) const;

private:
    Options opts_;
};
