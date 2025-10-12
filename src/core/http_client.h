#pragma once
#include <string>
#include <map>
#include <vector>

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    long status = 0;
    std::map<std::string, std::string> headers;
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

    explicit HttpClient(const Options& opts = Options());
    ~HttpClient();

    bool perform(const HttpRequest& req, HttpResponse& resp) const;

private:
    Options opts_;
};
