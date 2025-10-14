/**
 * @file http_client.cpp
 * @brief Lightweight HTTP client using libcurl
 */

#include "http_client.h"
#include <curl/curl.h>
#include <stdexcept>
#include <sstream>
#include <algorithm>

/// Callback invoked by libcurl to write the received body data.
static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

/// Callback invoked once per header line to parse header into map.
static size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t total = size * nitems;
    std::string_view hv(buffer, total);
    auto* headers = static_cast<std::vector<std::pair<std::string, std::string>>*>(userdata);

    auto pos = hv.find(':');
    if (pos != std::string_view::npos) {
        std::string name(hv.substr(0, pos));

        size_t val_start = pos + 1;
        while (val_start < hv.size() && (hv[val_start] == ' ' || hv[val_start] == '\t'))
            val_start++;

        size_t val_end = hv.size();
        while (val_end > val_start && (hv[val_end - 1] == '\r' || hv[val_end - 1] == '\n'))
            val_end--;
        std::string value(hv.substr(val_start, val_end - val_start));

        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c){ return std::tolower(c); });
        
        headers->emplace_back(std::move(name), std::move(value));
    }
    return total;
}

/// Initialize global libcurl state.
HttpClient::HttpClient(const Options& opts) : opts_(opts) {
    CURLcode c = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (c != CURLE_OK) {
        throw std::runtime_error("curl_global_init failed");
    }
}

/// Clean up global libcurl state.
HttpClient::~HttpClient() {
    curl_global_cleanup();
}

/// Execute an HTTP request and populate a response object.
bool HttpClient::perform(const HttpRequest& req, HttpResponse& resp) const {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string body;
    std::vector<std::pair<std::string, std::string>> resp_headers;

    // Basic configuration
    curl_easy_setopt(curl, CURLOPT_URL, req.url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, opts_.connect_timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, opts_.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, opts_.follow_redirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, opts_.max_redirects);

    // Response and header callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

    // Misc options
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp_headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, opts_.user_agent.c_str());
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    if (opts_.accept_encoding) curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    // Request headers
    struct curl_slist* curl_headers = nullptr;
    for (const auto& h : req.headers) {
        std::string line = h.first + ": " + h.second;
        curl_headers = curl_slist_append(curl_headers, line.c_str());
    }
    if (curl_headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);

    // HTTP method and body
    if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req.method.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req.body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body.size()));
    } else if (req.method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req.method.c_str());
    }

    // Error buffer setup
    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    // Perform request
    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        resp.error = errbuf[0] ? std::string(errbuf) : curl_easy_strerror(rc);
    }

    // Extract response info
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.status);

    char* effective_url = nullptr;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
    if (effective_url) resp.effective_url = effective_url;

    double total_time = 0.0;
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    // Populate response
    resp.total_time = total_time;
    resp.body = std::move(body);
    resp.body_bytes = resp.body.size();
    resp.headers = std::move(resp_headers);
    
    // Cleanup
    if (curl_headers) curl_slist_free_all(curl_headers);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK;
}
