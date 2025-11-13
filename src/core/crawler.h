#pragma once
#include "http_client.h"
#include <schema/crawl_result.h>
#include <string>
#include <set>
#include <vector>
#include <nlohmann/json.hpp>

// Web crawler that follows links and extracts forms from HTML pages.
// Starts from seed URLs and recursively follows links up to a configurable depth.
// Can also load OpenAPI specs to discover API endpoints. Respects robots.txt when enabled.

struct Form;

class Crawler {
public:
    struct Options {
        int max_depth;
        bool respect_robots;

        Options()
            : max_depth(5),
              respect_robots(true)
        {}
    };

    /**
     * @brief Create a new crawler with an HTTP client and options
     * @param client HTTP client to use for fetching pages
     * @param opts Crawl options (max depth, robots.txt handling, etc.)
     */
    Crawler(const HttpClient& client, const Options& opts = Options());

    /**
     * @brief Add a starting URL for the crawl
     * @param url URL to start from
     */
    void add_seed(const std::string& url);

    /**
     * @brief Load an OpenAPI spec file to discover API endpoints
     * @param path Path to the OpenAPI JSON file
     * @return true if loaded successfully, false otherwise
     */
    bool load_openapi_file(const std::string& path);

    /**
     * @brief Start crawling from all seed URLs
     * @return List of crawl results with pages, links, and forms found
     */
    std::vector<CrawlResult> run();

private:
    const HttpClient& client_;
    Options opts_;
    std::vector<std::string> seeds_;
    std::set<std::string> visited_;
    nlohmann::json openapi_;

    /**
     * @brief Convert a relative or absolute URL into a fully qualified absolute URL
     * @param base Base URL for resolving relative URLs
     * @param href URL to normalize (can be relative or absolute)
     * @return Absolute URL
     */
    std::string normalize_url(const std::string& base, const std::string& href) const;

    /**
     * @brief Extract the origin (scheme + host + port) from a URL
     * @param url Full URL
     * @return Origin string, or empty if URL is invalid
     */
    std::string origin_of(const std::string& url) const;

    /**
     * @brief Parse HTML to find all links and forms
     * @param base_url Base URL for resolving relative links
     * @param body HTML content to parse
     * @param out_links Set that will be populated with found links
     * @param out_forms Vector that will be populated with found forms
     */
    void parse_html(
        const std::string& base_url,
        const std::string& body,
        std::set<std::string>& out_links,
        std::vector<Form>& out_forms
    ) const;

    /**
     * @brief Check if a path is allowed by robots.txt for the given origin
     * @param origin Origin (scheme + host + port) to check robots.txt for
     * @param path URL path to check
     * @return true if allowed, false if disallowed or robots.txt unavailable
     */
    bool robots_allows(const std::string& origin, const std::string& path) const;
};
