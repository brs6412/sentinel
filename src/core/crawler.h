#pragma once
#include "http_client.h"
#include <schema/crawl_result.h>
#include <string>
#include <set>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

/**
 * @file crawler.h
 * @brief Web crawler that follows links and extracts forms from HTML pages
 *
 * The crawler starts from seed URLs and recursively follows links up to a
 * configurable depth. It can also load OpenAPI specs to discover API endpoints.
 * Respects robots.txt when enabled.
 */

/**
 * Forward declaration for form struct passed by reference in parse_html
 */
struct Form;

/**
 * Crawls URLs and extracts links and forms
 * @crawler.h (28-122)
 */
class Crawler {
public:
    /**
     * Options controlling crawl behavior
     * @crawler.h (23-32)
     */
    struct Options {
        int max_depth;
        bool respect_robots;

        /// Default constructor
        Options()
            : max_depth(5),
              respect_robots(true)
        {}
    };

    /**
     * Create a new crawler with an HTTP client and options
     * @crawler.h (39)
     * @param client HTTP client to use for fetching pages
     * @param opts Crawl options (max depth, robots.txt handling, etc.)
     */
    Crawler(const HttpClient& client, const Options& opts = Options());

    /**
     * Add a starting URL for the crawl
     * @crawler.h (45)
     * @param url URL to start from
     */
    void add_seed(const std::string& url);

    /**
     * Load an OpenAPI spec file to discover API endpoints
     * @crawler.h (52)
     * @param path Path to the OpenAPI JSON file
     * @return true if loaded successfully, false otherwise
     */
    bool load_openapi_file(const std::string& path);

    /**
     * Start crawling from all seed URLs
     * @crawler.h (58)
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
     * Convert a relative or absolute URL into a fully qualified absolute URL
     * @crawler.h (73)
     * @param base Base URL for resolving relative URLs
     * @param href URL to normalize (can be relative or absolute)
     * @return Absolute URL
     */
    std::string normalize_url(const std::string& base, const std::string& href) const;

    /**
     * Extract the origin (scheme + host + port) from a URL
     * @crawler.h (80)
     * @param url Full URL
     * @return Origin string, or empty if URL is invalid
     */
    std::string origin_of(const std::string& url) const;

    /**
     * Parse HTML to find all links and forms
     * @crawler.h (89-94)
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
     * Check if a path is allowed by robots.txt for the given origin
     * @crawler.h (102)
     * @param origin Origin (scheme + host + port) to check robots.txt for
     * @param path URL path to check
     * @return true if allowed, false if disallowed or robots.txt unavailable
     */
    bool robots_allows(const std::string& origin, const std::string& path) const;
};
