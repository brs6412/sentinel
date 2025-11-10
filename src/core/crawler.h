#pragma once
#include "http_client.h"
#include <schema/crawl_result.h>
#include <string>
#include <set>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

/**
 @brief Forward declaration for form struct passed by reference in parse_html
 */
struct Form;

/**
 * @brief Crawls URLs and extracts links and forms
 */
class Crawler {
public:
    /**
     * @brief Options controlling crawl behavior
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
     * @brief Constructs a Crawler object
     * @param client Reference to HttpClient for fetching pages
     * @param opts Crawl options
     */
    Crawler(const HttpClient& client, const Options& opts = Options());

    /**
     * @brief Add a seed URL to start crawling from.
     * @param url URL to add to seeds list.
     */
    void add_seed(const std::string& url);

    /**
     * @brief Load OpenAPI JSON file to integrate API paths into crawl.
     * @param path Path to the OpenAPI JSON file.
     * @return true if successful load, false otherwise
     */
    bool load_openapi_file(const std::string& path);

    /**
     * @brief Run the crawler on the seed URLs.
     * @return Vector of CrawlResult containing crawled pages, links, forms.
     */
    std::vector<CrawlResult> run();

private:
    const HttpClient& client_;
    Options opts_;
    std::vector<std::string> seeds_;
    std::set<std::string> visited_;
    nlohmann::json openapi_;

    /**
     * @brief Normalize a relative or absolute URL to absolute form.
     * @param base Base URL to resolve relative hrefs.
     * @param href URL to normalize.
     * @return Absolute URL string.
     */
    std::string normalize_url(const std::string& base, const std::string& href) const;

    /**
     * @brief Extract origin of a URL.
     * @param url URL string.
     * @return Origin string or empty if invalid.
     */
    std::string origin_of(const std::string& url) const;

    /**
     * @brief Parse HTML content to extract links and forms.
     * @param base_url Base URL of the page to resolving relative links.
     * @param body HTML content.
     * @param out_links Set to store extracted links.
     * @param out_forms Vector to store extracted forms.
     */
    void parse_html(
        const std::string& base_url, 
        const std::string& body, 
        std::set<std::string>& out_links, 
        std::vector<Form>& out_forms
    ) const;

    /**
     * @brief CHeck whether a URL path is allowed according to robots.txt. 
     * @param origin Origin of the URL.
     * @param path Path to check.
     * @retrurn true if allowed, false otherwise
     */
    bool robots_allows(const std::string& origin, const std::string& path) const;
};
