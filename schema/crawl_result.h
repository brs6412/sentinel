#pragma once

/**
 * @file crawl_result.h
 * @brief Data structure representing a single crawled page or endpoint
 * 
 * Contains the URL, method, parameters, headers, and discovery path for
 * each page or API endpoint found during crawling.
 */

/**
 * Results from crawling a single URL
 * @crawl_result.h (6-16)
 */
struct CrawlResult {
    std::string url;
    std::string method;
    std::vector<std::pair<std::string, std::string>> params;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::string> cookies;
    std::string source;
    std::vector<std::string> discovery_path;
    std::string timestamp;
    std::string hash;
};
