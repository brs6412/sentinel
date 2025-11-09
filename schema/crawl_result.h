/**
 * @brief Represents results of crawling a single url
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
}
