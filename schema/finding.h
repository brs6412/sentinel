/**
 * @brief Represents a finding that needs reproduction artifacts
 */
struct Finding {
    std::string id;
    std::string url;
    std::string category;
    std::string method;
    std::map<std::string, std::string> headers;
    std::string body;
    nlohmann::json evidence;
    std::string severity;
    double confidence;
    std::string remediation_id;
};
