#pragma once
#include <map>
#include <nlohmann/json.hpp>

/**
 * @file finding.h
 * @brief Data structure representing a security finding
 * 
 * Contains all the information needed to reproduce and understand a security
 * issue discovered during scanning.
 */

/**
 * Represents a security finding that needs reproduction artifacts
 * @finding.h (8-19)
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
