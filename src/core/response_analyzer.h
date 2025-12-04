#pragma once
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <memory>

// Response pattern analysis for detecting vulnerability indicators in HTTP responses.
// Detects SQL errors, command output, file content leaks, stack traces, and debug information.

enum class DatabaseType {
    UNKNOWN,
    MYSQL,
    POSTGRESQL,
    SQL_SERVER,
    ORACLE
};

enum class PatternType {
    SQL_ERROR,
    COMMAND_OUTPUT,
    FILE_CONTENT,
    STACK_TRACE,
    DEBUG_INFO,
    FRAMEWORK_ERROR
};

struct PatternMatch {
    PatternType type;
    std::string pattern_name;
    std::string evidence;           // Matched text snippet
    std::string context;             // Surrounding context
    DatabaseType db_type;            // For SQL errors
    std::string framework;          // For stack traces/framework errors
    double confidence;               // Confidence score (0.0-1.0)
    
    PatternMatch()
        : type(PatternType::SQL_ERROR),
          db_type(DatabaseType::UNKNOWN),
          confidence(0.0)
    {}
};

struct AnalysisResult {
    bool has_sql_error;
    bool has_command_output;
    bool has_file_content;
    bool has_stack_trace;
    bool has_debug_info;
    bool has_framework_error;
    
    DatabaseType detected_db_type;
    std::string detected_framework;
    
    std::vector<PatternMatch> matches;  // All detected patterns
    std::string summary;                 // Human-readable summary
    
    AnalysisResult()
        : has_sql_error(false),
          has_command_output(false),
          has_file_content(false),
          has_stack_trace(false),
          has_debug_info(false),
          has_framework_error(false),
          detected_db_type(DatabaseType::UNKNOWN)
    {}
    
    /**
     * @brief Check if any vulnerability indicators were detected
     * @return true if any indicators found
     */
    bool has_indicators() const {
        return has_sql_error || has_command_output || has_file_content ||
               has_stack_trace || has_debug_info || has_framework_error;
    }
};

// Pattern configuration loaded from YAML
struct PatternConfig {
    std::string name;
    PatternType type;
    std::string regex_pattern;
    std::string database_type;        // For SQL errors: "mysql", "postgresql", etc.
    std::string framework;            // For stack traces: "java", "python", etc.
    double confidence;                // Default confidence for this pattern
    bool case_sensitive;
    std::string description;
    
    PatternConfig()
        : type(PatternType::SQL_ERROR),
          confidence(0.8),
          case_sensitive(false)
    {}
};

class ResponseAnalyzer {
public:
    /**
     * @brief Create a response analyzer with default patterns
     */
    ResponseAnalyzer();
    
    /**
     * @brief Create a response analyzer and load patterns from YAML
     * @param config_path Path to response_patterns.yaml
     */
    explicit ResponseAnalyzer(const std::string& config_path);
    
    /**
     * @brief Analyze HTTP response body for vulnerability indicators
     * @param response_body HTTP response body content
     * @param response_headers Optional response headers for context
     * @return Analysis result with detected patterns
     */
    AnalysisResult analyze(const std::string& response_body, 
                          const std::map<std::string, std::string>& response_headers = {}) const;
    
    /**
     * @brief Load patterns from YAML configuration file
     * @param config_path Path to response_patterns.yaml
     * @return true if loaded successfully, false otherwise
     */
    bool load_patterns(const std::string& config_path);
    
    /**
     * @brief Add a custom pattern
     * @param pattern Pattern configuration to add
     */
    void add_pattern(const PatternConfig& pattern);
    
    /**
     * @brief Get all loaded patterns
     * @return Vector of pattern configurations
     */
    std::vector<PatternConfig> get_patterns() const;

private:
    std::vector<PatternConfig> patterns_;
    
    /**
     * @brief Initialize default patterns (hardcoded)
     */
    void initialize_default_patterns();
    
    /**
     * @brief Match a single pattern against response body
     * @param pattern Pattern to match
     * @param response_body Response body to analyze
     * @param match Output match result if found
     * @return true if pattern matched
     */
    bool match_pattern(const PatternConfig& pattern, 
                      const std::string& response_body,
                      PatternMatch& match) const;
    
    /**
     * @brief Extract context around a match (surrounding text)
     * @param response_body Full response body
     * @param match_pos Position of match
     * @param match_length Length of match
     * @param context_size Number of characters before/after to include
     * @return Context string
     */
    std::string extract_context(const std::string& response_body,
                               size_t match_pos,
                               size_t match_length,
                               size_t context_size = 100) const;
    
    /**
     * @brief Validate pattern context to reduce false positives
     * @param match Pattern match to validate
     * @param response_body Full response body
     * @return true if match is likely a true positive
     */
    bool validate_context(const PatternMatch& match, 
                         const std::string& response_body) const;
    
    /**
     * @brief Convert database type string to enum
     * @param db_type_str Database type string
     * @return DatabaseType enum
     */
    DatabaseType parse_database_type(const std::string& db_type_str) const;
    
    /**
     * @brief Build summary string from analysis result
     * @param result Analysis result
     * @return Human-readable summary
     */
    std::string build_summary(const AnalysisResult& result) const;
};

