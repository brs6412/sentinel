// Response pattern analysis implementation

#include "response_analyzer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <nlohmann/json.hpp>

ResponseAnalyzer::ResponseAnalyzer() {
    initialize_default_patterns();
}

ResponseAnalyzer::ResponseAnalyzer(const std::string& config_path) {
    initialize_default_patterns();
    load_patterns(config_path);
}

void ResponseAnalyzer::initialize_default_patterns() {
    patterns_.clear();

    // MySQL SQL Error Patterns
    PatternConfig mysql1;
    mysql1.name = "mysql_syntax_error";
    mysql1.type = PatternType::SQL_ERROR;
    mysql1.regex_pattern = R"(You have an error in your SQL syntax.*?near ['"]?([^'"]+)['"]? at line)";
    mysql1.database_type = "mysql";
    mysql1.confidence = 0.95;
    mysql1.case_sensitive = false;
    mysql1.description = "MySQL syntax error";
    patterns_.push_back(mysql1);

    PatternConfig mysql2;
    mysql2.name = "mysql_table_not_found";
    mysql2.type = PatternType::SQL_ERROR;
    mysql2.regex_pattern = R"(Table ['"]?([^'"]+)['"]? doesn't exist)";
    mysql2.database_type = "mysql";
    mysql2.confidence = 0.90;
    mysql2.case_sensitive = false;
    mysql2.description = "MySQL table not found";
    patterns_.push_back(mysql2);

    PatternConfig mysql3;
    mysql3.name = "mysql_access_denied";
    mysql3.type = PatternType::SQL_ERROR;
    mysql3.regex_pattern = R"(Access denied for user ['"]?([^'"]+)['"]?@)";
    mysql3.database_type = "mysql";
    mysql3.confidence = 0.85;
    mysql3.case_sensitive = false;
    mysql3.description = "MySQL access denied";
    patterns_.push_back(mysql3);

    // PostgreSQL SQL Error Patterns
    PatternConfig pg1;
    pg1.name = "postgresql_syntax_error";
    pg1.type = PatternType::SQL_ERROR;
    pg1.regex_pattern = R"(ERROR:\s+syntax error at or near ['"]?([^'"]+)['"]?)";
    pg1.database_type = "postgresql";
    pg1.confidence = 0.95;
    pg1.case_sensitive = false;
    pg1.description = "PostgreSQL syntax error";
    patterns_.push_back(pg1);

    PatternConfig pg2;
    pg2.name = "postgresql_relation_not_found";
    pg2.type = PatternType::SQL_ERROR;
    pg2.regex_pattern = R"(ERROR:\s+relation ['"]?([^'"]+)['"]? does not exist)";
    pg2.database_type = "postgresql";
    pg2.confidence = 0.90;
    pg2.case_sensitive = false;
    pg2.description = "PostgreSQL relation not found";
    patterns_.push_back(pg2);

    PatternConfig pg3;
    pg3.name = "postgresql_connection_failed";
    pg3.type = PatternType::SQL_ERROR;
    pg3.regex_pattern = R"(FATAL:\s+password authentication failed for user)";
    pg3.database_type = "postgresql";
    pg3.confidence = 0.85;
    pg3.case_sensitive = false;
    pg3.description = "PostgreSQL authentication failed";
    patterns_.push_back(pg3);

    // SQL Server Error Patterns
    PatternConfig mssql1;
    mssql1.name = "mssql_syntax_error";
    mssql1.type = PatternType::SQL_ERROR;
    mssql1.regex_pattern = R"(Unclosed quotation mark after the character string ['"]?([^'"]+)['"]?)";
    mssql1.database_type = "sql_server";
    mssql1.confidence = 0.95;
    mssql1.case_sensitive = false;
    mssql1.description = "SQL Server syntax error";
    patterns_.push_back(mssql1);

    PatternConfig mssql2;
    mssql2.name = "mssql_invalid_object";
    mssql2.type = PatternType::SQL_ERROR;
    mssql2.regex_pattern = R"(Invalid object name ['"]?([^'"]+)['"]?)";
    mssql2.database_type = "sql_server";
    mssql2.confidence = 0.90;
    mssql2.case_sensitive = false;
    mssql2.description = "SQL Server invalid object";
    patterns_.push_back(mssql2);

    PatternConfig mssql3;
    mssql3.name = "mssql_login_failed";
    mssql3.type = PatternType::SQL_ERROR;
    mssql3.regex_pattern = R"(Login failed for user ['"]?([^'"]+)['"]?)";
    mssql3.database_type = "sql_server";
    mssql3.confidence = 0.85;
    mssql3.case_sensitive = false;
    mssql3.description = "SQL Server login failed";
    patterns_.push_back(mssql3);

    // Oracle Error Patterns
    PatternConfig ora1;
    ora1.name = "oracle_syntax_error";
    ora1.type = PatternType::SQL_ERROR;
    ora1.regex_pattern = R"(ORA-\d+:\s*([^\n]+))";
    ora1.database_type = "oracle";
    ora1.confidence = 0.95;
    ora1.case_sensitive = false;
    ora1.description = "Oracle error code";
    patterns_.push_back(ora1);

    PatternConfig ora2;
    ora2.name = "oracle_table_not_found";
    ora2.type = PatternType::SQL_ERROR;
    ora2.regex_pattern = R"(ORA-00942:\s*table or view does not exist)";
    ora2.database_type = "oracle";
    ora2.confidence = 0.90;
    ora2.case_sensitive = false;
    ora2.description = "Oracle table not found";
    patterns_.push_back(ora2);

    // Command Output Patterns
    PatternConfig cmd1;
    cmd1.name = "passwd_file";
    cmd1.type = PatternType::COMMAND_OUTPUT;
    cmd1.regex_pattern = R"((?:root|daemon|bin|sys):[x*]:\d+:\d+:[^:]*:[^:]*:/[^:\s]+)";
    cmd1.confidence = 0.95;
    cmd1.case_sensitive = false;
    cmd1.description = "Unix passwd file content";
    patterns_.push_back(cmd1);

    PatternConfig cmd2;
    cmd2.name = "hosts_file";
    cmd2.type = PatternType::FILE_CONTENT;
    cmd2.regex_pattern = R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+localhost\s+localhost\.localdomain)";
    cmd2.confidence = 0.90;
    cmd2.case_sensitive = false;
    cmd2.description = "Unix hosts file content";
    patterns_.push_back(cmd2);

    PatternConfig cmd3;
    cmd3.name = "windows_hosts";
    cmd3.type = PatternType::FILE_CONTENT;
    cmd3.regex_pattern = R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+localhost\s+#\s+localhost)";
    cmd3.confidence = 0.90;
    cmd3.case_sensitive = false;
    cmd3.description = "Windows hosts file content";
    patterns_.push_back(cmd3);

    PatternConfig cmd4;
    cmd4.name = "web_config";
    cmd4.type = PatternType::FILE_CONTENT;
    cmd4.regex_pattern = R"(<configuration>.*?<connectionStrings>.*?</connectionStrings>.*?</configuration>)";
    cmd4.confidence = 0.85;
    cmd4.case_sensitive = false;
    cmd4.description = "ASP.NET web.config file";
    patterns_.push_back(cmd4);

    PatternConfig cmd5;
    cmd5.name = "command_output_username";
    cmd5.type = PatternType::COMMAND_OUTPUT;
    cmd5.regex_pattern = R"((?:uid|gid|groups?)\s*=\s*\d+)";
    cmd5.confidence = 0.75;
    cmd5.case_sensitive = false;
    cmd5.description = "Command output showing user info";
    patterns_.push_back(cmd5);

    PatternConfig cmd6;
    cmd6.name = "command_output_listing";
    cmd6.type = PatternType::COMMAND_OUTPUT;
    cmd6.regex_pattern = R"((?:total\s+\d+|drwx|-[rwx-]{9}\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+[^\n]+))";
    cmd6.confidence = 0.80;
    cmd6.case_sensitive = false;
    cmd6.description = "Unix file listing (ls -l output)";
    patterns_.push_back(cmd6);

    // Stack Trace Patterns
    PatternConfig st1;
    st1.name = "java_stack_trace";
    st1.type = PatternType::STACK_TRACE;
    st1.regex_pattern = R"(at\s+([\w\.]+)\.([\w\$]+)\([^)]+\.java:\d+\))";
    st1.framework = "java";
    st1.confidence = 0.95;
    st1.case_sensitive = false;
    st1.description = "Java stack trace";
    patterns_.push_back(st1);

    PatternConfig st2;
    st2.name = "python_traceback";
    st2.type = PatternType::STACK_TRACE;
    st2.regex_pattern = R"(Traceback\s+\(most recent call last\):.*?File\s+['"]?([^'"]+)['"]?,\s+line\s+(\d+))";
    st2.framework = "python";
    st2.confidence = 0.95;
    st2.case_sensitive = false;
    st2.description = "Python traceback";
    patterns_.push_back(st2);

    PatternConfig st3;
    st3.name = "dotnet_stack_trace";
    st3.type = PatternType::STACK_TRACE;
    st3.regex_pattern = R"(at\s+([\w\.]+)\.([\w]+)\([^)]+\)\s+in\s+([^:]+):line\s+\d+)";
    st3.framework = "dotnet";
    st3.confidence = 0.95;
    st3.case_sensitive = false;
    st3.description = ".NET stack trace";
    patterns_.push_back(st3);

    PatternConfig st4;
    st4.name = "php_fatal_error";
    st4.type = PatternType::STACK_TRACE;
    st4.regex_pattern = R"(Fatal error:.*?in\s+([^\s]+)\s+on\s+line\s+(\d+))";
    st4.framework = "php";
    st4.confidence = 0.90;
    st4.case_sensitive = false;
    st4.description = "PHP fatal error";
    patterns_.push_back(st4);

    PatternConfig st5;
    st5.name = "ruby_backtrace";
    st5.type = PatternType::STACK_TRACE;
    st5.regex_pattern = R"((?:[^\s]+\.rb:\d+:in\s+[^\n]+))";
    st5.framework = "ruby";
    st5.confidence = 0.90;
    st5.case_sensitive = false;
    st5.description = "Ruby backtrace";
    patterns_.push_back(st5);

    // Debug Information Patterns
    PatternConfig dbg1;
    dbg1.name = "internal_path";
    dbg1.type = PatternType::DEBUG_INFO;
    dbg1.regex_pattern = R"((?:/var/www|/home/[^/]+|C:\\[^:]+|D:\\[^:]+)[^\s<>"']+)";
    dbg1.confidence = 0.80;
    dbg1.case_sensitive = false;
    dbg1.description = "Internal file path exposure";
    patterns_.push_back(dbg1);

    PatternConfig dbg2;
    dbg2.name = "version_number";
    dbg2.type = PatternType::DEBUG_INFO;
    dbg2.regex_pattern = R"((?:version|v)\s*[:=]\s*[\d\.]+(?:-SNAPSHOT|-beta|-alpha|\.dev)?)";
    dbg2.confidence = 0.70;
    dbg2.case_sensitive = false;
    dbg2.description = "Version number exposure";
    patterns_.push_back(dbg2);

    PatternConfig dbg3;
    dbg3.name = "database_connection_string";
    dbg3.type = PatternType::DEBUG_INFO;
    dbg3.regex_pattern = R"((?:jdbc|mysql|postgresql|sqlserver|oracle):[^\s<>"']+)";
    dbg3.confidence = 0.85;
    dbg3.case_sensitive = false;
    dbg3.description = "Database connection string";
    patterns_.push_back(dbg3);

    // Internal IP address patterns
    PatternConfig ip1;
    ip1.name = "private_ip_10";
    ip1.type = PatternType::DEBUG_INFO;
    ip1.regex_pattern = R"(\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)";
    ip1.confidence = 0.90;
    ip1.case_sensitive = false;
    ip1.description = "Private IP address (10.x.x.x)";
    patterns_.push_back(ip1);

    PatternConfig ip2;
    ip2.name = "private_ip_192";
    ip2.type = PatternType::DEBUG_INFO;
    ip2.regex_pattern = R"(\b192\.168\.\d{1,3}\.\d{1,3}\b)";
    ip2.confidence = 0.90;
    ip2.case_sensitive = false;
    ip2.description = "Private IP address (192.168.x.x)";
    patterns_.push_back(ip2);

    PatternConfig ip3;
    ip3.name = "private_ip_172";
    ip3.type = PatternType::DEBUG_INFO;
    ip3.regex_pattern = R"(\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b)";
    ip3.confidence = 0.90;
    ip3.case_sensitive = false;
    ip3.description = "Private IP address (172.16-31.x.x)";
    patterns_.push_back(ip3);

    // Version information patterns
    PatternConfig ver1;
    ver1.name = "php_version";
    ver1.type = PatternType::DEBUG_INFO;
    ver1.regex_pattern = R"(PHP\s*[/\s]?\s*(\d+\.\d+\.\d+))";
    ver1.confidence = 0.85;
    ver1.case_sensitive = false;
    ver1.description = "PHP version number";
    patterns_.push_back(ver1);

    PatternConfig ver2;
    ver2.name = "framework_version";
    ver2.type = PatternType::DEBUG_INFO;
    ver2.regex_pattern = R"((?:Django|Rails|Laravel|Symfony|Spring|Express)\s*[/\s]?\s*(\d+\.\d+\.\d+))";
    ver2.confidence = 0.85;
    ver2.case_sensitive = false;
    ver2.description = "Framework version number";
    patterns_.push_back(ver2);

    PatternConfig ver3;
    ver3.name = "server_version";
    ver3.type = PatternType::DEBUG_INFO;
    ver3.regex_pattern = R"((?:Apache|nginx|IIS|Tomcat)\s*[/\s]?\s*(\d+\.\d+\.\d+))";
    ver3.confidence = 0.85;
    ver3.case_sensitive = false;
    ver3.description = "Server version number";
    patterns_.push_back(ver3);

    // Debug mode indicators
    PatternConfig debug1;
    debug1.name = "debug_mode_true";
    debug1.type = PatternType::DEBUG_INFO;
    debug1.regex_pattern = R"(\bdebug\s*[:=]\s*true\b)";
    debug1.confidence = 0.80;
    debug1.case_sensitive = false;
    debug1.description = "Debug mode enabled";
    patterns_.push_back(debug1);

    PatternConfig debug2;
    debug2.name = "debug_mode_on";
    debug2.type = PatternType::DEBUG_INFO;
    debug2.regex_pattern = R"(\bdebug\s*[:=]\s*on\b)";
    debug2.confidence = 0.80;
    debug2.case_sensitive = false;
    debug2.description = "Debug mode on";
    patterns_.push_back(debug2);

    PatternConfig debug3;
    debug3.name = "detailed_error";
    debug3.type = PatternType::DEBUG_INFO;
    debug3.regex_pattern = R"(\b(?:detailed|verbose|full)\s+error\b)";
    debug3.confidence = 0.75;
    debug3.case_sensitive = false;
    debug3.description = "Detailed error mode";
    patterns_.push_back(debug3);

    // Node.js stack traces
    PatternConfig st6;
    st6.name = "nodejs_stack_trace";
    st6.type = PatternType::STACK_TRACE;
    st6.regex_pattern = R"(Error:.*?\n\s+at\s+[^\n]+\([^)]+\)\n\s+at\s+[^\n]+)";
    st6.framework = "nodejs";
    st6.confidence = 0.95;
    st6.case_sensitive = false;
    st6.description = "Node.js stack trace";
    patterns_.push_back(st6);

    // Framework Error Patterns
    PatternConfig fw1;
    fw1.name = "django_error";
    fw1.type = PatternType::FRAMEWORK_ERROR;
    fw1.regex_pattern = R"(django\.(?:core|db|utils)\.exceptions\.[\w]+)";
    fw1.framework = "django";
    fw1.confidence = 0.90;
    fw1.case_sensitive = false;
    fw1.description = "Django framework error";
    patterns_.push_back(fw1);

    PatternConfig fw2;
    fw2.name = "rails_error";
    fw2.type = PatternType::FRAMEWORK_ERROR;
    fw2.regex_pattern = R"(ActionController::|ActiveRecord::|ActionView::)";
    fw2.framework = "rails";
    fw2.confidence = 0.90;
    fw2.case_sensitive = false;
    fw2.description = "Ruby on Rails error";
    patterns_.push_back(fw2);
}

bool ResponseAnalyzer::load_patterns(const std::string& config_path) {
    std::ifstream in(config_path);
    if (!in.is_open()) {
        return false;
    }

    // Simple YAML parser for pattern configuration
    // Expected format:
    // patterns:
    //   - name: "custom_pattern"
    //     type: "sql_error"
    //     regex: "pattern here"
    //     database_type: "mysql"
    //     confidence: 0.9

    std::string line;
    bool in_patterns = false;
    bool in_pattern = false;
    PatternConfig current_pattern;
    int indent_level = 0;

    while (std::getline(in, line)) {
        // Remove comments
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        if (line.empty()) continue;

        // Count leading spaces for indentation
        size_t leading_spaces = 0;
        while (leading_spaces < line.length() && line[leading_spaces] == ' ') {
            leading_spaces++;
        }
        int current_indent = leading_spaces / 2;

        // Parse key-value pairs
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) continue;

        std::string key = line.substr(0, colon_pos);
        key.erase(key.find_last_not_of(" \t") + 1);

        std::string value = line.substr(colon_pos + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        if (value.size() >= 2 && value[0] == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }

        if (key == "patterns" && current_indent == 0) {
            in_patterns = true;
            continue;
        }

        if (in_patterns) {
            if (key == "-" || (key == "name" && current_indent == 1)) {
                // Start of new pattern
                if (in_pattern && !current_pattern.name.empty()) {
                    patterns_.push_back(current_pattern);
                }
                current_pattern = PatternConfig();
                in_pattern = true;
                if (key == "name") {
                    current_pattern.name = value;
                }
            } else if (in_pattern) {
                if (key == "name") {
                    current_pattern.name = value;
                } else if (key == "type") {
                    std::string type_lower = value;
                    std::transform(type_lower.begin(), type_lower.end(), type_lower.begin(), ::tolower);
                    if (type_lower == "sql_error") {
                        current_pattern.type = PatternType::SQL_ERROR;
                    } else if (type_lower == "command_output") {
                        current_pattern.type = PatternType::COMMAND_OUTPUT;
                    } else if (type_lower == "file_content") {
                        current_pattern.type = PatternType::FILE_CONTENT;
                    } else if (type_lower == "stack_trace") {
                        current_pattern.type = PatternType::STACK_TRACE;
                    } else if (type_lower == "debug_info") {
                        current_pattern.type = PatternType::DEBUG_INFO;
                    } else if (type_lower == "framework_error") {
                        current_pattern.type = PatternType::FRAMEWORK_ERROR;
                    }
                } else if (key == "regex" || key == "pattern") {
                    current_pattern.regex_pattern = value;
                } else if (key == "database_type" || key == "db_type") {
                    current_pattern.database_type = value;
                } else if (key == "framework") {
                    current_pattern.framework = value;
                } else if (key == "confidence") {
                    try {
                        current_pattern.confidence = std::stod(value);
                    } catch (...) {
                        current_pattern.confidence = 0.8;
                    }
                } else if (key == "case_sensitive") {
                    current_pattern.case_sensitive = (value == "true" || value == "1");
                } else if (key == "description") {
                    current_pattern.description = value;
                }
            }
        }
    }

    // Save last pattern if any
    if (in_pattern && !current_pattern.name.empty()) {
        patterns_.push_back(current_pattern);
    }

    return true;
}

void ResponseAnalyzer::add_pattern(const PatternConfig& pattern) {
    patterns_.push_back(pattern);
}

std::vector<PatternConfig> ResponseAnalyzer::get_patterns() const {
    return patterns_;
}

AnalysisResult ResponseAnalyzer::analyze(const std::string& response_body,
                                        const std::map<std::string, std::string>& response_headers) const {
    AnalysisResult result;

    if (response_body.empty()) {
        return result;
    }

    // Match all patterns against response body
    for (const auto& pattern : patterns_) {
        PatternMatch match;
        if (match_pattern(pattern, response_body, match)) {
            // Validate context to reduce false positives
            if (validate_context(match, response_body)) {
                result.matches.push_back(match);

                // Update result flags
                switch (match.type) {
                    case PatternType::SQL_ERROR:
                        result.has_sql_error = true;
                        if (result.detected_db_type == DatabaseType::UNKNOWN) {
                            result.detected_db_type = match.db_type;
                        }
                        break;
                    case PatternType::COMMAND_OUTPUT:
                        result.has_command_output = true;
                        break;
                    case PatternType::FILE_CONTENT:
                        result.has_file_content = true;
                        break;
                    case PatternType::STACK_TRACE:
                        result.has_stack_trace = true;
                        if (result.detected_framework.empty()) {
                            result.detected_framework = match.framework;
                        }
                        break;
                    case PatternType::DEBUG_INFO:
                        result.has_debug_info = true;
                        break;
                    case PatternType::FRAMEWORK_ERROR:
                        result.has_framework_error = true;
                        if (result.detected_framework.empty()) {
                            result.detected_framework = match.framework;
                        }
                        break;
                }
            }
        }
    }

    result.summary = build_summary(result);
    return result;
}

bool ResponseAnalyzer::match_pattern(const PatternConfig& pattern,
                                    const std::string& response_body,
                                    PatternMatch& match) const {
    try {
        std::regex regex_pattern;
        if (pattern.case_sensitive) {
            regex_pattern = std::regex(pattern.regex_pattern);
        } else {
            regex_pattern = std::regex(pattern.regex_pattern, std::regex_constants::icase);
        }

        std::smatch regex_match;
        if (std::regex_search(response_body, regex_match, regex_pattern)) {
            match.type = pattern.type;
            match.pattern_name = pattern.name;
            match.confidence = pattern.confidence;

            // Extract matched text
            if (regex_match.size() > 0) {
                match.evidence = regex_match[0].str();
            }

            // Extract context
            size_t match_pos = regex_match.position(0);
            size_t match_length = regex_match.length(0);
            match.context = extract_context(response_body, match_pos, match_length);

            // Set database type if applicable
            if (pattern.type == PatternType::SQL_ERROR && !pattern.database_type.empty()) {
                match.db_type = parse_database_type(pattern.database_type);
            }

            // Set framework if applicable
            if (!pattern.framework.empty()) {
                match.framework = pattern.framework;
            }

            return true;
        }
    } catch (const std::regex_error& e) {
        // Invalid regex pattern, skip
        return false;
    }

    return false;
}

std::string ResponseAnalyzer::extract_context(const std::string& response_body,
                                             size_t match_pos,
                                             size_t match_length,
                                             size_t context_size) const {
    size_t start = (match_pos > context_size) ? match_pos - context_size : 0;
    size_t end = std::min(response_body.length(), match_pos + match_length + context_size);

    std::string context = response_body.substr(start, end - start);

    // Replace newlines with spaces for readability
    std::replace(context.begin(), context.end(), '\n', ' ');
    std::replace(context.begin(), context.end(), '\r', ' ');

    return context;
}

bool ResponseAnalyzer::validate_context(const PatternMatch& match,
                                       const std::string& response_body) const {
    // Basic validation to reduce false positives

    // Check if match is in HTML comment (likely not a real error)
    size_t match_pos = response_body.find(match.evidence);
    if (match_pos != std::string::npos) {
        // Check for HTML comment markers before match
        size_t comment_start = response_body.rfind("<!--", match_pos);
        size_t comment_end = response_body.find("-->", match_pos);
        if (comment_start != std::string::npos &&
            (comment_end == std::string::npos || comment_end > match_pos)) {
            // Match is inside HTML comment, likely false positive
            return false;
        }

        // Check if match is in script tag with error handling (might be intentional)
        size_t script_start = response_body.rfind("<script", match_pos);
        size_t script_end = response_body.find("</script>", match_pos);
        if (script_start != std::string::npos &&
            script_end != std::string::npos &&
            script_end > match_pos) {
            // Check if it's error handling code
            std::string script_content = response_body.substr(script_start, script_end - script_start);
            std::string script_lower = script_content;
            std::transform(script_lower.begin(), script_lower.end(), script_lower.begin(), ::tolower);
            if (script_lower.find("catch") != std::string::npos ||
                script_lower.find("error") != std::string::npos) {
                // Might be intentional error handling, reduce confidence
                return match.confidence > 0.7;
            }
        }
    }

    // Additional validation: check if it's a very short match (might be false positive)
    if (match.evidence.length() < 10 && match.confidence < 0.8) {
        return false;
    }

    return true;
}

DatabaseType ResponseAnalyzer::parse_database_type(const std::string& db_type_str) const {
    std::string lower = db_type_str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "mysql") {
        return DatabaseType::MYSQL;
    } else if (lower == "postgresql" || lower == "postgres") {
        return DatabaseType::POSTGRESQL;
    } else if (lower == "sql_server" || lower == "mssql" || lower == "sqlserver") {
        return DatabaseType::SQL_SERVER;
    } else if (lower == "oracle") {
        return DatabaseType::ORACLE;
    }

    return DatabaseType::UNKNOWN;
}

std::string ResponseAnalyzer::build_summary(const AnalysisResult& result) const {
    if (!result.has_indicators()) {
        return "No vulnerability indicators detected";
    }

    std::ostringstream summary;
    summary << "Detected: ";

    std::vector<std::string> indicators;
    if (result.has_sql_error) {
        std::string db_name = "Unknown";
        switch (result.detected_db_type) {
            case DatabaseType::MYSQL: db_name = "MySQL"; break;
            case DatabaseType::POSTGRESQL: db_name = "PostgreSQL"; break;
            case DatabaseType::SQL_SERVER: db_name = "SQL Server"; break;
            case DatabaseType::ORACLE: db_name = "Oracle"; break;
            default: break;
        }
        indicators.push_back("SQL error (" + db_name + ")");
    }
    if (result.has_command_output) {
        indicators.push_back("command output");
    }
    if (result.has_file_content) {
        indicators.push_back("file content");
    }
    if (result.has_stack_trace) {
        std::string framework = result.detected_framework.empty() ? "unknown" : result.detected_framework;
        indicators.push_back("stack trace (" + framework + ")");
    }
    if (result.has_debug_info) {
        indicators.push_back("debug information");
    }
    if (result.has_framework_error) {
        std::string framework = result.detected_framework.empty() ? "unknown" : result.detected_framework;
        indicators.push_back("framework error (" + framework + ")");
    }

    for (size_t i = 0; i < indicators.size(); ++i) {
        if (i > 0) {
            summary << ", ";
        }
        summary << indicators[i];
    }

    summary << " (" << result.matches.size() << " pattern(s) matched)";

    return summary.str();
}

