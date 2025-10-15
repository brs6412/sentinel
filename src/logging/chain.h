#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <fstream>

namespace logging {

/**
 * @brief Represents a single entry in the hash-chained log
 */
struct LogEntry {
    std::string event_type;
    std::string scan_id;
    std::string run_id;
    nlohmann::json payload;
    std::string prev_hash;
    std::string entry_hash;
    std::string timestamp;
    
    nlohmann::json to_json() const;
    static LogEntry from_json(const nlohmann::json& j);
};

/**
 * @brief Append-only JSONL logger with SHA-256 hash chaining for tamper evidence
 */
class ChainLogger {
public:
    /**
     * @brief Construct a logger that writes to specified path
     * @param log_path Path to JSONL log file
     * @param run_id Unique identifier for this scan run
     */
    explicit ChainLogger(const std::string& log_path, const std::string& run_id);
    
    /**
     * @brief Append a new entry to the log with hash chaining
     * @param event_type Type of event (e.g., "finding_recorded", "scan_start")
     * @param payload JSON data for this entry
     * @return true if successfully written
     */
    bool append(const std::string& event_type, const nlohmann::json& payload);
    
    /**
     * @brief Get the hash of the last entry (for chaining)
     * @return Hash string or empty if no entries
     */
    std::string last_hash() const { return last_hash_; }
    
    /**
     * @brief Verify integrity of a log file
     * @param log_path Path to JSONL log file to verify
     * @return true if all hashes are valid and chain is intact
     */
    static bool verify(const std::string& log_path);
    
    /**
     * @brief Load all entries from a log file
     * @param log_path Path to JSONL log file
     * @return Vector of log entries
     */
    static std::vector<LogEntry> load(const std::string& log_path);

private:
    std::string log_path_;
    std::string run_id_;
    std::string last_hash_;
    std::ofstream log_stream_;
    
    /**
     * @brief Compute SHA-256 hash of canonicalized JSON
     * @param entry The log entry to hash
     * @return Hex-encoded SHA-256 hash
     */
    static std::string compute_hash(const LogEntry& entry);
    
    /**
     * @brief Get current ISO8601 timestamp
     * @return Timestamp string
     */
    static std::string get_timestamp();
    
    /**
     * @brief Canonicalize JSON for stable hashing
     * @param j JSON object
     * @return Canonical string representation
     */
    static std::string canonicalize_json(const nlohmann::json& j);
};

} // namespace logging