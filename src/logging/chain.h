#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <fstream>

namespace logging {

/**
 * @file chain.h
 * @brief Append-only logger with hash chaining for tamper detection
 * 
 * Each log entry includes a hash of the previous entry, creating a chain.
 * This makes it easy to detect if someone modified or deleted entries.
 * Used for audit logging of security scans.
 */

/**
 * A single entry in the hash-chained log
 * @chain.h (12-23)
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
 * Append-only logger that chains entries together with hashes
 * @chain.h (28-90)
 * 
 * Each entry includes a hash of the previous entry, so you can verify
 * the log hasn't been tampered with by checking the chain.
 */
class ChainLogger {
public:
    /**
     * Create a logger that writes to a JSONL file
     * @chain.h (35)
     * @param log_path Path to the log file (will be created if needed)
     * @param run_id Unique ID for this scan run
     */
    explicit ChainLogger(const std::string& log_path, const std::string& run_id);
    
    /**
     * Add a new entry to the log with automatic hash chaining
     * @chain.h (43)
     * @param event_type What happened (e.g., "finding_recorded", "scan_start")
     * @param payload JSON data for this event
     * @return true if written successfully
     */
    bool append(const std::string& event_type, const nlohmann::json& payload);
    
    /**
     * Get the hash of the most recent entry
     * @chain.h (49)
     * @return Hash string, or empty if no entries yet
     */
    std::string last_hash() const { return last_hash_; }
    
    /**
     * Verify that a log file's hash chain is intact
     * @chain.h (56)
     * @param log_path Path to the log file to check
     * @return true if all hashes match and chain is valid
     */
    static bool verify(const std::string& log_path);
    
    /**
     * Read all entries from a log file
     * @chain.h (63)
     * @param log_path Path to the log file
     * @return List of all log entries
     */
    static std::vector<LogEntry> load(const std::string& log_path);

private:
    std::string log_path_;
    std::string run_id_;
    std::string last_hash_;
    std::ofstream log_stream_;
    
    /**
     * Compute SHA-256 hash of a log entry's canonical JSON
     * @chain.h (76)
     * @param entry The entry to hash
     * @return Hex-encoded hash
     */
    static std::string compute_hash(const LogEntry& entry);
    
    /**
     * Get current time as ISO8601 string
     * @chain.h (82)
     * @return Timestamp string
     */
    static std::string get_timestamp();
    
    /**
     * Convert JSON to a canonical string format for consistent hashing
     * @chain.h (89)
     * @param j JSON object to canonicalize
     * @return Canonical string representation
     */
    static std::string canonicalize_json(const nlohmann::json& j);
};

} // namespace logging