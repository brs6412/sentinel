#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <fstream>

namespace logging {

// Append-only logger with hash chaining for tamper detection.
// Each log entry includes a hash of the previous entry, creating a chain.
// This makes it easy to detect if someone modified or deleted entries.
// Used for audit logging of security scans.

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

// Append-only logger that chains entries together with hashes.
// Each entry includes a hash of the previous entry, so you can verify
// the log hasn't been tampered with by checking the chain.

class ChainLogger {
public:
    /**
     * @brief Create a logger that writes to a JSONL file
     * @param log_path Path to the log file (will be created if needed)
     * @param run_id Unique ID for this scan run
     */
    explicit ChainLogger(const std::string& log_path, const std::string& run_id);
    
    /**
     * @brief Add a new entry to the log with automatic hash chaining
     * @param event_type What happened (e.g., "finding_recorded", "scan_start")
     * @param payload JSON data for this event
     * @return true if written successfully
     */
    bool append(const std::string& event_type, const nlohmann::json& payload);
    
    /**
     * @brief Get the hash of the most recent entry
     * @return Hash string, or empty if no entries yet
     */
    std::string last_hash() const { return last_hash_; }
    
    /**
     * @brief Verify that a log file's hash chain is intact
     * @param log_path Path to the log file to check
     * @return true if all hashes match and chain is valid
     */
    static bool verify(const std::string& log_path);
    
    /**
     * @brief Read all entries from a log file
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
     * @brief Compute SHA-256 hash of a log entry's canonical JSON
     * @param entry The entry to hash
     * @return Hex-encoded hash
     */
    static std::string compute_hash(const LogEntry& entry);
    
    /**
     * @brief Get current time as ISO8601 string
     * @return Timestamp string
     */
    static std::string get_timestamp();
    
    /**
     * @brief Convert JSON to a canonical string format for consistent hashing
     * @param j JSON object to canonicalize
     * @return Canonical string representation
     */
    static std::string canonicalize_json(const nlohmann::json& j);
};

} // namespace logging