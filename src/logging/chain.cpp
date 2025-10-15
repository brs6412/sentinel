/**
 * @file chain.cpp
 * @brief Implementation of tamper-evident hash-chained JSONL logger
 */

#include "chain.h"
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <iostream>
#include <algorithm>

namespace logging {

using json = nlohmann::json;

// Convert LogEntry to JSON
json LogEntry::to_json() const {
    json j;
    j["event_type"] = event_type;
    j["run_id"] = run_id;
    j["timestamp"] = timestamp;
    j["prev_hash"] = prev_hash;
    j["entry_hash"] = entry_hash;
    j["payload"] = payload;
    if (!scan_id.empty()) {
        j["scan_id"] = scan_id;
    }
    return j;
}

// Parse LogEntry from JSON
LogEntry LogEntry::from_json(const json& j) {
    LogEntry entry;
    entry.event_type = j.value("event_type", "");
    entry.run_id = j.value("run_id", "");
    entry.scan_id = j.value("scan_id", "");
    entry.timestamp = j.value("timestamp", "");
    entry.prev_hash = j.value("prev_hash", "");
    entry.entry_hash = j.value("entry_hash", "");
    entry.payload = j.value("payload", json::object());
    return entry;
}

// Constructor
ChainLogger::ChainLogger(const std::string& log_path, const std::string& run_id)
    : log_path_(log_path), run_id_(run_id), last_hash_("") {
    
    // Try to load existing chain to continue it
    if (std::ifstream test(log_path); test.good()) {
        auto entries = load(log_path);
        if (!entries.empty()) {
            last_hash_ = entries.back().entry_hash;
        }
    }
    
    // Open in append mode
    log_stream_.open(log_path_, std::ios::app);
}

// Get current ISO8601 timestamp
std::string ChainLogger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::tm tm;
    gmtime_r(&time_t, &tm);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return oss.str();
}

// Canonicalize JSON (sorted keys, no whitespace)
std::string ChainLogger::canonicalize_json(const json& j) {
    // nlohmann::json dumps with sorted keys by default when using dump()
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

// Compute SHA-256 hash
std::string ChainLogger::compute_hash(const LogEntry& entry) {
    // Build canonical string: prev_hash + timestamp + event_type + run_id + payload
    std::ostringstream canonical;
    canonical << entry.prev_hash;
    canonical << entry.timestamp;
    canonical << entry.event_type;
    canonical << entry.run_id;
    canonical << canonicalize_json(entry.payload);
    
    std::string data = canonical.str();
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), 
           data.size(), hash);
    
    std::ostringstream hex;
    hex << "sha256:";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hex << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(hash[i]);
    }
    return hex.str();
}

// Append new entry
bool ChainLogger::append(const std::string& event_type, const json& payload) {
    if (!log_stream_.is_open()) {
        return false;
    }
    
    LogEntry entry;
    entry.event_type = event_type;
    entry.run_id = run_id_;
    entry.timestamp = get_timestamp();
    entry.prev_hash = last_hash_.empty() ? "sha256:genesis" : last_hash_;
    entry.payload = payload;
    
    // Compute hash for this entry
    entry.entry_hash = compute_hash(entry);
    
    // Write to log
    log_stream_ << entry.to_json().dump() << "\n";
    log_stream_.flush();
    
    // Update last hash
    last_hash_ = entry.entry_hash;
    
    return true;
}

// Load all entries from file
std::vector<LogEntry> ChainLogger::load(const std::string& log_path) {
    std::vector<LogEntry> entries;
    std::ifstream in(log_path);
    if (!in.is_open()) {
        return entries;
    }
    
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        try {
            json j = json::parse(line);
            entries.push_back(LogEntry::from_json(j));
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse log entry: " << e.what() << "\n";
        }
    }
    
    return entries;
}

// Verify log integrity
bool ChainLogger::verify(const std::string& log_path) {
    auto entries = load(log_path);
    
    if (entries.empty()) {
        std::cout << "✓ Log is empty (valid)\n";
        return true;
    }
    
    // First entry should have genesis prev_hash
    if (entries[0].prev_hash != "sha256:genesis") {
        std::cerr << "   First entry doesn't have genesis prev_hash\n";
        std::cerr << "   Expected: sha256:genesis\n";
        std::cerr << "   Got: " << entries[0].prev_hash << "\n";
        return false;
    }
    
    // Verify each entry's hash
    for (size_t i = 0; i < entries.size(); i++) {
        auto& entry = entries[i];
        
        // Recompute hash
        std::string computed = compute_hash(entry);
        
        if (computed != entry.entry_hash) {
            std::cerr << "   Hash mismatch at entry " << i << "\n";
            std::cerr << "   Expected: " << entry.entry_hash << "\n";
            std::cerr << "   Computed: " << computed << "\n";
            std::cerr << "   Event: " << entry.event_type << "\n";
            std::cerr << "   Timestamp: " << entry.timestamp << "\n";
            return false;
        }
        
        // Verify chain link (except first entry)
        if (i > 0) {
            if (entry.prev_hash != entries[i-1].entry_hash) {
                std::cerr << "   Chain break at entry " << i << "\n";
                std::cerr << "   prev_hash: " << entry.prev_hash << "\n";
                std::cerr << "   previous entry_hash: " << entries[i-1].entry_hash << "\n";
                return false;
            }
        }
    }
    
    std::cout << "✓ Log verified: " << entries.size() << " entries, chain intact\n";
    return true;
}

} // namespace logging