/**
 * @file test_chain.cpp
 * @brief Unit tests for hash-chained logger
 * 
 * Tests the append-only logger that chains entries together with hashes.
 * Verifies that tampering is detected and that the chain continues correctly
 * across multiple logger instances.
 */

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "logging/chain.h"
#include <filesystem>
#include <fstream>

using namespace logging;
namespace fs = std::filesystem;

/**
 * Test basic log entry creation and verification
 * @test_chain.cpp (23-130)
 */
TEST_CASE("ChainLogger creates valid log entries", "[chain]") {
    std::string test_log = "test_log.jsonl";
    
    // Clean up any existing test file
    if (fs::exists(test_log)) {
        fs::remove(test_log);
    }
    
    SECTION("Basic append and verify") {
        {
            ChainLogger logger(test_log, "test_run_1");
            
            nlohmann::json payload1;
            payload1["message"] = "first entry";
            REQUIRE(logger.append("test_event", payload1));
            
            nlohmann::json payload2;
            payload2["message"] = "second entry";
            REQUIRE(logger.append("test_event", payload2));
            
            REQUIRE(!logger.last_hash().empty());
        }
        
        // Verify the log
        REQUIRE(ChainLogger::verify(test_log));
        
        // Load and check entries
        auto entries = ChainLogger::load(test_log);
        REQUIRE(entries.size() == 2);
        REQUIRE(entries[0].event_type == "test_event");
        REQUIRE(entries[0].prev_hash == "sha256:genesis");
        REQUIRE(entries[1].prev_hash == entries[0].entry_hash);
    }
    
    SECTION("Chain continuation") {
        // First logger creates entries
        {
            ChainLogger logger1(test_log, "run1");
            nlohmann::json p;
            p["data"] = "entry1";
            logger1.append("event", p);
        }
        
        std::string last_hash1;
        {
            auto entries = ChainLogger::load(test_log);
            last_hash1 = entries.back().entry_hash;
        }
        
        // Second logger continues the chain
        {
            ChainLogger logger2(test_log, "run2");
            nlohmann::json p;
            p["data"] = "entry2";
            logger2.append("event", p);
        }
        
        // Verify chain is intact
        REQUIRE(ChainLogger::verify(test_log));
        
        auto entries = ChainLogger::load(test_log);
        REQUIRE(entries.size() == 2);
        REQUIRE(entries[1].prev_hash == last_hash1);
    }
    
    SECTION("Tamper detection") {
        {
            ChainLogger logger(test_log, "run");
            nlohmann::json p;
            p["value"] = 42;
            logger.append("event", p);
            logger.append("event", p);
        }
        
        // Verify original is valid
        REQUIRE(ChainLogger::verify(test_log));
        
        // Tamper with the log
        std::ifstream in(test_log);
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(in, line)) {
            lines.push_back(line);
        }
        in.close();
        
        // Modify second entry's payload
        if (lines.size() >= 2) {
            auto j = nlohmann::json::parse(lines[1]);
            j["payload"]["value"] = 999; // Tamper!
            lines[1] = j.dump();
            
            std::ofstream out(test_log);
            for (const auto& l : lines) {
                out << l << "\n";
            }
            out.close();
            
            // Verification should fail
            REQUIRE_FALSE(ChainLogger::verify(test_log));
        }
    }
    
    // Cleanup
    if (fs::exists(test_log)) {
        fs::remove(test_log);
    }
}

/**
 * Test that LogEntry can be serialized to JSON and back
 * @test_chain.cpp (136-159)
 */
TEST_CASE("LogEntry JSON serialization", "[chain]") {
    LogEntry entry;
    entry.event_type = "test";
    entry.run_id = "run123";
    entry.scan_id = "scan456";
    entry.timestamp = "2025-01-01T00:00:00Z";
    entry.prev_hash = "sha256:prev";
    entry.entry_hash = "sha256:current";
    entry.payload = nlohmann::json::object();
    entry.payload["key"] = "value";
    
    SECTION("to_json and from_json roundtrip") {
        auto json = entry.to_json();
        auto restored = LogEntry::from_json(json);
        
        REQUIRE(restored.event_type == entry.event_type);
        REQUIRE(restored.run_id == entry.run_id);
        REQUIRE(restored.scan_id == entry.scan_id);
        REQUIRE(restored.timestamp == entry.timestamp);
        REQUIRE(restored.prev_hash == entry.prev_hash);
        REQUIRE(restored.entry_hash == entry.entry_hash);
        REQUIRE(restored.payload == entry.payload);
    }
}