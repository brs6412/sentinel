// src/sentinel_llm.cpp
//
// Purpose:
//   A tiny, self-contained CLI that simulates an LLM “augmentation” step.
//   In this stub (used when no real LLM backend like Ollama is available),
//   we simply copy a baseline YAML to an “augmented” YAML and emit a small
//   JSON manifest containing the output file’s SHA-256. This lets the rest
//   of the pipeline run deterministically and verify artifacts.
//
// Usage:
//   sentinel-llm --in INPUT.yaml --out OUTPUT.yaml \
//                [--model NAME] [--max-new N] [--temperature T] \
//                [--seed S] [--manifest PATH]
//
// Notes:
//   - Only --in, --out, and optionally --manifest influence I/O.
//   - --model/--max-new/--temperature/--seed are accepted for parity with
//     a real LLM interface, but in this stub they are only logged.
//   - SHA-256 is implemented locally (tinysha256 namespace) to avoid deps.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace tinysha256 {
// ---- Minimal SHA-256 implementation (single-file, no external deps) ----
// This is deliberately compact but now spaced and commented for clarity.

using u8 = unsigned char;
using u32 = uint32_t;
using u64 = uint64_t;

// Rotate-right helper
static inline u32 R(u32 x, u32 n) { return (x >> n) | (x << (32 - n)); }

// SHA-256 round constants
static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Hash state and working buffer
struct Ctx {
  u32   h[8];   // current hash
  u64   bits;   // total bits processed
  u8    buf[64];// partial block buffer
  size_t len;   // bytes currently in buf
};

// Initialize state per SHA-256 spec
static void init(Ctx& c) {
  c.h[0] = 0x6a09e667; c.h[1] = 0xbb67ae85; c.h[2] = 0x3c6ef372; c.h[3] = 0xa54ff53a;
  c.h[4] = 0x510e527f; c.h[5] = 0x9b05688c; c.h[6] = 0x1f83d9ab; c.h[7] = 0x5be0cd19;
  c.bits = 0;
  c.len  = 0;
}

// Process a single 512-bit block
static void transform(Ctx& c, const u8* m) {
  u32 w[64];

  // Load 16 words (big-endian) from the block
  for (int i = 0; i < 16; ++i) {
    w[i] = (m[i * 4] << 24) | (m[i * 4 + 1] << 16) | (m[i * 4 + 2] << 8) | m[i * 4 + 3];
  }

  // Extend to 64 words
  for (int i = 16; i < 64; ++i) {
    u32 s0 = R(w[i - 15], 7) ^ R(w[i - 15], 18) ^ (w[i - 15] >> 3);
    u32 s1 = R(w[i - 2], 17) ^ R(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  // Working variables (A..H)
  u32 A = c.h[0], B = c.h[1], C = c.h[2], D = c.h[3];
  u32 E = c.h[4], F = c.h[5], G = c.h[6], H = c.h[7];

  // 64 rounds
  for (int i = 0; i < 64; ++i) {
    u32 S1    = R(E, 6) ^ R(E, 11) ^ R(E, 25);
    u32 ch    = (E & F) ^ (~E & G);
    u32 temp1 = H + S1 + ch + K[i] + w[i];

    u32 S0    = R(A, 2) ^ R(A, 13) ^ R(A, 22);
    u32 maj   = (A & B) ^ (A & C) ^ (B & C);
    u32 temp2 = S0 + maj;

    H = G; G = F; F = E; E = D + temp1;
    D = C; C = B; B = A; A = temp1 + temp2;
  }

  // Add back into the state
  c.h[0] += A; c.h[1] += B; c.h[2] += C; c.h[3] += D;
  c.h[4] += E; c.h[5] += F; c.h[6] += G; c.h[7] += H;
}

// Feed arbitrary data into the hasher
static void update(Ctx& c, const void* data, size_t n) {
  const u8* p = static_cast<const u8*>(data);
  c.bits += static_cast<u64>(n) * 8;

  // Fill the block buffer and transform whenever we hit 64 bytes
  while (n--) {
    c.buf[c.len++] = *p++;
    if (c.len == 64) { transform(c, c.buf); c.len = 0; }
  }
}

// Finalize: pad, length-encode, transform last block(s), output digest
static void final(Ctx& c, u8 out[32]) {
  size_t i = c.len;
  c.buf[i++] = 0x80;             // append 1-bit then zero pad

  if (i > 56) {                  // not enough space for length? flush this block
    while (i < 64) c.buf[i++] = 0;
    transform(c, c.buf);
    i = 0;
  }
  while (i < 56) c.buf[i++] = 0; // pad zeros until 56

  // Append big-endian 64-bit length (bits processed)
  u64 b = c.bits;
  for (int j = 7; j >= 0; --j) c.buf[i++] = static_cast<u8>((b >> (j * 8)) & 0xff);

  transform(c, c.buf);

  // Produce 32-byte digest (big-endian words)
  for (int j = 0; j < 8; ++j) {
    out[j * 4 + 0] = (c.h[j] >> 24) & 0xff;
    out[j * 4 + 1] = (c.h[j] >> 16) & 0xff;
    out[j * 4 + 2] = (c.h[j] >> 8) & 0xff;
    out[j * 4 + 3] = (c.h[j]) & 0xff;
  }
}

// Convert digest bytes to lowercase hex string
static std::string to_hex(const u8 digest[32]) {
  std::ostringstream s;
  s << std::hex << std::setfill('0');
  for (int i = 0; i < 32; ++i) s << std::setw(2) << static_cast<int>(digest[i]);
  return s.str();
}

// Convenience: compute file SHA-256 by streaming in chunks
static std::string file_sha256(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  Ctx c; init(c);

  std::vector<char> buf(8192);
  while (in.good()) {
    in.read(buf.data(), buf.size());
    std::streamsize g = in.gcount();
    if (g > 0) update(c, buf.data(), static_cast<size_t>(g));
  }

  u8 out[32]; final(c, out);
  return to_hex(out);
}
}  // namespace tinysha256

// ---- Small utilities and option parsing ------------------------------------

// CLI options we support; defaults align with the stub behavior
struct Options {
  std::string in_path;                                 // required
  std::string out_path;                                // required
  std::string model       = "llama3:instruct";         // logged only
  std::string temperature = "0.2";                     // logged only
  std::string seed        = "42";                      // logged only
  std::string manifest    = "out/assets/assets.manifest.json"; // where we write the manifest
};

// Print a compact usage summary to the provided stream
static void print_usage(std::ostream& os) {
  os << "Usage:\n"
        "  sentinel-llm --in INPUT.yaml --out OUTPUT.yaml "
        "[--model NAME] [--max-new N] [--temperature T] [--seed S] [--manifest PATH]\n";
}

// True if we can open the file for reading
static bool file_exists(const std::string& p) {
  std::ifstream f(p);
  return f.good();
}

// Overwrite-copy src → dst creating parent directories as needed
static bool copy_file(const std::string& src, const std::string& dst) {
  std::error_code ec;
  std::filesystem::create_directories(std::filesystem::path(dst).parent_path(), ec);
  std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
  return !ec;
}

// Write a small JSON manifest containing the augmented file path and its SHA-256
static void write_manifest(const std::string& aug_path, const std::string& manifest_path) {
  std::filesystem::create_directories(std::filesystem::path(manifest_path).parent_path());
  const std::string sha = tinysha256::file_sha256(aug_path);

  std::ofstream out(manifest_path, std::ios::binary);
  out << "{\n"
         "  \"files\": [\n"
         "    { \"path\": \"" << aug_path << "\", \"sha256\": \"" << sha << "\" }\n"
         "  ]\n"
         "}\n";
}

// Parse argv[] into Options; returns std::nullopt on bad/missing args
static std::optional<Options> parse_args(int argc, char** argv) {
  Options opt;

  for (int i = 1; i < argc; ++i) {
    const std::string k = argv[i];

    // Helper to read the next token as a value
    auto need = [&](std::string& dst) -> bool {
      if (i + 1 >= argc) return false;
      dst = argv[++i];
      return true;
    };

    if (k == "--in") {
      if (!need(opt.in_path)) return std::nullopt;
    } else if (k == "--out") {
      if (!need(opt.out_path)) return std::nullopt;
    } else if (k == "--model") {
      if (!need(opt.model)) return std::nullopt;
    } else if (k == "--max-new") {
      // Accept but ignore (stub doesn’t generate tokens)
      if (i + 1 < argc) ++i;
    } else if (k == "--temperature") {
      if (!need(opt.temperature)) return std::nullopt;
    } else if (k == "--seed") {
      if (!need(opt.seed)) return std::nullopt;
    } else if (k == "--manifest") {
      if (!need(opt.manifest)) return std::nullopt;
    } else {
      std::cerr << "Unknown argument: " << k << "\n";
      return std::nullopt;
    }
  }

  // Require both input and output paths
  if (opt.in_path.empty() || opt.out_path.empty()) return std::nullopt;
  return opt;
}

// ---- Main program -----------------------------------------------------------

int main(int argc, char** argv) {
  // 1) Parse arguments
  const auto opts = parse_args(argc, argv);
  if (!opts) {
    print_usage(std::cerr);
    return 2; // standard “command line usage error”
  }

  // 2) Ensure input exists
  if (!file_exists(opts->in_path)) {
    std::cerr << "Error: input file not found: " << opts->in_path << "\n";
    return 2;
  }

  // 3) Stub “LLM step”: copy baseline → augmented, and log parameters
  std::cerr << "[sentinel-llm] Ollama not detected; copying baseline → augmented "
               "(deterministic fallback). "
            << "model=" << opts->model
            << " temperature=" << opts->temperature
            << " seed=" << opts->seed << "\n";

  if (!copy_file(opts->in_path, opts->out_path)) {
    std::cerr << "Error: failed to write " << opts->out_path << "\n";
    return 2;
  }

  // 4) Emit manifest with SHA-256 of the augmented file (for integrity checks)
  write_manifest(opts->out_path, opts->manifest);

  // 5) Friendly success message with exact output locations
  std::cout << "Wrote " << opts->out_path
            << " and " << opts->manifest << "\n";

  return 0;
}
