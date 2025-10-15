#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdlib>

struct Endpoint {
  std::string method, url, name;
};
struct Finding {
  std::string vuln_type, target, response_snippet;
};

static std::string slurp(const std::string& path) {
  std::ifstream in(path);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

static bool file_exists(const std::string& p) {
  std::ifstream f(p); return f.good();
}

static std::string extract_field(const std::string& line, const std::string& key) {
  // Very small JSON field extractor for "key":"value" on a single line.
  // Works with our fixtures; not a general JSON parser.
  std::regex rx("\"" + key + "\"\\s*:\\s*\"(.*?)\"");
  std::smatch m;
  if (std::regex_search(line, m, rx)) return m[1].str();
  return "";
}

static std::vector<Endpoint> read_endpoints_jsonl(const std::string& path) {
  std::vector<Endpoint> out;
  std::ifstream in(path);
  std::string line;
  while (std::getline(in, line)) {
    if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
    Endpoint e;
    e.method = extract_field(line, "method");
    e.url    = extract_field(line, "url");
    e.name   = extract_field(line, "name");
    out.push_back(e);
  }
  return out;
}

static std::vector<Finding> read_findings_jsonl(const std::string& path) {
  std::vector<Finding> out;
  std::ifstream in(path);
  std::string line;
  while (std::getline(in, line)) {
    if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
    Finding f;
    f.vuln_type        = extract_field(line, "vuln_type");
    f.target           = extract_field(line, "target");
    f.response_snippet = extract_field(line, "response_snippet");
    out.push_back(f);
  }
  return out;
}

static double parse_double(const std::string& s, double defv) {
  char* end=nullptr;
  const double v = std::strtod(s.c_str(), &end);
  return (end && end != s.c_str()) ? v : defv;
}

static double parse_yaml_double(const std::string& yaml, const std::string& key, double defv) {
  // Minimal YAML "key: value" float parser for our known keys.
  std::regex rx("\\b" + key + "\\s*:\\s*([0-9]*\\.?[0-9]+)");
  std::smatch m;
  if (std::regex_search(yaml, m, rx)) return parse_double(m[1].str(), defv);
  return defv;
}

static std::string html_escape(const std::string& s) {
  std::string out; out.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&':  out += "&amp;";  break;
      case '<':  out += "&lt;";   break;
      case '>':  out += "&gt;";   break;
      case '"':  out += "&quot;"; break;
      default:   out.push_back(c); break;
    }
  }
  return out;
}

int main(int argc, char** argv) {
  // Args: --policy P --findings F --endpoints E --out O
  std::string policy_path, findings_path, endpoints_path, out_path;
  for (int i=1; i+1<argc; ++i) {
    std::string k = argv[i];
    std::string v = argv[i+1];
    if      (k == std::string("--policy"))    policy_path    = v;
    else if (k == std::string("--findings"))  findings_path  = v;
    else if (k == std::string("--endpoints")) endpoints_path = v;
    else if (k == std::string("--out"))       out_path       = v;
  }
  if (policy_path.empty() || findings_path.empty() || endpoints_path.empty() || out_path.empty()) {
    std::cerr << "Usage: reporter_stub --policy P --findings F --endpoints E --out O\n";
    return 2;
  }
  if (!file_exists(policy_path) || !file_exists(findings_path) || !file_exists(endpoints_path)) {
    std::cerr << "Missing input file(s).\n";
    return 2;
  }

  const std::string policy = slurp(policy_path);
  // Defaults match earlier tasks
  const double block_score = parse_yaml_double(policy, "block_score", 0.75);
  const double w_missing   = parse_yaml_double(policy, "missing_headers", 0.40);
  const double w_cookie    = parse_yaml_double(policy, "cookie_flags",   0.50);

  const auto findings  = read_findings_jsonl(findings_path);
  const auto endpoints = read_endpoints_jsonl(endpoints_path);

  // Compute total risk = sum(weights for each finding)
  double total = 0.0;
  for (const auto& f : findings) {
    if      (f.vuln_type == "missing_headers") total += w_missing;
    else if (f.vuln_type == "cookie_flags")    total += w_cookie;
  }
  if (total > 1.0) total = 1.0;
  const bool block = (total > block_score);

  // Build HTML
  std::ostringstream html;
  html << "<!doctype html><html><head><meta charset='utf-8'>"
       << "<title>Sentinel Report (Fixture E2E)</title>"
       << "<style>"
          "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
          "max-width:1000px;margin:2rem auto;padding:0 1rem}"
          "table{border-collapse:collapse;width:100%}"
          "th,td{border:1px solid #ddd;padding:.5rem;vertical-align:top}"
          "th{background:#f5f5f5;text-align:left}"
          ".badge{display:inline-block;padding:.25rem .5rem;border-radius:.5rem;font-weight:600}"
          ".badge-pass{background:#e6ffed;color:#046d1f}"
          ".badge-block{background:#ffecec;color:#8a0303}"
          "code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.9em}"
       << "</style></head><body>\n";
  html << "<h1>Sentinel Report (Fixture E2E)</h1>\n";
  html << "<p><strong>Total Risk:</strong> " << std::fixed << std::setprecision(2) << total
       << " &nbsp; <span class='badge badge-" << (block ? "block" : "pass") << "'>"
       << (block ? "BLOCK" : "PASS") << "</span></p>\n";
  html << "<p><strong>Policy block_score:</strong> " << std::fixed << std::setprecision(2) << block_score << "</p>\n";

  html << "<h2>Endpoints (from fixtures)</h2>\n<table><thead><tr><th>Method</th><th>URL</th><th>Name</th></tr></thead><tbody>\n";
  for (const auto& e : endpoints) {
    html << "<tr><td>" << html_escape(e.method) << "</td><td>" << html_escape(e.url)
         << "</td><td>" << html_escape(e.name) << "</td></tr>\n";
  }
  html << "</tbody></table>\n";

  html << "<h2>Findings (from fixtures)</h2>\n<table><thead><tr><th>Vuln Type</th><th>Target</th><th>Evidence Snippet</th></tr></thead><tbody>\n";
  for (const auto& f : findings) {
    html << "<tr><td>" << html_escape(f.vuln_type) << "</td><td>" << html_escape(f.target)
         << "</td><td><pre>" << html_escape(f.response_snippet) << "</pre></td></tr>\n";
  }
  html << "</tbody></table>\n"
       << "<p style='margin-top:2rem;font-size:.9em;color:#666'>Generated from local fixtures. No network calls.</p>\n"
       << "</body></html>\n";

  // Write out
  std::filesystem::path outp(out_path);
  std::filesystem::create_directories(outp.parent_path());
  std::ofstream out(out_path, std::ios::binary);
  out << html.str();
  out.close();

  std::cout << "Wrote " << out_path << "\n";
  return block ? 1 : 0; // non-zero if policy says BLOCK (so CI can gate)
}
