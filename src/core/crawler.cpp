/**
 * @file crawler.cpp
 * @brief Web crawler using gumbo and http_client
 */

#include "crawler.h"
#include <gumbo.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <algorithm>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <chrono>
#include <iomanip>
#include <vector>
#include <string>
#include <utility>
#include <sstream>

struct Form {
    std::string action;
    std::string method;
    std::vector<std::pair<std::string, std::string>> inputs;
};

/// Get currrent timestamp in ISO8601 format.
static std::string current_utc_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream ss;
    ss << std::put_time(&tm,"%Y-%m-%dT%H:%M:%S") << '.';
    ss << std::setw(3) << std::setfill('0') << ms.count() << "Z";
    return ss.str();
}

/// Hash string using sha256.
static std::string sha256_hex(const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    ss << "sha256:";
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; i++) {
        ss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return ss.str();
}

/// Convert string copy to lowercase using lambda on each character.
static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

// Helper function to decode URL
static std::string url_decode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int val = 0;
            std::istringstream iss(str.substr(i + 1, 2));
            if (iss >> std::hex >> val)
                result.push_back(static_cast<char>(val));
            i += 2;
        } else if (str[i] == '+') {
            result.push_back(' ');
        } else {
            result.push_back(str[i]);
        }
    }
    return result;
}

// Helper function to parse a url for query params
std::vector<std::pair<std::string, std::string>> parse_query(const std::string& url) {
    std::vector<std::pair<std::string, std::string>> params;
    size_t qpos = url.find('?');
    if (qpos == std::string::npos || qpos + 1 >= url.size())
        return params;

    std::string query = url.substr(qpos + 1);
    size_t start = 0;
    while (start < query.size()) {
        size_t amp = query.find('&', start);
        std::string token = (amp == std::string::npos) ? 
            query.substr(start) :
            query.substr(start, amp - start);

        size_t eq = token.find('=');
        std::string key = url_decode(eq == std::string::npos ? token : token.substr(0, eq));
        std::string val = (eq == std::string::npos) ? "" : url_decode(token.substr(eq + 1));

        if (!key.empty())
            params.emplace_back(key, val);

        if (amp == std::string::npos) break;
        start = amp + 1;
    }
    return params;
}

// Helper function to check if URL path segment consists of digits
bool is_numeric_segment(const std::string& segment) {
    if (segment.empty()) return false;
    for (char c : segment) {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }
    return true;
}

/// Init Crawler with HttpClient reference and config options.
Crawler::Crawler(const HttpClient& client, const Options& opts)
    : client_(client), opts_(opts) {}

/// Add a new starting URL to seed list.
void Crawler::add_seed(const std::string& url) {
    seeds_.push_back(url);
}

/// Read an OpenAPI definition.
bool Crawler::load_openapi_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return false;
    try {
        in >> openapi_;
        if (openapi_.contains("paths")) {
            for (auto& el : openapi_["paths"].items()) {
                std::string p = el.key();
            }
        }
    } catch (...) {
        return false;
    }
    return true;
}

/// Assemble full URL from components.
static std::string join_url( const std::string& scheme, 
    const std::string& hostport, 
    const std::string& resource_path 
) {
    std::string out = scheme + "://" + hostport;
    if (!resource_path.empty() && resource_path.front() != '/') out += '/';
    out += resource_path;
    return out;
}

/// Extract origin from a full URL.
std::string Crawler::origin_of(const std::string& url) const {
    CURLU* h = curl_url();
    if (!h) return {};
    CURLUcode rc = curl_url_set(h, CURLUPART_URL, url.c_str(), 0);
    if (rc != CURLUE_OK) { 
        curl_url_cleanup(h); 
        return {}; 
    }
    char* scheme = nullptr;
    char* host = nullptr;
    char* port = nullptr;
    curl_url_get(h, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(h, CURLUPART_HOST, &host, 0);
    curl_url_get(h, CURLUPART_PORT, &port, 0);
    std::string origin;
    if (scheme && host) {
        std::string hostport(host);
        if (port) {
            hostport += ":";
            hostport += port;
        }
        origin = join_url(scheme, hostport, "");
    }
    if (scheme) curl_free(scheme);
    if (host) curl_free(host);
    if (port) curl_free(port);
    curl_url_cleanup(h);
    return origin;
}

/// Resolve href into an absolute URL using base as reference.
std::string Crawler::normalize_url(const std::string& base, const std::string& href) const {
    if (href.empty()) return {};
    
    // Detect absolute URLs (http://, https://, ...) 
    static const std::regex abs_re(R"(^[a-zA-Z][a-zA-Z0-9+\-.]*://)");
    if (std::regex_search(href, abs_re)) {
        // Remove fragment
        const auto pos = href.find('#');
        return (pos != std::string::npos) ? href.substr(0, pos) : href;
    }

    if (href[0] == '/') {
        std::string base_fixed = base;
        if (base_fixed.back() == '/')
            base_fixed.pop_back();
        return base_fixed + href;
    }

    std::string base_fixed = base;
    if (base_fixed.back() != '/')
        base_fixed += '/';
    return base_fixed + href;
}

/// Populate form vector via recursive traversal of Gumbo HTML DOM tree.
static void extract_forms(
    GumboNode* node, 
    const std::string& base, 
    std::vector<Form>& out_forms
) {
    if (node->type != GUMBO_NODE_ELEMENT) return;
    GumboAttribute* attr;
    if (node->v.element.tag == GUMBO_TAG_FORM) {
        // Extract action and method
        Form form;
        attr = gumbo_get_attribute(&node->v.element.attributes, "action");
        form.action = attr ? std::string(attr->value) : "";
        attr = gumbo_get_attribute(&node->v.element.attributes, "method");
        form.method = attr ? to_lower(attr->value) : "get";

        // Begin iterative DFS
        std::vector<GumboNode*> stack;
        stack.push_back(node);
        while (!stack.empty()) {
            GumboNode* n = stack.back();
            stack.pop_back();
            if (n->type != GUMBO_NODE_ELEMENT) continue;
            if (
                n->v.element.tag == GUMBO_TAG_INPUT    || 
                n->v.element.tag == GUMBO_TAG_TEXTAREA || 
                n->v.element.tag == GUMBO_TAG_SELECT
            ) {
                // Ignore nameless inputs
                GumboAttribute* name_attr = gumbo_get_attribute(&n->v.element.attributes, "name");
                if (name_attr) {
                    std::string name = name_attr->value;
                    std::string value;
                    GumboAttribute* val_attr = gumbo_get_attribute(
                        &n->v.element.attributes, 
                        "value"
                    );
                    if (val_attr) {
                        value = val_attr->value;
                    }
                    form.inputs.emplace_back(name, value);
                }
            }
            // Add child nodes of current element to DFS stack
            GumboVector* children = &n->v.element.children;
            for (unsigned int i = 0; i < children->length; i++) {
                GumboNode* child = static_cast<GumboNode*>(children->data[i]);
                if (child) {
                    stack.push_back(child);
                }
            }
        }
        out_forms.push_back(std::move(form));
    }
    
    // Recurse on non-form children
    GumboVector* children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; i++) {
        GumboNode* child = static_cast<GumboNode*>(children->data[i]);
        if (child && child-> type == GUMBO_NODE_ELEMENT) {
            extract_forms(child, base, out_forms);
        }
    }
}

/// Parse HTML document and extract <a> links and <form> elements.
void Crawler::parse_html(
    const std::string& base_url, 
    const std::string& body, 
    std::set<std::string>& out_links,
    std::vector<Form>& out_forms
) const {
    GumboOutput* output = gumbo_parse(body.c_str());
    if (!output) return;

    // Begin iterative DFS
    std::vector<GumboNode*> stack;
    stack.push_back(output->root);
    while (!stack.empty()) {
        GumboNode* node = stack.back();
        stack.pop_back();
        if (node->type != GUMBO_NODE_ELEMENT) continue;

        // Only looking for a tags or form elements
        if (node->v.element.tag == GUMBO_TAG_A) {
            GumboAttribute* href = gumbo_get_attribute(&node->v.element.attributes, "href");
            if (href && href->value && href->value[0] != '#') {
                // Skip fragment-only links
                std::string hrefs = href->value;
                std::string norm = normalize_url(base_url, hrefs);
                if (!norm.empty()) {
                    out_links.insert(norm);
                }
            }
        } else if (node->v.element.tag == GUMBO_TAG_FORM) {
            extract_forms(node, base_url, out_forms);
        }

        // Push child nodes onyo stack
        GumboVector* children = &node->v.element.children;
        for (unsigned int i = 0; i < children->length; i++) {
            GumboNode* child = static_cast<GumboNode*>(children->data[i]);
            if (child) {
                stack.push_back(child);
            }
        }
    }

    gumbo_destroy_output(&kGumboDefaultOptions, output);
    
    // Every form action should be an absolute URL
    for (auto& f : out_forms) {
        if (!f.action.empty()) {
            f.action = normalize_url(base_url, f.action);
        } else {
            // Default to page URL
            f.action = base_url;
        }
    }
}

/// Determine if crawling a given path on a site is allowed (check robots.txt).
bool Crawler::robots_allows(const std::string& origin, const std::string& path) const {
    if (!opts_.respect_robots) return true;

    // Fetch origin + /robots.txt and parse Disallow lines
    HttpRequest r;
    r.method = "GET";
    r.url = origin + "/robots.txt";
    HttpResponse resp;
    if (!client_.perform(r, resp)) {
        // Assume robots allowed
        return true;
    }
    if (resp.status >= 400) return true;

    std::istringstream ss(resp.body);
    std::string line;
    std::vector<std::string> disallows;
    while (std::getline(ss, line)) {
        // Trim CRLF
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }
        std::string lower = to_lower(line);
        if (lower.rfind("disallow:", 0) == 0) {
            std::string p = line.substr(9);

            // Trim whitespace
            size_t start = 0;
            while (start < p.size() && isspace((unsigned char)p[start])) 
                start++;
            size_t end = p.size();
            while (end > start && isspace((unsigned char)p[end - 1])) 
                end--;

            // Store disallowed path in vector
            std::string val = p.substr(start, end - start);
            if (!val.empty()) {
                disallows.push_back(val);
            }
        }
    }
    for (const auto& d : disallows) {
        if (d == "/") {
            // Site wide disallow
            return false;
        }
        if (!d.empty() && path.rfind(d, 0) == 0) {
            // Path prefix match
            return false;
        }
    }
    return true;
}

/// Perform web crawl process starting from seeds_.
std::vector<CrawlResult> Crawler::run() {
    std::vector<CrawlResult> results;
    if (seeds_.empty()) {
        return results;
    }

    // Queue of (URL, depth) pairs for recursion depth tracking
    std::vector<std::pair<std::string, int>> q;
    for (auto &s : seeds_) {
        q.emplace_back(s, 0);
    }

    // Begin BFS
    size_t i = 0;
    while (i < q.size()) {
        auto [url, depth] = q[i++];
        if (visited_.count(url)) {
            continue;
        }
        visited_.insert(url);

        if (url.find("robots.txt") != std::string::npos ||
            url.find("sitemap.xml") != std::string::npos) {
            continue;
        }

        // Prevent leaving target domain
        std::string base_origin = origin_of(seeds_[0]);
        std::string current = origin_of(url);
        if (current.empty() || base_origin.empty() || current != base_origin) {
            continue;
        }

        // Extract path component and skip if robots disallowed
        CURLU* u = curl_url();
        std::string path = "/";
        if (u) {
            if (curl_url_set(u, CURLUPART_URL, url.c_str(), 0) == CURLUE_OK) {
                char* p = nullptr;
                if (curl_url_get(u, CURLUPART_PATH, &p, 0) == CURLUE_OK) {
                    path = p ? p : "/";
                    curl_free(p);
                }
            }
            curl_url_cleanup(u);
        }
        if (opts_.respect_robots) {
            std::string origin = origin_of(url);
            if (!robots_allows(origin, path)) continue;
        }

        HttpRequest req;
        req.method = "GET";
        req.url = url;
        req.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        HttpResponse resp;
        client_.perform(req, resp);

        CrawlResult cr;
        cr.url = url;
        cr.method = "GET";
        cr.headers = std::move(resp.headers);
        cr.source = resp.body;
        cr.discovery_path = {url};
        cr.timestamp = current_utc_timestamp();
        cr.hash = sha256_hex(url);

        if (resp.status >= 200 && resp.status < 400 && !resp.body.empty()) {
            auto query_params = parse_query(url);
            if (!query_params.empty()) {
                CrawlResult cr_q = cr;
                cr_q.params = std::move(query_params);
                cr_q.source = resp.body;
                results.push_back(std::move(cr_q));
            } else {
                results.push_back(std::move(cr));
            }

            std::set<std::string> links;
            std::vector<Form> forms;
            parse_html(url, resp.body, links, forms);

            for (const auto& f : forms) {
                CrawlResult cr1;
                std::string action_url = f.action.empty() ? url : f.action;
                cr1.url = action_url;
                cr1.method = f.method.empty() ? "POST" : f.method;
                cr1.params = std::move(f.inputs);
                cr1.source = "form";
                cr1.discovery_path = {url, action_url};
                cr1.timestamp = current_utc_timestamp();
                cr1.hash = sha256_hex(action_url);
                results.push_back(std::move(cr1));
            }

            if (depth < opts_.max_depth) {
                for (const auto& link : links) {
                    // Add links found to queue if not visited and if same-origin
                    if (visited_.count(link)) {
                        continue;
                    }
                    std::string link_origin = origin_of(link);
                    if (link_origin == base_origin) {
                        q.emplace_back(link, depth + 1);
                    }
                }

                if (!openapi_.is_null() && openapi_.contains("paths") && depth == 0) {
                    for (auto& el : openapi_["paths"].items()) {
                        std::string p = el.key();
                        std::string candidate = base_origin + p;
                        if (!visited_.count(candidate)) {
                            q.emplace_back(candidate, depth + 1);
                        }
                    }
                }
            }
        }
    }
    return results;
}
