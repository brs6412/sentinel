/**
 * @file discovery.cpp
 * @brief Web crawler using gumbo and http_client
 */

#include "discovery.h"
#include <gumbo.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <algorithm>
#include <curl/curl.h>

using json = nlohmann::json;

/// Convert string copy to lowercase using lambda on each character.
static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

/// Init Discovery with HttpClient reference and config options.
Discovery::Discovery(const HttpClient& client, const Options& opts)
    : client_(client), opts_(opts) {}

/// Add a new starting URL to seed list.
void Discovery::add_seed(const std::string& url) {
    seeds_.push_back(url);
}

/// Read an OpenAPI definition.
bool Discovery::load_openapi_file(const std::string& path) {
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
std::string Discovery::origin_of(const std::string& url) const {
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
std::string Discovery::normalize_url(const std::string& base, const std::string& href) const {
    if (href.empty()) return {};
    
    // Detect absolute URLs (http://, https://, ...) 
    static const std::regex abs_re(R"(^[a-zA-Z][a-zA-Z0-9+\-.]*://)");
    if (std::regex_search(href, abs_re)) {
        // Remove fragment
        const auto pos = href.find('#');
        return (pos != std::string::npos) ? href.substr(0, pos) : href;
    }

    // Init URL handles
    CURLU* base_h = curl_url();
    CURLU* resolved_h = curl_url();
    if (!base_h || !resolved_h) {
        if (base_h) curl_url_cleanup(base_h);
        if (resolved_h) curl_url_cleanup(resolved_h);
        return {};
    }

    // Parse base URL
    if (curl_url_set(base_h, CURLUPART_URL, base.c_str(), 0) != CURLUE_OK) {
        curl_url_cleanup(base_h);
        curl_url_cleanup(resolved_h);
        return {};
    }

    // Resolve href relative to base
    if (curl_url_set(resolved_h, CURLUPART_URL, href.c_str(), CURLU_URLENCODE) != CURLUE_OK) {
        curl_url_cleanup(base_h);
        curl_url_cleanup(resolved_h);
        return {};
    }

    // Combine 
    if (curl_url_set(resolved_h, CURLUPART_URL, href.c_str(), CURLU_URLENCODE) != CURLUE_OK) {
        curl_url_cleanup(base_h);
        curl_url_cleanup(resolved_h);
        return {};
    }

    // Extract final normalized URL
    char* out_url = nullptr;
    if (curl_url_get(resolved_h, CURLUPART_URL, &out_url, 0) != CURLUE_OK) {
        curl_url_cleanup(base_h);
        curl_url_cleanup(resolved_h);
        return {};
    }

    std::string result(out_url);
    curl_free(out_url);

    const auto pos = result.find('#');
    if (pos != std::string::npos) {
        result.resize(pos);
    }

    curl_url_cleanup(base_h);
    curl_url_cleanup(resolved_h);
    return result;
}

/// Populate form vector via recursive traversal of Gumbo HTML DOM tree.
static void extract_forms(
    GumboNode* node, 
    const std::string& base, 
    std::vector<CrawlResult::Form>& out_forms
) {
    if (node->type != GUMBO_NODE_ELEMENT) return;
    GumboAttribute* attr;
    if (node->v.element.tag == GUMBO_TAG_FORM) {
        // Extract action and method
        CrawlResult::Form form;
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
void Discovery::parse_html(
    const std::string& base_url, 
    const std::string& body, 
    std::set<std::string>& out_links,
    std::vector<CrawlResult::Form>& out_forms
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
bool Discovery::robots_allows(const std::string& origin, const std::string& path) const {
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
std::vector<CrawlResult> Discovery::run() {
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
        cr.status = resp.status;

        if (resp.status >= 200 && resp.status < 400 && !resp.body.empty()) {
            parse_html(url, resp.body, cr.links, cr.forms);
            if (depth < opts_.max_depth) {
                for (const auto& link : cr.links) {
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
        results.push_back(std::move(cr));
    }
    return results;
}
