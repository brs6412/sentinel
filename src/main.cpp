#include "core/http_client.h"
#include <iostream>

int main() {
    HttpClient client;
    HttpRequest req;
    req.url = "https://google.com";

    HttpResponse res;
    if (client.perform(req, res)) {
        std::cout << "Status: " << res.status << "\n";
        std::cout << "Body bytes:\n" << res.body_bytes << "\n";
    } else {
        std::cerr << "Req failed: " << res.error << "\n";
    }

    return 0;
}
