#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <memory>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
// === Cache: new headers
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

// Return current local time formatted as "yy-mm-dd hh:mm:ss"
static std::string now_local_yy_mm_dd_hh_mm_ss()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &t); // thread-safe on Windows
#else
    local_tm = *std::localtime(&t); // use localtime_r if available
    // Alternatively (POSIX): localtime_r(&t, &local_tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

struct Url {
    std::string scheme; // "http" or "https"
    std::string host;   // hostname or [IPv6]
    std::string port;   // "80" / "443" / or explicit
    std::string path;   // always starts with '/', at least "/"
};

struct ChunkReadStats {
    size_t socket_bytes = 0;   // total bytes read from socket during chunked phase
    size_t body_bytes = 0;     // total bytes appended to 'acc' (payload only)
    size_t chunks = 0;         // number of chunks successfully appended
    size_t last_chunk_size = 0;
    bool eof_in_size_line = false;
    bool eof_in_chunk_data = false;
    bool missing_crlf_after_chunk = false;
};


static void to_lower_inplace(std::string &s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
}


static bool is_default_port(const Url& u) {
    if (u.scheme == "https") return (u.port == "443");
    if (u.scheme == "http")  return (u.port == "80");
    return false;
}

static bool validate_scheme(const Url& u){
    if (u.scheme == "https") return true;
    if (u.scheme == "http")  return true;
    return false;
}

// Simple URL parser supporting IPv6 literals in brackets, e.g., https://[2001:db8::1]:8443/path
static bool parse_url(const std::string& input, Url& out, std::string& error) {
    auto pos = input.find("://");
    if (pos == std::string::npos) {
        error = "Invalid URL: missing '://'";
        return false;
    }
    out.scheme = input.substr(0, pos);
    to_lower_inplace(out.scheme);

    if (!validate_scheme(out)){
        return false;
    }
    
    size_t host_start = pos + 3;
    size_t path_start = std::string::npos;
    size_t host_end   = std::string::npos;

    // IPv6 literal?
    if (host_start < input.size() && input[host_start] == '[') {
        size_t rb = input.find(']', host_start);
        if (rb == std::string::npos) {
            error = "Invalid URL: missing closing ']' for IPv6 address";
            return false;
        }
        out.host = input.substr(host_start, rb - host_start + 1); // include [ ]
        if (rb + 1 < input.size() && input[rb + 1] == ':') {
            // port after IPv6
            size_t port_begin = rb + 2;
            path_start = input.find('/', port_begin);
            if (path_start == std::string::npos) {
                out.port = input.substr(port_begin);
                out.path = "/";
                goto finalize_defaults;
            } else {
                out.port = input.substr(port_begin, path_start - port_begin);
            }
        } else {
            // no port, next '/' starts path
            path_start = input.find('/', rb + 1);
        }
        host_end = (path_start == std::string::npos) ? input.size() : path_start; // host already set
    } else {
        // IPv4 or name: host[:port][/path]
        path_start = input.find('/', host_start);
        host_end   = (path_start == std::string::npos) ? input.size() : path_start;
        size_t colon = input.find(':', host_start);
        if (colon != std::string::npos && colon < host_end) {
            out.host = input.substr(host_start, colon - host_start);
            out.port = input.substr(colon + 1, host_end - (colon + 1));
        } else {
            out.host = input.substr(host_start, host_end - host_start);
        }
    }

    if (out.host.empty()) {
        error = "Invalid URL: empty host";
        return false;
    }

    if (path_start == std::string::npos) {
        out.path = "/";
    } else {
        out.path = input.substr(path_start);
        if (out.path.empty()) out.path = "/";
    }

finalize_defaults:
    // Default port by scheme
    if (out.port.empty()) {
        if (out.scheme == "https") out.port = "443";
        else if (out.scheme == "http") out.port = "80";
        else {
            error = "Unsupported scheme: " + out.scheme;
            return false;
        }
    }

    // Validate port
    if (!std::all_of(out.port.begin(), out.port.end(), ::isdigit)) {
        error = "Invalid port: " + out.port;
        return false;
    }

    return true;
}


int main(int argc, char* argv[]) {
    bool cache_enabled = false;
    std::string url_str;
    std::string output_file;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--cache") cache_enabled = true;
	else if (a == "-o" || a == "--output") {
            if (i + 1 >= argc) {
	      std::fprintf(stdout, "-o/--output requires a filename (or - for stdout)\n");
	      std::fprintf(stdout, "Usage: %s [--cache] [-o <file|->] url\n", argv[0]);
	      return EXIT_FAILURE;
            }
            output_file = argv[++i];
        }
        else if (!a.empty() && a[0] == '-') {
            std::fprintf(stdout, "Error Unknown option: %s\n", a.c_str());
            std::fprintf(stdout, "Usage: %s [--cache] -o <file>|-> url\n", argv[0]);
            return EXIT_FAILURE;
        } else {
            url_str = a;
        }
    }
    if (url_str.empty()) {
        std::fprintf(stdout, "Usage: %s [--cache] url\n", argv[0]);
        return EXIT_FAILURE;
    }

    Url url;
    std::string error;
    if (!parse_url(url_str, url, error)) {
        std::fprintf(stdout, "ERROR URL parse error: %s\n", error.c_str());
        return EXIT_FAILURE;
    }

    std::printf("Protocol: %s, Host %s, port = %s, path = %s, ",
                url.scheme.c_str(), url.host.c_str(), url.port.c_str(), url.path.c_str());
    std::printf("Output: %s\n", output_file.c_str());

    const int max_redirects = 10;
    int redirects = 0;
    using clock = std::chrono::steady_clock;

    auto t1 = clock::now();
    
    /* do stuff */
    int resp_body_size=0xFACCE;
    

    auto t2 = clock::now();
    std::chrono::duration<double> diff = t2 - t1; // seconds
    std::cout << std::fixed << std::setprecision(6);
    std::cout << now_local_yy_mm_dd_hh_mm_ss() << " " << url_str << " " << resp_body_size << " [bytes] " << diff.count()
              << " [s] " << (8*resp_body_size/diff.count())/1e6 << " [Mbps]\n";



    
    return EXIT_SUCCESS;
}
