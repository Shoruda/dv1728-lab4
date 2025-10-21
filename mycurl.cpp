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
#include <cctype>

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

static int get_status_code(const std::string& response) {
    // First line should be like: "HTTP/1.1 200 OK"
    auto first_line_end = response.find("\r\n");
    if (first_line_end == std::string::npos) return -1;
    
    std::string status_line = response.substr(0, first_line_end);
    
    // Find first space, then parse next number
    auto first_space = status_line.find(' ');
    if (first_space == std::string::npos) return -1;
    
    auto second_space = status_line.find(' ', first_space + 1);
    if (second_space == std::string::npos) return -1;
    
    std::string code_str = status_line.substr(first_space + 1, second_space - first_space - 1);
    try {
        return std::stoi(code_str);
    } catch (...) {
        return -1;
    }
}

bool handle_http(int sock, const Url& url, std::string& body, std::map<std::string, std::string>& headers, int& status_code) 
{
    std::ostringstream req;
    req << "GET " << url.path << " HTTP/1.1\r\n";
    req << "Host: " << url.host << "\r\n";
    req << "User-Agent: mycurl/1.0\r\n";
    req << "Connection: close\r\n\r\n";

    std::string request = req.str();
    if (send(sock, request.c_str(), request.size(), 0) < 0) 
    {
        std::cerr << "Send failed: " << strerror(errno) << "\n";
        return false;
    }

    std::string resp;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0)
        resp.append(buf, n);

    if (resp.empty()) 
    {
        std::cerr << "Empty HTTP response.\n";
        return false;
    }

    status_code = get_status_code(resp);

    auto pos = resp.find("\r\n\r\n");
    if (pos == std::string::npos) 
    {
        std::cerr << "Malformed HTTP response (no header-body split)\n";
        return false;
    }

    std::string header_str = resp.substr(0, pos);
    body = resp.substr(pos + 4);

    std::istringstream hdr_stream(header_str);
    std::string line;
    bool first = true;
    while (std::getline(hdr_stream, line)) 
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) 
        {
            std::cout << "HTTP Response: " << line << "\n";
            first = false;
        } 
        else 
        {
            auto colon = line.find(':');
            if (colon != std::string::npos) 
            {
                std::string key = line.substr(0, colon);
                std::string value = line.substr(colon + 1);
                key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
                value.erase(0, value.find_first_not_of(" \t"));
                to_lower_inplace(key);
                headers[key] = value;
            }
        }
    }

    return true;
}

bool handle_https(int sock, const Url& url, std::string& body, std::map<std::string, std::string>& headers, int& status_code) 
{
    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) return false;

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, url.host.c_str());

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) 
    {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        std::cout << "SSL certificate subject: " << subj << "\n";
        std::cout << "SSL certificate issuer: " << issuer << "\n";
        OPENSSL_free(subj);
        OPENSSL_free(issuer);
        X509_free(cert);
    }

    std::ostringstream req;
    req << "GET " << url.path << " HTTP/1.1\r\n";
    req << "Host: " << url.host << "\r\n";
    req << "User-Agent: mycurl/1.0\r\n";
    req << "Connection: close\r\n\r\n";
    std::string req_str = req.str();

    SSL_write(ssl, req_str.c_str(), req_str.size());

    char buf[4096];
    std::string resp;
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0)
        resp.append(buf, n);

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    status_code = get_status_code(resp);

    auto pos = resp.find("\r\n\r\n");
    if (pos != std::string::npos)
    {
        std::string header_str = resp.substr(0, pos);
        body = resp.substr(pos + 4);
        std::istringstream hdr_stream(header_str);
        std::string line;
        bool first = true;
        while (std::getline(hdr_stream, line)) 
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (first) 
            {
                std::cout << "HTTPS Response: " << line << "\n";
                first = false;
            } 
            else 
            {
                auto colon = line.find(':');
                if (colon != std::string::npos) 
                {
                    std::string key = line.substr(0, colon);
                    std::string value = line.substr(colon + 1);
                    key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
                    value.erase(0, value.find_first_not_of(" \t"));
                    to_lower_inplace(key);
                    headers[key] = value;
                }

            }
        }
    }       
    else
        body = resp;

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
    
    /* do magic :3 */

    while (redirects <= max_redirects) 
    {
        if (url.host.empty()) 
        {
            std::fprintf(stdout, "error Empty host\n");
            return 1;
        }

        if (isdigit(url.host[0]) || url.host[0] == '[') 
        {
            std::fprintf(stdout, "error IP addresses not allowed, use hostname instead\n");
            return 1;
        }

        int sockfd;
        struct addrinfo hints{}, *res;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &res);
        if (status != 0) 
        {
            std::fprintf(stdout, "error getaddrinfo: %s\n", gai_strerror(status));
            exit(1);
        }

        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) 
        {
            std::fprintf(stdout, "error socket creation failed: %s\n", strerror(errno));
            freeaddrinfo(res);
            exit(1);
        }

        if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) 
        {
            std::fprintf(stdout, "error connect failed: %s\n", strerror(errno));
            freeaddrinfo(res);
            close(sockfd);
            exit(1);
        }

        freeaddrinfo(res);
        std::printf("Connected to %s:%s\n", url.host.c_str(), url.port.c_str());

        std::map<std::string, std::string> headers;
        std::string body;
        int status_code = 0;
        bool ok = false;

        if (url.scheme == "http") 
        {
            ok = handle_http(sockfd, url, body, headers, status_code);
        } 
        else if (url.scheme == "https") 
        {
            ok = handle_https(sockfd, url, body, headers, status_code);
        }

        close(sockfd);

        if (!ok) 
        {
            std::cerr << "Request failed\n";
            return EXIT_FAILURE;
        }

        if (status_code >= 300 && status_code < 400) 
        {
            auto loc_it = headers.find("location");
            if (loc_it == headers.end()) 
            {
                std::cerr << "Redirect without Location header\n";
                return EXIT_FAILURE;
            }

            std::string new_location = loc_it->second;
            std::cout << "redirecting" << "\n";
            std::cout << "Redirect " << redirects + 1 << ": " << status_code 
                    << " -> " << new_location << "\n";

            Url new_url;
            std::string parse_error;
            
            if (new_location[0] == '/') 
            {
                new_url = url;
                new_url.path = new_location;
            } 
            else if (new_location.find("://") == std::string::npos) 
            {
                new_url = url;
                new_url.path = new_location;
            } 
            else 
            {
                if (!parse_url(new_location, new_url, parse_error)) 
                {
                    std::fprintf(stdout, "ERROR parsing redirect URL: %s\n", parse_error.c_str());
                    return EXIT_FAILURE;
                }
            }

            url = new_url;
            redirects++;
            continue;
        }

        if (!output_file.empty()) 
        {
            if (output_file == "-") 
            {
                std::cout << body;
            } 
            else 
            {
                std::ofstream outfile(output_file, std::ios::binary);
                if (!outfile.is_open()) 
                {
                    std::cerr << "Error: could not open file for writing: " << output_file << "\n";
                    return EXIT_FAILURE;
                }
                outfile.write(body.data(), body.size());
                outfile.close();
                std::cout << "Saved " << body.size() << " bytes to '" << output_file << "'\n";
            }
        }   
        
        int resp_body_size = body.size();
        auto t2 = clock::now();
        std::chrono::duration<double> diff = t2 - t1; //seconds
        std::cout << std::fixed << std::setprecision(6);
        std::cout << now_local_yy_mm_dd_hh_mm_ss() << " " << url_str << " " 
                << resp_body_size << " [bytes] " << diff.count()
                << " [s] " << (8*resp_body_size/diff.count())/1e6 << " [Mbps]\n";
        
        break;
    }

    if (redirects > max_redirects) 
    {
        std::fprintf(stdout, "error too many redirects\n");
        return 1;
    }
}