#define _WIN32_WINNT 0x0600
#define NTDDI_VERSION 0x06000000
#define WINVER 0x0600

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <curl/curl.h>

#pragma comment(lib, "ws2_32.lib")

struct Memory {
    char *response;
    size_t size;
};

static size_t store_data(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    struct Memory *mem = (struct Memory *)userp;

    printf("[DEBUG] store_data called: size=%zu, nmemb=%zu, total=%zu\n", size, nmemb, total_size);

    char *ptr = realloc(mem->response, mem->size + total_size + 1);
    if (!ptr) {
        fprintf(stderr, "[ERROR] realloc failed\n");
        return 0;
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), contents, total_size);
    mem->size += total_size;
    mem->response[mem->size] = '\0';

    printf("[DEBUG] stored %zu bytes, total size now %zu\n", total_size, mem->size);

    return total_size;
}

void extract_json_data(const char *json, const char *key, char *out, size_t out_size) {
    char *found = strstr(json, key);
    if (found) {
        found = strchr(found, ':');
        if (found) {
            found++;
            while (*found == ' ' || *found == '"') found++;
            char *end = found;
            while (*end && *end != '"' && *end != ',' && *end != '\n' && *end != '}') end++;
            size_t len = end - found;
            if (len >= out_size) len = out_size - 1;
            strncpy(out, found, len);
            out[len] = '\0';
        }
    } else {
        out[0] = '\0';
    }
}

void print_title_border(const char* title) {
    int border_length = 70;
    int title_length = (int)strlen(title);
    int padding = (border_length - title_length - 2) / 2;

    for (int i = 0; i < border_length; i++) printf("*");
    printf("\n*");
    for (int i = 0; i < padding; i++) printf(" ");
    printf("%s", title);
    for (int i = 0; i < (border_length - title_length - padding - 2); i++) printf(" ");
    printf("*\n");
    for (int i = 0; i < border_length; i++) printf("*");
    printf("\n");
}

char* resolve_hostname(const char* hostname) {
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    printf("[DEBUG] Resolving hostname: %s\n", hostname);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "[ERROR] getaddrinfo error: %s\n", gai_strerrorA(status));
        return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        DWORD ip_len = sizeof(ipstr);
        if (WSAAddressToStringA(p->ai_addr, (DWORD)p->ai_addrlen, NULL, ipstr, &ip_len) == 0) {
            printf("[DEBUG] Resolved to IP: %s\n", ipstr);
            freeaddrinfo(res);
            return _strdup(ipstr);
        }
    }

    freeaddrinfo(res);
    fprintf(stderr, "[ERROR] Could not resolve hostname to IP\n");
    return NULL;
}

void perform_isp_lookup(const char* ip_address) {
    printf("\nPerforming ISP lookup for %s...\n\n", ip_address);

    CURL *curl;
    CURLcode res;
    struct Memory chunk = { .response = NULL, .size = 0 };

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        printf("[ERROR] Failed to initialize curl.\n");
        curl_global_cleanup();
        return;
    }

    char url[128];
    // FORCING HTTP to avoid SSL errors
    snprintf(url, sizeof(url), "http://ipapi.co/%s/json/", ip_address);
    printf("[DEBUG] URL set to: %s\n", url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "isp/1.0");

    // Disable SSL verification since we are using HTTP (and avoid SSL checks)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, store_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "[ERROR] Curl request failed: %s\n", curl_easy_strerror(res));
    } else if (chunk.response && chunk.size > 0) {
        printf("[DEBUG] Curl response received, size: %zu bytes\n", chunk.size);

        char ip[64], version[16], city[64], region[64], region_code[16], country[64];
        char country_code[8], postal[16], latitude[32], longitude[32], timezone[64];
        char utc_offset[16], country_calling_code[16], currency[16], languages[128], asn[32], org[128];

        extract_json_data(chunk.response, "\"ip\"", ip, sizeof(ip));
        extract_json_data(chunk.response, "\"version\"", version, sizeof(version));
        extract_json_data(chunk.response, "\"city\"", city, sizeof(city));
        extract_json_data(chunk.response, "\"region\"", region, sizeof(region));
        extract_json_data(chunk.response, "\"region_code\"", region_code, sizeof(region_code));
        extract_json_data(chunk.response, "\"country_name\"", country, sizeof(country));
        extract_json_data(chunk.response, "\"country_code\"", country_code, sizeof(country_code));
        extract_json_data(chunk.response, "\"postal\"", postal, sizeof(postal));
        extract_json_data(chunk.response, "\"latitude\"", latitude, sizeof(latitude));
        extract_json_data(chunk.response, "\"longitude\"", longitude, sizeof(longitude));
        extract_json_data(chunk.response, "\"timezone\"", timezone, sizeof(timezone));
        extract_json_data(chunk.response, "\"utc_offset\"", utc_offset, sizeof(utc_offset));
        extract_json_data(chunk.response, "\"country_calling_code\"", country_calling_code, sizeof(country_calling_code));
        extract_json_data(chunk.response, "\"currency\"", currency, sizeof(currency));
        extract_json_data(chunk.response, "\"languages\"", languages, sizeof(languages));
        extract_json_data(chunk.response, "\"asn\"", asn, sizeof(asn));
        extract_json_data(chunk.response, "\"org\"", org, sizeof(org));

        printf("IP Address           : %s\n", ip);
        printf("IP Version           : %s\n", version);
        printf("City                 : %s\n", city);
        printf("Region               : %s\n", region);
        printf("Region Code          : %s\n", region_code);
        printf("Country              : %s\n", country);
        printf("Country Code         : %s\n", country_code);
        printf("Postal Code          : %s\n", postal);
        printf("Latitude             : %s\n", latitude);
        printf("Longitude            : %s\n", longitude);
        printf("Timezone             : %s\n", timezone);
        printf("UTC Offset           : %s\n", utc_offset);
        printf("Calling Code         : %s\n", country_calling_code);
        printf("Currency             : %s\n", currency);
        printf("Languages            : %s\n", languages);
        printf("ASN                  : %s\n", asn);
        printf("ISP / Organization   : %s\n\n", org);
    } else {
        fprintf(stderr, "[ERROR] No data received from ISP lookup.\n");
    }

    if (chunk.response) free(chunk.response);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

int main() {
    WSADATA wsaData;
    int iResult;

    SetConsoleTitle("isp Lookup Tool");

    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "[ERROR] WSAStartup failed: %d\n", iResult);
        return 1;
    }

    print_title_border("isp Lookup Tool 2025");
    printf("\n");

    char target[256];
    char* target_ip = NULL;

    while (1) {
        printf("Enter IP address or hostname: ");
        if (fgets(target, sizeof(target), stdin) == NULL) {
            fprintf(stderr, "[ERROR] Error reading input.\n");
            break;
        }

        target[strcspn(target, "\n")] = 0;
        if (strcmp(target, "exit") == 0) break;

        char* cleaned = target;
        char* prefix = strstr(cleaned, "http://");
        if (!prefix) prefix = strstr(cleaned, "https://");
        if (prefix) cleaned = prefix + (prefix[4] == 's' ? 8 : 7);

        char* slash = strchr(cleaned, '/');
        if (slash) *slash = '\0';

        target_ip = resolve_hostname(cleaned);
        if (!target_ip) {
            fprintf(stderr, "[ERROR] Failed to resolve hostname to IP.\n\n");
            continue;
        }

        printf("Resolved IP: %s\n", target_ip);
        perform_isp_lookup(target_ip);
        free(target_ip);
        printf("\n");
    }

    WSACleanup();
    return 0;
}
