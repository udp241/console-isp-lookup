/*
 * isp - IP / ISP lookup for the Windows console
 * https://github.com/udp241/console-isp-lookup
 *
 * Copyright (c) 2026 wljt
 *
 * Looks an address up on ip-api.com and falls back to ipapi.co and
 * ipinfo.io if that fails. Uses WinHTTP and Winsock only, so there's
 * nothing extra to install or link against.
 */

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <conio.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#endif

#define ISP_VERSION  "2.0"
#define ISP_AUTHOR   "@wljt"
#define USER_AGENT   "isp/" ISP_VERSION
#define NET_TIMEOUT  6000      /* ms, per connect / send / receive */
#define MAX_BODY     (1u << 20)

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

/* ---- colours (same palette as the rest of the rhino tools) ---- */

static int g_color = 1;

#define CYAN    (g_color ? "\x1b[38;5;87m"  : "")
#define GREEN   (g_color ? "\x1b[38;5;120m" : "")
#define RED     (g_color ? "\x1b[38;5;203m" : "")
#define YELLOW  (g_color ? "\x1b[38;5;221m" : "")
#define MAGENTA (g_color ? "\x1b[38;5;213m" : "")
#define ORANGE  (g_color ? "\x1b[38;5;215m" : "")
#define GRAY    (g_color ? "\x1b[38;5;245m" : "")
#define BOLD    (g_color ? "\x1b[1m"        : "")
#define RESET   (g_color ? "\x1b[0m"        : "")

/* ---- growable buffer ---- */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} Buf;

static int buf_add(Buf *b, const void *src, size_t n)
{
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        char *p;
        while (cap < b->len + n + 1)
            cap *= 2;
        p = realloc(b->data, cap);
        if (!p)
            return 0;
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 1;
}

static void buf_free(Buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ---- portable helpers (json, input cleanup) ---- */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return p;
}

static size_t put_utf8(char *out, size_t o, size_t n, unsigned cp)
{
    char tmp[3];
    size_t k;

    if (cp < 0x80) {
        tmp[0] = (char)cp;
        k = 1;
    } else if (cp < 0x800) {
        tmp[0] = (char)(0xC0 | (cp >> 6));
        tmp[1] = (char)(0x80 | (cp & 0x3F));
        k = 2;
    } else {
        tmp[0] = (char)(0xE0 | (cp >> 12));
        tmp[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[2] = (char)(0x80 | (cp & 0x3F));
        k = 3;
    }
    if (o + k < n) {
        memcpy(out + o, tmp, k);
        o += k;
    }
    return o;
}

/* Reads a JSON string at p (which must point at the opening quote).
 * Unescapes into out if out isn't NULL. Returns the position after the
 * closing quote, or NULL if the string is malformed. */
static const char *json_str(const char *p, char *out, size_t n)
{
    size_t o = 0;

    if (*p != '"')
        return NULL;

    for (p++; *p && *p != '"'; ) {
        unsigned cp;

        if (*p != '\\') {
            if (out && o + 1 < n)
                out[o++] = *p;
            p++;
            continue;
        }

        p++;
        switch (*p) {
        case 'n': cp = '\n'; break;
        case 't': cp = '\t'; break;
        case 'r': cp = '\r'; break;
        case 'b': cp = '\b'; break;
        case 'f': cp = '\f'; break;
        case 'u': {
            char hex[5];
            int i;
            for (i = 0; i < 4; i++) {
                if (!isxdigit((unsigned char)p[1 + i]))
                    return NULL;
                hex[i] = p[1 + i];
            }
            hex[4] = '\0';
            cp = (unsigned)strtoul(hex, NULL, 16);
            if (cp >= 0xD800 && cp <= 0xDFFF)
                cp = '?';
            p += 4;
            break;
        }
        case '\0':
            return NULL;
        default:
            cp = (unsigned char)*p;
            break;
        }
        p++;
        if (out)
            o = put_utf8(out, o, n, cp);
    }

    if (*p != '"')
        return NULL;
    if (out && n)
        out[o] = '\0';
    return p + 1;
}

/* Skips over one JSON value of any type. */
static const char *json_skip(const char *p)
{
    p = skip_ws(p);

    if (*p == '"')
        return json_str(p, NULL, 0);

    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (*p) {
            if (*p == '"') {
                p = json_str(p, NULL, 0);
                if (!p)
                    return NULL;
                continue;
            }
            if (*p == '{' || *p == '[') {
                depth++;
            } else if (*p == '}' || *p == ']') {
                if (--depth == 0)
                    return p + 1;
            }
            p++;
        }
        return NULL;
    }

    while (*p && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p))
        p++;
    return p;
}

/* Looks up a top-level key in a flat JSON object. Strings come back
 * unescaped, numbers and booleans as written, null as "". Nested
 * objects/arrays count as found but come back empty. */
static int json_get(const char *json, const char *key, char *out, size_t n)
{
    const char *p;

    out[0] = '\0';
    if (!json)
        return 0;

    p = skip_ws(json);
    if (*p != '{')
        return 0;
    p++;

    for (;;) {
        char k[64];

        p = skip_ws(p);
        if (*p == '}')
            return 0;
        p = json_str(p, k, sizeof k);
        if (!p)
            return 0;
        p = skip_ws(p);
        if (*p != ':')
            return 0;
        p = skip_ws(p + 1);

        if (strcmp(k, key) == 0) {
            const char *e;
            size_t len;

            if (*p == '"')
                return json_str(p, out, n) != NULL;
            if (*p == '{' || *p == '[')
                return 1;
            e = json_skip(p);
            if (!e)
                return 0;
            len = (size_t)(e - p);
            if (len >= n)
                len = n - 1;
            memcpy(out, p, len);
            out[len] = '\0';
            if (strcmp(out, "null") == 0)
                out[0] = '\0';
            return 1;
        }

        p = json_skip(p);
        if (!p)
            return 0;
        p = skip_ws(p);
        if (*p != ',')
            return 0;
        p++;
    }
}

/* Turns whatever the user typed into a bare host or address:
 * "https://user@example.com:8443/x?y" -> "example.com",
 * "[2606:4700::1111]:443" -> "2606:4700::1111". */
static void clean_target(const char *in, char *out, size_t n)
{
    const char *p = in;
    const char *scheme;
    char *at, *colon;
    size_t o = 0, len;

    while (*p && isspace((unsigned char)*p))
        p++;
    scheme = strstr(p, "://");
    if (scheme)
        p = scheme + 3;

    while (*p && *p != '/' && *p != '?' && *p != '#' && !isspace((unsigned char)*p) && o + 1 < n)
        out[o++] = *p++;
    out[o] = '\0';

    at = strrchr(out, '@');
    if (at)
        memmove(out, at + 1, strlen(at + 1) + 1);

    if (out[0] == '[') {
        char *close = strchr(out, ']');
        if (close) {
            *close = '\0';
            memmove(out, out + 1, strlen(out + 1) + 1);
        }
        return;
    }

    /* one colon means host:port, more than one is a bare IPv6 address */
    colon = strchr(out, ':');
    if (colon && !strchr(colon + 1, ':'))
        *colon = '\0';

    len = strlen(out);
    if (len && out[len - 1] == '.')
        out[len - 1] = '\0';
}

/* "AS13335 Cloudflare, Inc." -> "AS13335" + "Cloudflare, Inc." */
static void split_as(const char *s, char *asn, size_t an, char *rest, size_t rn)
{
    const char *sp;
    size_t len;

    asn[0] = rest[0] = '\0';
    if (strncmp(s, "AS", 2) != 0) {
        snprintf(rest, rn, "%s", s);
        return;
    }
    sp = strchr(s, ' ');
    len = sp ? (size_t)(sp - s) : strlen(s);
    if (len >= an)
        len = an - 1;
    memcpy(asn, s, len);
    asn[len] = '\0';
    if (sp)
        snprintf(rest, rn, "%s", sp + 1);
}

/* Private, loopback, link-local, CGNAT, multicast and reserved ranges. */
static int is_private(const char *ip)
{
    struct in_addr a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, ip, &a4) == 1) {
        const unsigned char *b = (const unsigned char *)&a4;
        return b[0] == 0 || b[0] == 10 || b[0] == 127 ||
               (b[0] == 100 && (b[1] & 0xC0) == 64) ||
               (b[0] == 169 && b[1] == 254) ||
               (b[0] == 172 && (b[1] & 0xF0) == 16) ||
               (b[0] == 192 && b[1] == 168) ||
               b[0] >= 224;
    }

    if (inet_pton(AF_INET6, ip, &a6) == 1) {
        static const unsigned char zero[15];
        const unsigned char *b = (const unsigned char *)&a6;
        if (memcmp(b, zero, 15) == 0 && b[15] <= 1)
            return 1;                                   /* :: and ::1 */
        if ((b[0] & 0xFE) == 0xFC)
            return 1;                                   /* fc00::/7  */
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
            return 1;                                   /* fe80::/10 */
        if (b[0] == 0xFF)
            return 1;                                   /* multicast */
    }
    return 0;
}

static int is_ip_literal(const char *s)
{
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

/* ---- end portable helpers ---- */

/* ---- network ---- */

static int https_get(const char *host, const char *path, const char *header,
                     Buf *out, DWORD *status)
{
    wchar_t whost[256], wpath[1024], whdr[256], wua[64];
    HINTERNET ses = NULL, con = NULL, req = NULL;
    DWORD protos = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    DWORD code = 0, size = sizeof code;
    int ok = 0;

    *status = 0;
    if (!MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256) ||
        !MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 1024) ||
        !MultiByteToWideChar(CP_UTF8, 0, header ? header : "", -1, whdr, 256) ||
        !MultiByteToWideChar(CP_UTF8, 0, USER_AGENT, -1, wua, 64))
        return 0;

    ses = WinHttpOpen(wua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses)
        goto done;

    /* older builds reject the TLS 1.3 flag, so retry with 1.2 alone */
    if (!WinHttpSetOption(ses, WINHTTP_OPTION_SECURE_PROTOCOLS, &protos, sizeof protos)) {
        protos = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(ses, WINHTTP_OPTION_SECURE_PROTOCOLS, &protos, sizeof protos);
    }
    WinHttpSetTimeouts(ses, NET_TIMEOUT, NET_TIMEOUT, NET_TIMEOUT, NET_TIMEOUT);

    con = WinHttpConnect(ses, whost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!con)
        goto done;
    req = WinHttpOpenRequest(con, L"GET", wpath, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req)
        goto done;

    if (!WinHttpSendRequest(req,
                            whdr[0] ? whdr : WINHTTP_NO_ADDITIONAL_HEADERS,
                            whdr[0] ? (DWORD)-1L : 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, NULL))
        goto done;

    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &size, WINHTTP_NO_HEADER_INDEX);
    *status = code;

    for (;;) {
        char tmp[4096];
        DWORD avail = 0, got = 0;

        if (!WinHttpQueryDataAvailable(req, &avail))
            goto done;
        if (avail == 0)
            break;
        if (avail > sizeof tmp)
            avail = sizeof tmp;
        if (!WinHttpReadData(req, tmp, avail, &got))
            goto done;
        if (got == 0)
            break;
        if (!buf_add(out, tmp, got) || out->len > MAX_BODY)
            goto done;
    }
    ok = out->data != NULL;

done:
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    if (ses) WinHttpCloseHandle(ses);
    return ok;
}

static int connect_timeout(SOCKET s, const struct sockaddr *sa, int len, int ms)
{
    u_long nb = 1;
    fd_set wr, ex;
    struct timeval tv;
    int err = 0, elen = sizeof err;

    ioctlsocket(s, FIONBIO, &nb);
    if (connect(s, sa, len) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
        return 0;

    FD_ZERO(&wr);
    FD_SET(s, &wr);
    FD_ZERO(&ex);
    FD_SET(s, &ex);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (select(0, NULL, &wr, &ex, &tv) <= 0 || FD_ISSET(s, &ex))
        return 0;

    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return err == 0;
}

/* Plain HTTP GET to a known IP with our own Host header. ip-api.com's
 * free tier is HTTP only, and doing it by hand lets us connect to an
 * address we resolved ourselves (see resolve_api_host). */
static int http_get_ip(const char *ip, const char *host, const char *path,
                       Buf *out, int *status)
{
    struct sockaddr_in sa;
    SOCKET s;
    char req[1024], *body;
    DWORD to = NET_TIMEOUT;
    int n, sent, ok = 0;

    *status = 0;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(80);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1)
        return 0;

    n = snprintf(req, sizeof req,
                 "GET %s HTTP/1.0\r\n"
                 "Host: %s\r\n"
                 "User-Agent: " USER_AGENT "\r\n"
                 "Accept: application/json\r\n"
                 "Connection: close\r\n\r\n", path, host);
    if (n <= 0 || n >= (int)sizeof req)
        return 0;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return 0;
    if (!connect_timeout(s, (struct sockaddr *)&sa, sizeof sa, NET_TIMEOUT))
        goto done;

    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof to);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&to, sizeof to);

    for (sent = 0; sent < n; ) {
        int k = send(s, req + sent, n - sent, 0);
        if (k <= 0)
            goto done;
        sent += k;
    }

    for (;;) {
        char tmp[4096];
        int k = recv(s, tmp, sizeof tmp, 0);
        if (k == 0)
            break;
        if (k < 0)
            goto done;
        if (!buf_add(out, tmp, (size_t)k) || out->len > MAX_BODY)
            goto done;
    }

    if (!out->data || sscanf(out->data, "HTTP/%*d.%*d %d", status) != 1)
        goto done;
    body = strstr(out->data, "\r\n\r\n");
    if (!body)
        goto done;
    body += 4;
    out->len -= (size_t)(body - out->data);
    memmove(out->data, body, out->len + 1);
    ok = 1;

done:
    closesocket(s);
    return ok;
}

static int sinkholed(const char *ip)
{
    return strncmp(ip, "0.", 2) == 0 || strncmp(ip, "127.", 4) == 0;
}

/* Resolves an API hostname through Cloudflare's DNS-over-HTTPS. */
static int doh_resolve(const char *host, char *ip, size_t n)
{
    char path[256];
    const char *p;
    Buf b = {0};
    DWORD status = 0;
    int ok = 0;

    snprintf(path, sizeof path, "/dns-query?name=%s&type=A", host);
    if (!https_get("1.1.1.1", path, "Accept: application/dns-json", &b, &status) || status != 200)
        goto done;

    p = strstr(b.data, "\"Answer\"");
    while (p && (p = strstr(p, "\"data\"")) != NULL) {
        char val[64];
        struct in_addr tmp;
        const char *next;

        p = skip_ws(p + 6);
        if (*p != ':')
            continue;
        p = skip_ws(p + 1);
        next = json_str(p, val, sizeof val);
        if (next && inet_pton(AF_INET, val, &tmp) == 1 && !sinkholed(val)) {
            snprintf(ip, n, "%s", val);
            ok = 1;
            break;
        }
        p = next;
    }

done:
    buf_free(&b);
    return ok;
}

/* Normal DNS first. If that fails or comes back as a sinkhole address
 * (Pi-hole, adblock hosts files and the like), ask DoH instead. */
static int resolve_api_host(const char *host, char *ip, size_t n, int *via_doh)
{
    struct addrinfo hints, *res = NULL;

    *via_doh = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, ip, n);
        freeaddrinfo(res);
        if (!sinkholed(ip))
            return 1;
    }

    *via_doh = 1;
    return doh_resolve(host, ip, n);
}

static int resolve_target(const char *host, char *ip, size_t n)
{
    struct addrinfo hints, *res = NULL, *p, *pick;
    int ok;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
        return 0;

    pick = res;
    for (p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            pick = p;
            break;
        }
    }
    ok = getnameinfo(pick->ai_addr, (socklen_t)pick->ai_addrlen, ip, (DWORD)n,
                     NULL, 0, NI_NUMERICHOST) == 0;
    freeaddrinfo(res);
    return ok;
}

static void reverse_dns(const char *ip, char *out, size_t n)
{
    struct sockaddr_storage ss;
    struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
    int len;

    out[0] = '\0';
    memset(&ss, 0, sizeof ss);
    if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        len = sizeof *s4;
    } else if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        len = sizeof *s6;
    } else {
        return;
    }
    if (getnameinfo((struct sockaddr *)&ss, len, out, (DWORD)n, NULL, 0, NI_NAMEREQD) != 0)
        out[0] = '\0';
}

/* ---- providers ---- */

typedef struct {
    char ip[64], reverse[256];
    char asn[32], asname[128], isp[160], org[160];
    char country[80], cc[8], region[80], city[80], zip[24];
    char lat[24], lon[24], tz[64], currency[16];
    int  proxy, hosting, mobile;           /* 1 yes, 0 no, -1 unknown */
    const char *source;
} Info;

/* Provider result: 1 = got it, 0 = failed (try the next one),
 * -1 = the address itself was rejected (no point trying others). */
typedef int (*provider_fn)(const char *q, Info *info, char *why, size_t wn);

static void info_init(Info *i)
{
    memset(i, 0, sizeof *i);
    i->proxy = i->hosting = i->mobile = -1;
}

static int tri(const char *v)
{
    if (strcmp(v, "true") == 0)
        return 1;
    if (strcmp(v, "false") == 0)
        return 0;
    return -1;
}

#define IPAPI_FIELDS "status,message,query,country,countryCode,regionName,city,zip," \
                     "lat,lon,timezone,currency,isp,org,as,asname,reverse,mobile,proxy,hosting"

static int from_ip_api(const char *q, Info *info, char *why, size_t wn)
{
    char ip[64], path[512], v[256], rest[160];
    Buf b = {0};
    int doh = 0, status = 0, rc = 0;

    if (!resolve_api_host("ip-api.com", ip, sizeof ip, &doh)) {
        snprintf(why, wn, "couldn't resolve ip-api.com");
        return 0;
    }

    snprintf(path, sizeof path, "/json/%s?fields=" IPAPI_FIELDS, q);
    if (!http_get_ip(ip, "ip-api.com", path, &b, &status)) {
        snprintf(why, wn, "no response");
        goto done;
    }
    if (status != 200) {
        snprintf(why, wn, status == 429 ? "rate limited" : "HTTP %d", status);
        goto done;
    }

    json_get(b.data, "status", v, sizeof v);
    if (strcmp(v, "success") != 0) {
        json_get(b.data, "message", v, sizeof v);
        snprintf(why, wn, "%s", v[0] ? v : "lookup failed");
        if (strcmp(v, "invalid query") == 0 || strstr(v, "range"))
            rc = -1;
        goto done;
    }

    json_get(b.data, "query", info->ip, sizeof info->ip);
    json_get(b.data, "reverse", info->reverse, sizeof info->reverse);
    json_get(b.data, "isp", info->isp, sizeof info->isp);
    json_get(b.data, "org", info->org, sizeof info->org);
    json_get(b.data, "as", v, sizeof v);
    split_as(v, info->asn, sizeof info->asn, rest, sizeof rest);
    json_get(b.data, "asname", info->asname, sizeof info->asname);
    if (!info->asname[0])
        snprintf(info->asname, sizeof info->asname, "%s", rest);

    json_get(b.data, "country", info->country, sizeof info->country);
    json_get(b.data, "countryCode", info->cc, sizeof info->cc);
    json_get(b.data, "regionName", info->region, sizeof info->region);
    json_get(b.data, "city", info->city, sizeof info->city);
    json_get(b.data, "zip", info->zip, sizeof info->zip);
    json_get(b.data, "lat", info->lat, sizeof info->lat);
    json_get(b.data, "lon", info->lon, sizeof info->lon);
    json_get(b.data, "timezone", info->tz, sizeof info->tz);
    json_get(b.data, "currency", info->currency, sizeof info->currency);

    json_get(b.data, "proxy", v, sizeof v);
    info->proxy = tri(v);
    json_get(b.data, "hosting", v, sizeof v);
    info->hosting = tri(v);
    json_get(b.data, "mobile", v, sizeof v);
    info->mobile = tri(v);

    info->source = doh ? "ip-api.com (resolved over DoH)" : "ip-api.com";
    rc = 1;

done:
    buf_free(&b);
    return rc;
}

static int from_ipapi_co(const char *q, Info *info, char *why, size_t wn)
{
    char path[256], v[256];
    Buf b = {0};
    DWORD status = 0;
    int rc = 0;

    if (q[0])
        snprintf(path, sizeof path, "/%s/json/", q);
    else
        snprintf(path, sizeof path, "/json/");

    if (!https_get("ipapi.co", path, "Accept: application/json", &b, &status)) {
        snprintf(why, wn, "no response");
        goto done;
    }
    if (status != 200) {
        snprintf(why, wn, status == 429 ? "rate limited" : "HTTP %lu", (unsigned long)status);
        goto done;
    }
    if (json_get(b.data, "error", v, sizeof v) && strcmp(v, "true") == 0) {
        json_get(b.data, "reason", v, sizeof v);
        snprintf(why, wn, "%s", v[0] ? v : "lookup failed");
        goto done;
    }

    json_get(b.data, "ip", info->ip, sizeof info->ip);
    if (!info->ip[0]) {
        snprintf(why, wn, "unexpected response");
        goto done;
    }
    json_get(b.data, "asn", info->asn, sizeof info->asn);
    json_get(b.data, "org", info->org, sizeof info->org);
    snprintf(info->isp, sizeof info->isp, "%s", info->org);
    json_get(b.data, "country_name", info->country, sizeof info->country);
    json_get(b.data, "country_code", info->cc, sizeof info->cc);
    json_get(b.data, "region", info->region, sizeof info->region);
    json_get(b.data, "city", info->city, sizeof info->city);
    json_get(b.data, "postal", info->zip, sizeof info->zip);
    json_get(b.data, "latitude", info->lat, sizeof info->lat);
    json_get(b.data, "longitude", info->lon, sizeof info->lon);
    json_get(b.data, "timezone", info->tz, sizeof info->tz);
    json_get(b.data, "currency", info->currency, sizeof info->currency);

    info->source = "ipapi.co";
    rc = 1;

done:
    buf_free(&b);
    return rc;
}

static int from_ipinfo(const char *q, Info *info, char *why, size_t wn)
{
    char path[256], v[256], *comma;
    Buf b = {0};
    DWORD status = 0;
    int rc = 0;

    if (q[0])
        snprintf(path, sizeof path, "/%s/json", q);
    else
        snprintf(path, sizeof path, "/json");

    if (!https_get("ipinfo.io", path, "Accept: application/json", &b, &status)) {
        snprintf(why, wn, "no response");
        goto done;
    }
    if (status != 200) {
        snprintf(why, wn, status == 429 ? "rate limited" : "HTTP %lu", (unsigned long)status);
        goto done;
    }
    if (json_get(b.data, "bogon", v, sizeof v) && strcmp(v, "true") == 0) {
        snprintf(why, wn, "reserved address");
        rc = -1;
        goto done;
    }
    if (json_get(b.data, "error", v, sizeof v)) {
        snprintf(why, wn, "api error");
        goto done;
    }

    json_get(b.data, "ip", info->ip, sizeof info->ip);
    if (!info->ip[0]) {
        snprintf(why, wn, "unexpected response");
        goto done;
    }
    json_get(b.data, "hostname", info->reverse, sizeof info->reverse);
    json_get(b.data, "org", v, sizeof v);
    split_as(v, info->asn, sizeof info->asn, info->org, sizeof info->org);
    snprintf(info->isp, sizeof info->isp, "%s", info->org);
    json_get(b.data, "country", info->cc, sizeof info->cc);
    json_get(b.data, "region", info->region, sizeof info->region);
    json_get(b.data, "city", info->city, sizeof info->city);
    json_get(b.data, "postal", info->zip, sizeof info->zip);
    json_get(b.data, "timezone", info->tz, sizeof info->tz);
    json_get(b.data, "loc", v, sizeof v);
    comma = strchr(v, ',');
    if (comma) {
        *comma = '\0';
        snprintf(info->lat, sizeof info->lat, "%s", v);
        snprintf(info->lon, sizeof info->lon, "%s", comma + 1);
    }

    info->source = "ipinfo.io";
    rc = 1;

done:
    buf_free(&b);
    return rc;
}

static const struct {
    const char *name;
    provider_fn fn;
} providers[] = {
    { "ip-api.com", from_ip_api   },
    { "ipapi.co",   from_ipapi_co },
    { "ipinfo.io",  from_ipinfo   },
};

/* ---- output ---- */

static void banner(void)
{
    const char *title = "Rhino's ISP Lookup Tool";
    char stars[65];
    int inner = (int)sizeof stars - 3;            /* 62 chars between the borders */
    int tlen = (int)strlen(title);
    int left = (inner - tlen) / 2;
    int right = inner - tlen - left;

    memset(stars, '*', sizeof stars - 1);
    stars[sizeof stars - 1] = '\0';

    printf("\n  %s%s%s\n", CYAN, stars, RESET);
    printf("  %s*%s%*s%s%s%s%s%*s%s*%s\n",
           CYAN, RESET, left, "", BOLD, YELLOW, title, RESET, right, "", CYAN, RESET);
    printf("  %s%s%s\n", CYAN, stars, RESET);
    printf("  %sisp v" ISP_VERSION " - Copyright (c) 2026 " ISP_AUTHOR "%s\n\n", GRAY, RESET);
}

static void usage(void)
{
    printf("  usage: isp [--no-color] [target ...]\n\n"
           "    target       IP address, hostname or URL (\"me\" for your own IP)\n"
           "    --no-color   plain output, no ANSI colours\n"
           "    -h, --help   show this help\n\n"
           "  With no target it starts an interactive prompt.\n\n");
}

static void section(const char *name)
{
    printf("\n  %s-- %s --%s\n", CYAN, name, RESET);
}

static void row(const char *label, const char *color, const char *value)
{
    if (value && value[0])
        printf("  %-12s: %s%s%s\n", label, color, value, RESET);
    else
        printf("  %-12s: %s-%s\n", label, GRAY, RESET);
}

static void flag_row(const char *label, int v, const char *yes_color)
{
    if (v == 1)
        printf("  %-12s: %syes%s\n", label, yes_color, RESET);
    else if (v == 0)
        printf("  %-12s: %sno%s\n", label, GREEN, RESET);
    else
        printf("  %-12s: %s-%s\n", label, GRAY, RESET);
}

static void print_info(const Info *i)
{
    char buf[256];

    section("Network");
    row("IP", YELLOW, i->ip);
    row("Reverse DNS", MAGENTA, i->reverse);
    row("ASN", YELLOW, i->asn);
    row("AS Name", MAGENTA, i->asname);
    row("ISP", MAGENTA, i->isp);
    row("Org", MAGENTA, i->org);

    section("Location");
    if (i->country[0] && i->cc[0])
        snprintf(buf, sizeof buf, "%s (%s)", i->country, i->cc);
    else
        snprintf(buf, sizeof buf, "%s", i->country[0] ? i->country : i->cc);
    row("Country", GREEN, buf);
    row("Region", GREEN, i->region);
    row("City", GREEN, i->city);
    row("Postal", "", i->zip);
    if (i->lat[0] && i->lon[0])
        snprintf(buf, sizeof buf, "%s, %s", i->lat, i->lon);
    else
        buf[0] = '\0';
    row("Lat / Lon", ORANGE, buf);
    row("Timezone", "", i->tz);
    row("Currency", "", i->currency);

    if (i->proxy >= 0 || i->hosting >= 0 || i->mobile >= 0) {
        section("Flags");
        flag_row("Proxy / VPN", i->proxy, RED);
        flag_row("Hosting", i->hosting, RED);
        flag_row("Mobile", i->mobile, YELLOW);
        if (i->hosting == 1 || i->proxy == 1)
            putchar('\n');
        if (i->hosting == 1)
            printf("  %s[!] suspicious: this IP looks like a datacenter/hosting provider%s\n", RED, RESET);
        if (i->proxy == 1)
            printf("  %s[!] suspicious: this IP is flagged as a proxy/VPN%s\n", RED, RESET);
    }

    printf("\n  %ssource: %s%s\n\n", GRAY, i->source, RESET);
}

/* ---- lookup ---- */

static int lookup(const char *raw)
{
    char target[256], ip[64] = "", why[160];
    Info info;
    size_t i;
    int rc = 0;

    clean_target(raw, target, sizeof target);

    if (target[0]) {
        if (is_ip_literal(target)) {
            snprintf(ip, sizeof ip, "%s", target);
        } else if (resolve_target(target, ip, sizeof ip)) {
            printf("  %sResolved%s %s%s%s -> %s%s%s\n",
                   GRAY, RESET, YELLOW, target, RESET, YELLOW, ip, RESET);
        } else {
            printf("  %s[!] Couldn't resolve %s%s\n\n", RED, target, RESET);
            return 0;
        }
        if (is_private(ip)) {
            printf("  %s[!] %s is a private/reserved address, nothing to look up%s\n\n", RED, ip, RESET);
            return 0;
        }
        printf("  Looking up %s%s%s ...\n", YELLOW, ip, RESET);
    } else {
        printf("  Looking up %syour public IP%s ...\n", YELLOW, RESET);
    }
    fflush(stdout);

    for (i = 0; i < sizeof providers / sizeof providers[0]; i++) {
        info_init(&info);
        why[0] = '\0';
        rc = providers[i].fn(ip, &info, why, sizeof why);
        if (rc == 1)
            break;
        printf("  %s%s: %s%s\n", GRAY, providers[i].name, why[0] ? why : "failed", RESET);
        fflush(stdout);
        if (rc < 0)
            break;
    }

    if (rc != 1) {
        printf("  %s[!] Lookup failed%s\n\n", RED, RESET);
        fflush(stdout);
        return 0;
    }

    if (!info.reverse[0] && info.ip[0])
        reverse_dns(info.ip, info.reverse, sizeof info.reverse);

    print_info(&info);
    fflush(stdout);
    return 1;
}

/* ---- console ---- */

static void console_init(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;

    SetConsoleTitleA("Rhino is a God");
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, NULL, _IOFBF, 1 << 14);

    if (getenv("NO_COLOR") ||
        !GetConsoleMode(out, &mode) ||
        !SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        g_color = 0;
}

/* True when we're the only process on this console, i.e. started from
 * Win+R or Explorer. Keeps the window open long enough to read it. */
static int standalone(void)
{
    DWORD procs[2];
    return GetConsoleProcessList(procs, 2) <= 1;
}

static void interactive(void)
{
    char line[512];

    printf("  %sBlank line = your own IP, \"exit\" to quit%s\n\n", GRAY, RESET);
    for (;;) {
        char *t = line;

        printf("  %sEnter IP address or hostname:%s ", CYAN, RESET);
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin))
            break;
        line[strcspn(line, "\r\n")] = '\0';
        while (isspace((unsigned char)*t))
            t++;
        if (_stricmp(t, "exit") == 0 || _stricmp(t, "quit") == 0)
            break;
        putchar('\n');
        lookup(t);
    }
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    int i, targets = 0, failed = 0;

    console_init();

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-color") == 0) {
            g_color = 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "/?") == 0) {
            banner();
            usage();
            fflush(stdout);
            return 0;
        }
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    banner();

    for (i = 1; i < argc; i++) {
        const char *t = argv[i];

        if (t[0] == '-') {
            if (strcmp(t, "--no-color") != 0)
                printf("  %s[!] unknown option %s (try -h)%s\n\n", RED, t, RESET);
            continue;
        }
        if (_stricmp(t, "me") == 0 || _stricmp(t, "self") == 0)
            t = "";
        targets++;
        if (!lookup(t))
            failed++;
    }

    if (targets) {
        if (standalone()) {
            printf("  %sPress any key to exit...%s", GRAY, RESET);
            fflush(stdout);
            _getch();
        }
    } else {
        interactive();
    }

    fflush(stdout);
    WSACleanup();
    return failed ? 1 : 0;
}
