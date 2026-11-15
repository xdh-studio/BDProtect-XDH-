/*
 * BatchUpload - BDProtect 批量特征上传工具
 *
 * 功能：
 *   1. 选择一个文件夹（可选包含子文件夹），自动统计其中每个文件的
 *      文件名、大小、MD5
 *   2. 连接服务器读取云端病毒库 Wildlist.txt，逐条对比是否已存在
 *        - MD5 相同            -> 重复，跳过（显示“重复：云端已有”）
 *        - 仅大小相同          -> 视为新文件，但提示“云端有同大小条目”
 *        - 本文件夹内 MD5 相同 -> 只上传第一个
 *   3. 把新增文件的 "大小 MD5 名称" 一次性批量上传（服务器 addviruses 命令）
 *   4. 可选：上传后自动把病毒库版本号升一位并发布，客户端下次启动即可更新
 *
 * 服务器配置读取 exe 同目录 IPconfig.ini：
 *   server_ip=152.136.44.200
 *   server_port=28586
 */
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>

/* ========== 控件 ID ========== */
#define ID_EDT_FOLDER    1001
#define ID_BTN_BROWSE    1002
#define ID_CHK_RECURSE   1003
#define ID_CHK_PUBLISH   1004
#define ID_BTN_SCAN      1005
#define ID_BTN_UPLOAD    1006
#define ID_BTN_CLEAR     1007
#define ID_LST_FILES     1101
#define ID_PROGRESS      1201
#define ID_LBL_STATUS    1301

#define ID_EDT_PWD       1401
#define ID_BTN_LOGIN_OK  1402
#define ID_BTN_LOGIN_NO  1403

#define MAX_SCAN_FILES   20000
#define MAX_NAME_W       120

/* ========== 全局状态 ========== */
typedef struct { char host[256]; int port; } ServerCfg;
static ServerCfg g_cfg;
static char g_pwd[256] = {0};          /* 当前管理密码（UTF-8） */

static HWND g_hMain = NULL;
static HWND g_edtFolder = NULL, g_chkRecurse = NULL, g_chkPublish = NULL;
static HWND g_btnScan = NULL, g_btnUpload = NULL, g_btnClear = NULL, g_btnBrowse = NULL;
static HWND g_lstFiles = NULL, g_prog = NULL, g_lblStatus = NULL;

static HFONT g_fontBody = NULL;
static BOOL  g_modalDone = FALSE;
static BOOL  g_loginOk = FALSE;
static BOOL  g_busy = FALSE;

/* 扫描得到的文件列表 */
enum {
    ST_NEW = 0,        /* 新增 */
    ST_SAMESIZE,       /* 新增，但云端已有同样大小的条目 */
    ST_DUPCLOUD,       /* 云端已有相同 MD5 */
    ST_DUPLOCAL,       /* 本文件夹内重复 */
    ST_UPLOADED,       /* 已上传 */
    ST_ERROR           /* 读取失败 */
};

typedef struct {
    wchar_t path[MAX_PATH];
    wchar_t rel[MAX_PATH];
    unsigned long long size;
    wchar_t md5[33];
    wchar_t vname[MAX_NAME_W + 8];
    int status;
} FileItem;

static FileItem* g_files = NULL;
static int g_fileCount = 0;
static int g_fileCap = 0;
static BOOL g_recurse = TRUE;

/* 云端病毒库（保留比较需要的字段；名称用于避免重名） */
typedef struct { unsigned long long size; wchar_t hash[33]; BOOL hasHash; wchar_t name[128]; } CloudEntry;
static CloudEntry* g_cloud = NULL;
static int g_cloudCount = 0;
static unsigned long long* g_cloudSizes = NULL;
static int* g_cloudHashTab = NULL;     /* 存索引+1，0 表示空 */
static int g_cloudHashCap = 0;

/* 本文件夹内 MD5 去重表 */
static int* g_localTab = NULL;
static int g_localCap = 0;

static HFONT MakeFont(int px, int weight) {
    return CreateFontW(-px, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
}

static void PumpMessages(void) {
    MSG m;
    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
}

/* 可重入分词（MinGW 的 wcstok 只有两参数版本） */
static wchar_t* WTok(wchar_t* str, const wchar_t* delim, wchar_t** ctx) {
    wchar_t* s = str ? str : *ctx;
    if (!s) return NULL;
    s += wcsspn(s, delim);
    if (!*s) { *ctx = NULL; return NULL; }
    wchar_t* end = s + wcscspn(s, delim);
    if (*end) { *end = 0; *ctx = end + 1; } else *ctx = NULL;
    return s;
}

/* ========== 编码辅助 ========== */
static void W2U(const wchar_t* w, char* out, int cap) {
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap, NULL, NULL);
}
static void U2W(const char* u, wchar_t* out, int cap) {
    MultiByteToWideChar(CP_UTF8, 0, u, -1, out, cap);
}
static void QuoteArg(const wchar_t* w, char* out, int cap) {
    W2U(w, out, cap);
    for (char* p = out; *p; p++) {
        if (*p == '"' || *p == '\r' || *p == '\n' || *p == '\t') *p = '_';
    }
}

/* ========== 网络客户端（与 BDAdmin 同一套协议） ========== */
static BOOL LoadServerCfg(ServerCfg* cfg) {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* s = wcsrchr(path, L'\\');
    if (s) wcscpy(s + 1, L"IPconfig.ini");
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return FALSE;
    cfg->host[0] = 0; cfg->port = 0;
    wchar_t line[512];
    while (fgetws(line, 512, f)) {
        wchar_t* eq = wcschr(line, L'=');
        if (!eq) continue;
        *eq = 0;
        wchar_t* key = line;
        wchar_t* val = eq + 1;
        size_t l = wcslen(val);
        while (l > 0 && (val[l-1] == L'\r' || val[l-1] == L'\n' || val[l-1] == L' ')) val[--l] = 0;
        while (*val == L' ') val++;
        if (_wcsicmp(key, L"server_ip") == 0)   W2U(val, cfg->host, sizeof(cfg->host));
        else if (_wcsicmp(key, L"server_port") == 0) cfg->port = _wtoi(val);
    }
    fclose(f);
    return cfg->host[0] && cfg->port > 0;
}

static BOOL WSAReady(void) {
    static BOOL ready = FALSE;
    if (!ready) { WSADATA w; if (WSAStartup(MAKEWORD(2, 2), &w) == 0) ready = TRUE; }
    return ready;
}

static BOOL ConnectServer(const ServerCfg* cfg, SOCKET* out) {
    if (!WSAReady()) return FALSE;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    sprintf(portstr, "%d", cfg->port);
    if (getaddrinfo(cfg->host, portstr, &hints, &res) != 0) return FALSE;
    BOOL ok = FALSE;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int r = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        BOOL connected = FALSE;
        if (r == 0) connected = TRUE;
        else if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
            struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
            if (select(0, NULL, &wf, NULL, &tv) > 0) {
                int err = 0, elen = sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
                connected = (err == 0);
            }
        }
        nb = 0; ioctlsocket(s, FIONBIO, &nb);
        if (connected) {
            DWORD tmo = 20000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tmo, sizeof(tmo));
            *out = s; ok = TRUE; break;
        }
        closesocket(s);
    }
    freeaddrinfo(res);
    return ok;
}

static BOOL RecvLine(SOCKET s, char* buf, int cap) {
    int i = 0; char c;
    while (i < cap - 1) {
        int r = recv(s, &c, 1, 0);
        if (r <= 0) return FALSE;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = 0;
    return TRUE;
}

static BOOL RecvExact(SOCKET s, char* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int r = recv(s, buf + got, (int)(len - got), 0);
        if (r <= 0) return FALSE;
        got += r;
    }
    return TRUE;
}

static char* RecvAll(SOCKET s, size_t* outLen) {
    size_t cap = 65536, len = 0;
    char* buf = (char*)malloc(cap + 1);
    if (!buf) return NULL;
    while (1) {
        if (len == cap) { cap *= 2; char* nb = (char*)realloc(buf, cap + 1); if (!nb) { free(buf); return NULL; } buf = nb; }
        int r = recv(s, buf + len, (int)(cap - len), 0);
        if (r <= 0) break;
        len += r;
    }
    buf[len] = 0;
    if (outLen) *outLen = len;
    return buf;
}

static char* ReadServerFile(const char* name, size_t* outLen) {
    SOCKET s;
    if (!ConnectServer(&g_cfg, &s)) return NULL;
    char req[512];
    snprintf(req, sizeof(req), "read %s\r\n", name);
    if (send(s, req, (int)strlen(req), 0) <= 0) { closesocket(s); return NULL; }
    char line[256];
    if (!RecvLine(s, line, sizeof(line)) || strncmp(line, "OK", 2) != 0) { closesocket(s); return NULL; }
    char* p = line + 2; while (*p == ' ') p++;
    unsigned long long size = _strtoui64(p, NULL, 10);
    if (size == 0 || size > 64ULL * 1024 * 1024) { closesocket(s); return NULL; }
    char* buf = (char*)malloc((size_t)size + 1);
    if (!buf) { closesocket(s); return NULL; }
    if (!RecvExact(s, buf, (size_t)size)) { free(buf); closesocket(s); return NULL; }
    buf[size] = 0;
    closesocket(s);
    if (outLen) *outLen = (size_t)size;
    return buf;
}

static BOOL Sha256Hex(const char* data, int len, char* out, int cap) {
    if (cap < 65) return FALSE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE obj = NULL, digest = NULL;
    DWORD objLen = 0, digestLen = 0, cb = 0;
    BOOL ok = FALSE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(objLen), &cb, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&digestLen, sizeof(digestLen), &cb, 0))) goto done;
    obj = (PBYTE)malloc(objLen);
    digest = (PBYTE)malloc(digestLen);
    if (!obj || !digest) goto done;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, obj, objLen, NULL, 0, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest, digestLen, 0))) goto done;

    for (DWORD i = 0; i < digestLen && (int)(i * 2 + 2) < cap; i++)
        sprintf(out + i * 2, "%02x", digest[i]);
    out[digestLen * 2] = 0;
    ok = TRUE;

done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    free(obj); free(digest);
    return ok;
}

/* 计算整个文件的 MD5（流式，适合大文件） */
static BOOL Md5FileW(const wchar_t* path, wchar_t* out, int cap) {
    if (cap < 33) return FALSE;
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE obj = NULL, digest = NULL;
    DWORD objLen = 0, digestLen = 0, cb = 0;
    BOOL ok = FALSE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(objLen), &cb, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&digestLen, sizeof(digestLen), &cb, 0))) goto done;
    if (digestLen != 16) goto done;
    obj = (PBYTE)malloc(objLen);
    digest = (PBYTE)malloc(digestLen);
    if (!obj || !digest) goto done;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, obj, objLen, NULL, 0, 0))) goto done;

    char buf[65536];
    DWORD r = 0;
    while (ReadFile(hFile, buf, sizeof(buf), &r, NULL) && r > 0) {
        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)buf, r, 0))) goto done;
    }
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest, digestLen, 0))) goto done;

    for (DWORD i = 0; i < digestLen; i++) swprintf(out + i * 2, 3, L"%02x", digest[i]);
    out[digestLen * 2] = 0;
    ok = TRUE;

done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    free(obj); free(digest);
    CloseHandle(hFile);
    return ok;
}

/* ========== 认证 ========== */
static char g_nonce[64] = {0};

static BOOL AdminConnect(SOCKET* out) {
    SOCKET s;
    if (!ConnectServer(&g_cfg, &s)) return FALSE;
    g_nonce[0] = 0;
    if (send(s, "hello\r\n", 7, 0) <= 0) { closesocket(s); return FALSE; }
    char line[128];
    if (!RecvLine(s, line, sizeof(line)) || strncmp(line, "OK ", 3) != 0) {
        closesocket(s);
        return FALSE;
    }
    strncpy(g_nonce, line + 3, sizeof(g_nonce) - 1);
    g_nonce[sizeof(g_nonce) - 1] = 0;
    *out = s;
    return TRUE;
}

static BOOL AdminWriteCmd(SOCKET s, const char* args) {
    char payload[1024], proof[65], cmd[4096];
    snprintf(payload, sizeof(payload), "%s%s", g_nonce, g_pwd);
    if (!Sha256Hex(payload, (int)strlen(payload), proof, sizeof(proof))) return FALSE;
    snprintf(cmd, sizeof(cmd), "admin %s %s %s\r\n", g_nonce, proof, args);
    cmd[sizeof(cmd) - 1] = 0;
    return send(s, cmd, (int)strlen(cmd), 0) > 0;
}

static char* AdminTalk(const char* args) {
    SOCKET s;
    if (!AdminConnect(&s)) return NULL;
    if (!AdminWriteCmd(s, args)) { closesocket(s); return NULL; }
    char* resp = RecvAll(s, NULL);
    closesocket(s);
    return resp;
}

static BOOL RespOk(const char* resp) { return resp && strncmp(resp, "OK", 2) == 0; }

/* ========== 版本号 ========== */
static BOOL ParseVersion(const char* text, wchar_t* out, int cap) {
    const char* p = strstr(text, "Version:");
    if (!p) return FALSE;
    p += 8; while (*p == ' ') p++;
    char tmp[64]; int i = 0;
    while (p[i] && p[i] != '\r' && p[i] != '\n' && i < 63) { tmp[i] = p[i]; i++; }
    tmp[i] = 0;
    U2W(tmp, out, cap);
    return TRUE;
}

/* 1.0.1 -> 1.0.2，1.0.9 -> 1.1.1（与 BDAdmin 一致） */
static void BumpVersion(const wchar_t* cur, wchar_t* out, int cap) {
    int a = 1, b = 0, c = 0;
    swscanf(cur, L"%d.%d.%d", &a, &b, &c);
    if (c < 9) c++;
    else { c = 1; b++; }
    swprintf(out, cap, L"%d.%d.%d", a, b, c);
}

static void TodayStr(wchar_t* out, int cap) {
    time_t t = time(NULL);
    struct tm* tmv = localtime(&t);
    swprintf(out, cap, L"%04d-%02d-%02d", tmv->tm_year + 1900, tmv->tm_mon + 1, tmv->tm_mday);
}

/* ========== 哈希表 / 去重 ========== */
static unsigned HashStr(const char* s) {
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h & 0x7fffffffu;
}
static int NextPow2(int n) {
    int c = 16;
    while (c < n) c <<= 1;
    return c;
}

static int CmpUll(const void* x, const void* y) {
    unsigned long long a = *(const unsigned long long*)x, b = *(const unsigned long long*)y;
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* 云端 MD5 / 大小索引 */
static void BuildCloudIndex(void) {
    free(g_cloudSizes); g_cloudSizes = NULL;
    free(g_cloudHashTab); g_cloudHashTab = NULL;
    g_cloudHashCap = NextPow2(g_cloudCount * 2 + 16);
    g_cloudHashTab = (int*)calloc(g_cloudHashCap, sizeof(int));
    if (g_cloudCount > 0)
        g_cloudSizes = (unsigned long long*)malloc(sizeof(unsigned long long) * g_cloudCount);

    for (int i = 0; i < g_cloudCount; i++) {
        if (g_cloudSizes) g_cloudSizes[i] = g_cloud[i].size;
        if (!g_cloud[i].hasHash || !g_cloudHashTab) continue;
        char a[33];
        W2U(g_cloud[i].hash, a, sizeof(a));
        unsigned h = HashStr(a) & (g_cloudHashCap - 1);
        while (g_cloudHashTab[h] != 0) h = (h + 1) & (g_cloudHashCap - 1);
        g_cloudHashTab[h] = i + 1;
    }
    /* 大小排序，供二分查找 */
    if (g_cloudSizes)
        qsort(g_cloudSizes, g_cloudCount, sizeof(unsigned long long), CmpUll);
}

static BOOL CloudHasSize(unsigned long long size) {
    if (!g_cloudSizes || g_cloudCount <= 0) return FALSE;
    int lo = 0, hi = g_cloudCount - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (g_cloudSizes[mid] == size) return TRUE;
        if (g_cloudSizes[mid] < size) lo = mid + 1;
        else hi = mid - 1;
    }
    return FALSE;
}

/* 返回 1=哈希相同，0=没有，-1=仅大小相同 */
static int CloudMatch(unsigned long long size, const wchar_t* hash) {
    if (g_cloudHashTab) {
        char a[33];
        W2U(hash, a, sizeof(a));
        unsigned h = HashStr(a) & (g_cloudHashCap - 1);
        int guard = 0;
        while (g_cloudHashTab[h] != 0 && guard++ < g_cloudHashCap) {
            int idx = g_cloudHashTab[h] - 1;
            if (idx >= 0 && idx < g_cloudCount && g_cloud[idx].hasHash &&
                _wcsicmp(g_cloud[idx].hash, hash) == 0)
                return 1;
            h = (h + 1) & (g_cloudHashCap - 1);
        }
    }
    if (CloudHasSize(size)) return -1;
    return 0;
}

/* 本文件夹内 MD5 去重索引 */
static void LocalBuild(int n) {
    free(g_localTab);
    g_localCap = NextPow2(n * 2 + 16);
    g_localTab = (int*)calloc(g_localCap, sizeof(int));
}
/* 返回重复条目的索引，-1 表示没有；找到后不重复插入 */
static int LocalFindOrInsert(int idx, BOOL insert) {
    if (!g_localTab) return -1;
    char a[33];
    W2U(g_files[idx].md5, a, sizeof(a));
    unsigned h = HashStr(a) & (g_localCap - 1);
    int guard = 0;
    while (g_localTab[h] != 0 && guard++ < g_localCap) {
        int j = g_localTab[h] - 1;
        if (j >= 0 && j < g_fileCount && _wcsicmp(g_files[j].md5, g_files[idx].md5) == 0)
            return j;
        h = (h + 1) & (g_localCap - 1);
    }
    if (insert && guard < g_localCap) g_localTab[h] = idx + 1;
    return -1;
}

/* ========== 云端病毒库读取 ========== */
static void FreeCloud(void) {
    free(g_cloud); g_cloud = NULL; g_cloudCount = 0;
    free(g_cloudSizes); g_cloudSizes = NULL;
    free(g_cloudHashTab); g_cloudHashTab = NULL; g_cloudHashCap = 0;
}

static BOOL FetchWildlist(void) {
    FreeCloud();
    size_t len = 0;
    char* resp = ReadServerFile("Wildlist.txt", &len);
    if (!resp) return FALSE;
    wchar_t* w = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    if (!w) { free(resp); return FALSE; }
    U2W(resp, w, (int)len + 1);
    free(resp);

    int cap = 1024;
    g_cloud = (CloudEntry*)malloc(sizeof(CloudEntry) * cap);
    if (!g_cloud) { free(w); return FALSE; }
    g_cloudCount = 0;

    wchar_t* save = NULL;
    wchar_t* line = WTok(w, L"\n", &save);
    while (line) {
        wchar_t* p = line;
        while (*p == L' ' || *p == L'\t' || *p == L'\r') p++;
        if (*p && *p != L'#' && *p != L';') {
            wchar_t* end = NULL;
            unsigned long long sz = _wcstoui64(p, &end, 10);
            if (end != p) {
                while (*end == L' ' || *end == L'\t') end++;
                /* 第二段是 32 位十六进制则视为 MD5（与客户端解析一致） */
                wchar_t token[64];
                int ti = 0;
                while (*end && *end != L' ' && *end != L'\t' && ti < 63) token[ti++] = *end++;
                token[ti] = 0;
                BOOL isHash = (ti == 32);
                for (int k = 0; isHash && k < 32; k++) {
                    wchar_t c = token[k];
                    if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')))
                        isHash = FALSE;
                }
                if (g_cloudCount == cap) {
                    cap *= 2;
                    CloudEntry* nb = (CloudEntry*)realloc(g_cloud, sizeof(CloudEntry) * cap);
                    if (!nb) break;
                    g_cloud = nb;
                }
                CloudEntry* e = &g_cloud[g_cloudCount++];
                e->size = sz;
                e->hasHash = isHash;
                if (isHash) { wcsncpy(e->hash, token, 32); e->hash[32] = 0; }
                else e->hash[0] = 0;

                /* 名称：哈希后面的剩余部分；旧格式则回退到第二段本身 */
                wchar_t* nameStart;
                if (isHash) { while (*end == L' ' || *end == L'\t') end++; nameStart = end; }
                else nameStart = end - ti;
                int ni = 0;
                while (nameStart[ni] && nameStart[ni] != L'\r' && nameStart[ni] != L'\n' &&
                       ni < 127) {
                    e->name[ni] = nameStart[ni];
                    ni++;
                }
                while (ni > 0 && (e->name[ni-1] == L' ' || e->name[ni-1] == L'\t')) ni--;
                e->name[ni] = 0;
            }
        }
        line = WTok(NULL, L"\n", &save);
    }
    free(w);
    BuildCloudIndex();
    return TRUE;
}

/* ========== 文件枚举 ========== */
static void AddFileItem(const wchar_t* full, const wchar_t* rel, unsigned long long size) {
    if (g_fileCount >= MAX_SCAN_FILES) return;
    if (g_fileCount == g_fileCap) {
        int nc = g_fileCap ? g_fileCap * 2 : 256;
        FileItem* nb = (FileItem*)realloc(g_files, sizeof(FileItem) * nc);
        if (!nb) return;
        g_files = nb;
        g_fileCap = nc;
    }
    FileItem* it = &g_files[g_fileCount++];
    wcsncpy(it->path, full, MAX_PATH - 1); it->path[MAX_PATH - 1] = 0;
    wcsncpy(it->rel, rel, MAX_PATH - 1); it->rel[MAX_PATH - 1] = 0;
    it->size = size;
    it->md5[0] = 0;
    it->vname[0] = 0;
    it->status = ST_NEW;
}

static void ScanDirRec(const wchar_t* dir, const wchar_t* relBase, int depth) {
    if (depth > 64) return;
    wchar_t pattern[MAX_PATH];
    swprintf(pattern, MAX_PATH, L"%s\\*", dir);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        wchar_t full[MAX_PATH], rel[MAX_PATH];
        swprintf(full, MAX_PATH, L"%s\\%s", dir, fd.cFileName);
        if (relBase[0]) swprintf(rel, MAX_PATH, L"%s\\%s", relBase, fd.cFileName);
        else swprintf(rel, MAX_PATH, L"%s", fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (g_recurse && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                ScanDirRec(full, rel, depth + 1);
        } else {
            unsigned long long sz = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (sz > 0) AddFileItem(full, rel, sz);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

/* 由相对路径生成病毒名：去掉扩展名，空白/引号替换为下划线 */
static void VirusNameFromRel(const wchar_t* rel, wchar_t* out, int cap) {
    const wchar_t* base = wcsrchr(rel, L'\\');
    base = base ? base + 1 : rel;
    wchar_t tmp[MAX_NAME_W + 8];
    wcsncpy(tmp, base, MAX_NAME_W);
    tmp[MAX_NAME_W] = 0;
    wchar_t* dot = wcsrchr(tmp, L'.');
    if (dot && dot != tmp) *dot = 0;
    int j = 0;
    for (int i = 0; tmp[i] && j < cap - 1 && j < MAX_NAME_W; i++) {
        wchar_t c = tmp[i];
        if (c == L' ' || c == L'\t' || c == L'"' || c == L'\'' ||
            c == L'\r' || c == L'\n' || c == L'/')
            c = L'_';
        out[j++] = c;
    }
    out[j] = 0;
    if (j == 0) { wcsncpy(out, L"sample", cap); }
}

/* ---------- 病毒名去重 ----------
   服务器 addvirus 以“大小 + 名称”判重：若与云端已有条目重名同大小，
   新条目会被拒绝，随后 editvirus 会误改到旧条目。所以上传前必须保证
   本批每个文件的 (大小, 名称) 与云端、与本批其它文件都不冲突。 */
static BOOL CloudNameTaken(const wchar_t* name, unsigned long long size) {
    for (int i = 0; i < g_cloudCount; i++)
        if (g_cloud[i].size == size && _wcsicmp(g_cloud[i].name, name) == 0) return TRUE;
    return FALSE;
}

static int* g_nameTab = NULL;
static int g_nameCap = 0;

static unsigned HashName(const wchar_t* name, unsigned long long size) {
    unsigned h = 2166136261u ^ (unsigned)size ^ (unsigned)(size >> 32);
    while (*name) { h ^= (unsigned)(*name++); h *= 16777619u; }
    return h & 0x7fffffffu;
}

static void NameIndexBuild(int n) {
    free(g_nameTab);
    g_nameCap = NextPow2(n * 2 + 16);
    g_nameTab = (int*)calloc(g_nameCap, sizeof(int));
}

/* 查找本批前面已分配且 大小+名称 相同的条目；insert 时插入当前条目 */
static int NameFindOrInsert(int idx, BOOL insert) {
    if (!g_nameTab) return -1;
    unsigned h = HashName(g_files[idx].vname, g_files[idx].size) & (g_nameCap - 1);
    int guard = 0;
    while (g_nameTab[h] != 0 && guard++ < g_nameCap) {
        int j = g_nameTab[h] - 1;
        if (j >= 0 && j < g_fileCount && g_files[j].size == g_files[idx].size &&
            _wcsicmp(g_files[j].vname, g_files[idx].vname) == 0)
            return j;
        h = (h + 1) & (g_nameCap - 1);
    }
    if (insert && guard < g_nameCap) g_nameTab[h] = idx + 1;
    return -1;
}

/* 生成不与云端 / 本批其它文件冲突的病毒名（冲突时追加 _2、_3…） */
static void AssignUniqueVName(int idx) {
    FileItem* it = &g_files[idx];
    wchar_t base[MAX_NAME_W + 8];
    VirusNameFromRel(it->rel, base, MAX_NAME_W + 8);

    for (int n = 1; n < 10000; n++) {
        wchar_t cand[MAX_NAME_W + 8];
        if (n == 1) {
            wcsncpy(cand, base, MAX_NAME_W);
            cand[MAX_NAME_W] = 0;
        } else {
            wchar_t tail[16];
            swprintf(tail, 16, L"_%d", n);
            int bl = (int)wcslen(base);
            if (bl > MAX_NAME_W - 10) bl = MAX_NAME_W - 10;
            wmemcpy(cand, base, bl);
            wcscpy(cand + bl, tail);
        }
        wcsncpy(it->vname, cand, MAX_NAME_W + 7);
        it->vname[MAX_NAME_W + 7] = 0;
        if (!CloudNameTaken(cand, it->size) && NameFindOrInsert(idx, FALSE) < 0) break;
    }
    NameFindOrInsert(idx, TRUE);
}

/* ========== UI 辅助 ========== */
static HWND MkStatic(HWND p, const wchar_t* t, int x, int y, int w, int h, int id) {
    HWND c = CreateWindowW(L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                           x, y, w, h, p, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
    return c;
}
static HWND MkEdit(HWND p, int id, int x, int y, int w, int h, DWORD extra) {
    HWND c = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL,
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | extra, x, y, w, h, p, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
    return c;
}
static HWND MkButton(HWND p, int id, const wchar_t* t, int x, int y, int w, int h) {
    HWND c = CreateWindowW(L"BUTTON", t, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x, y, w, h, p, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
    return c;
}
static HWND MkCheck(HWND p, int id, const wchar_t* t, int x, int y, int w, int h, BOOL checked) {
    HWND c = CreateWindowW(L"BUTTON", t, WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        x, y, w, h, p, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
    SendMessageW(c, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    return c;
}

static void CenterWindow(HWND hwnd, int w, int h) {
    RECT rc = {0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};
    if (g_hMain && IsWindow(g_hMain)) GetWindowRect(g_hMain, &rc);
    int x = rc.left + ((rc.right - rc.left) - w) / 2;
    int y = rc.top + ((rc.bottom - rc.top) - h) / 2;
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

static void RunModal(HWND owner, HWND dlg) {
    g_modalDone = FALSE;
    EnableWindow(owner, FALSE);
    ShowWindow(dlg, SW_SHOW);
    UpdateWindow(dlg);
    MSG m;
    while (!g_modalDone && GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    g_modalDone = FALSE;
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

static void SetStatusFmt(const wchar_t* fmt, ...) {
    wchar_t buf[600];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 600, fmt, ap);
    va_end(ap);
    if (g_lblStatus) SetWindowTextW(g_lblStatus, buf);
    PumpMessages();
}

static void SetProgress(int permille) {
    if (g_prog) SendMessageW(g_prog, PBM_SETPOS, permille, 0);
}

static const wchar_t* StatusText(int st) {
    switch (st) {
    case ST_NEW:       return L"新增";
    case ST_SAMESIZE:  return L"新增（云端有同大小条目）";
    case ST_DUPCLOUD:  return L"重复：云端已有";
    case ST_DUPLOCAL:  return L"重复：本文件夹内已有";
    case ST_UPLOADED:  return L"已上传";
    default:           return L"读取失败";
    }
}

static void RefillList(void) {
    SendMessageW(g_lstFiles, LVM_DELETEALLITEMS, 0, 0);
    for (int i = 0; i < g_fileCount; i++) {
        FileItem* it = &g_files[i];
        wchar_t num[32];
        swprintf(num, 32, L"%llu", it->size);

        LVITEMW li = {0};
        li.mask = LVIF_TEXT;
        li.iItem = i;
        li.iSubItem = 0;
        li.pszText = it->rel;
        SendMessageW(g_lstFiles, LVM_INSERTITEMW, 0, (LPARAM)&li);

        SendMessageW(g_lstFiles, LVM_SETITEMTEXTW, i, (LPARAM)&(LVITEMW){ LVIF_TEXT, i, 1, 0, 0, num, 0, 0, 0 });
        SendMessageW(g_lstFiles, LVM_SETITEMTEXTW, i, (LPARAM)&(LVITEMW){ LVIF_TEXT, i, 2, 0, 0, it->md5[0] ? it->md5 : L"(未计算)", 0, 0, 0 });
        SendMessageW(g_lstFiles, LVM_SETITEMTEXTW, i, (LPARAM)&(LVITEMW){ LVIF_TEXT, i, 3, 0, 0, (LPWSTR)StatusText(it->status), 0, 0, 0 });
        SendMessageW(g_lstFiles, LVM_SETITEMTEXTW, i, (LPARAM)&(LVITEMW){ LVIF_TEXT, i, 4, 0, 0, it->vname, 0, 0, 0 });
    }
}

static void UpdateSummary(void) {
    int nNew = 0, nSame = 0, nCloud = 0, nLocal = 0, nUp = 0, nErr = 0;
    for (int i = 0; i < g_fileCount; i++) {
        switch (g_files[i].status) {
        case ST_NEW: nNew++; break;
        case ST_SAMESIZE: nSame++; break;
        case ST_DUPCLOUD: nCloud++; break;
        case ST_DUPLOCAL: nLocal++; break;
        case ST_UPLOADED: nUp++; break;
        default: nErr++; break;
        }
    }
    SetStatusFmt(L"共 %d 个文件：新增 %d，同大小新增 %d，云端已有 %d，本文件夹重复 %d，已上传 %d，读取失败 %d",
                 g_fileCount, nNew, nSame, nCloud, nLocal, nUp, nErr);
}

static void SetBusy(BOOL busy) {
    g_busy = busy;
    EnableWindow(g_btnScan, !busy);
    EnableWindow(g_btnUpload, !busy);
    EnableWindow(g_btnClear, !busy);
    EnableWindow(g_btnBrowse, !busy);
    EnableWindow(g_edtFolder, !busy);
    EnableWindow(g_chkRecurse, !busy);
    EnableWindow(g_chkPublish, !busy);
}

static int CountUploadable(void) {
    int n = 0;
    for (int i = 0; i < g_fileCount; i++)
        if (g_files[i].status == ST_NEW || g_files[i].status == ST_SAMESIZE) n++;
    return n;
}

/* ========== 扫描 ========== */
static void OnScan(void) {
    if (g_busy) return;
    wchar_t folder[MAX_PATH];
    GetWindowTextW(g_edtFolder, folder, MAX_PATH);
    if (!folder[0]) {
        MessageBoxW(g_hMain, L"请先选择要扫描的文件夹", L"提示", MB_ICONINFORMATION);
        return;
    }
    DWORD attr = GetFileAttributesW(folder);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        MessageBoxW(g_hMain, L"文件夹不存在或无法访问", L"提示", MB_ICONWARNING);
        return;
    }

    SetBusy(TRUE);
    g_recurse = (SendMessageW(g_chkRecurse, BM_GETCHECK, 0, 0) == BST_CHECKED);
    g_fileCount = 0;
    SetProgress(0);

    /* 1. 读取云端病毒库，失败则不继续，避免把重复特征当成新增 */
    SetStatusFmt(L"正在读取云端病毒库...");
    if (!FetchWildlist()) {
        SetStatusFmt(L"读取云端病毒库失败，请检查服务器连接");
        SetBusy(FALSE);
        MessageBoxW(g_hMain, L"无法读取云端病毒库 Wildlist.txt。\n请检查 IPconfig.ini 配置和网络连接后重试。",
                    L"错误", MB_ICONERROR);
        return;
    }
    SetStatusFmt(L"云端病毒库共 %d 条，正在枚举文件...", g_cloudCount);

    /* 2. 枚举文件 */
    ScanDirRec(folder, L"", 0);
    if (g_fileCount == 0) {
        RefillList();
        SetStatusFmt(L"文件夹中没有可处理的文件（空文件已跳过）");
        SetBusy(FALSE);
        return;
    }

    /* 3. 逐个计算 MD5 并对比 */
    LocalBuild(g_fileCount);
    NameIndexBuild(g_fileCount);
    for (int i = 0; i < g_fileCount; i++) {
        FileItem* it = &g_files[i];
        SetStatusFmt(L"正在计算 MD5（%d/%d）：%s", i + 1, g_fileCount, it->rel);
        SetProgress((i + 1) * 1000 / g_fileCount);

        if (!Md5FileW(it->path, it->md5, 33)) {
            it->status = ST_ERROR;
            continue;
        }
        VirusNameFromRel(it->rel, it->vname, MAX_NAME_W + 8);

        int cm = CloudMatch(it->size, it->md5);
        if (cm == 1) {
            it->status = ST_DUPCLOUD;
            continue;
        }
        if (LocalFindOrInsert(i, FALSE) >= 0) {
            it->status = ST_DUPLOCAL;
            continue;
        }
        LocalFindOrInsert(i, TRUE);
        it->status = (cm == -1) ? ST_SAMESIZE : ST_NEW;
        AssignUniqueVName(i);   /* 只给要上传的条目分配唯一病毒名 */
    }

    RefillList();
    UpdateSummary();
    SetProgress(1000);
    SetBusy(FALSE);
}

/* ========== 上传 ==========
   不使用服务端新命令，只用已有的两条管理命令完成一条特征的写入：
     1) addvirus <大小> "<名称>"                  -> 追加 "大小 名称"
     2) editvirus <大小> "<名称>" <大小> "<名称>" "<MD5>"
                                                  -> 把同一行补上 MD5
   （editvirus 原本就支持可选的哈希参数，管理程序的病毒库修改也在用它） */
static BOOL UploadOneFeature(const FileItem* it) {
    char nameu[512], md5u[64], args[2048];

    QuoteArg(it->vname, nameu, sizeof(nameu));
    W2U(it->md5, md5u, sizeof(md5u));

    snprintf(args, sizeof(args), "addvirus %I64u \"%s\"", it->size, nameu);
    args[sizeof(args) - 1] = 0;
    char* resp = AdminTalk(args);
    BOOL ok = RespOk(resp);
    free(resp);
    if (!ok) return FALSE;

    snprintf(args, sizeof(args), "editvirus %I64u \"%s\" %I64u \"%s\" \"%s\"",
             it->size, nameu, it->size, nameu, md5u);
    args[sizeof(args) - 1] = 0;
    resp = AdminTalk(args);
    ok = RespOk(resp);
    free(resp);
    return ok;
}

static BOOL AutoPublishWildlist(int addedCount) {
    size_t vl = 0;
    char* v = ReadServerFile("WildlistVersion.txt", &vl);
    wchar_t cur[64] = L"1.0.1";
    if (v) { if (!ParseVersion(v, cur, 64)) wcscpy(cur, L"1.0.1"); free(v); }
    wchar_t next[64], date[64], desc[160];
    BumpVersion(cur, next, 64);
    TodayStr(date, 64);
    if (addedCount > 0) swprintf(desc, 160, L"批量上传特征 %d 条", addedCount);
    else wcscpy(desc, L"批量上传特征");

    char unext[64], udate[64], udesc[512], args[1024];
    QuoteArg(next, unext, sizeof(unext));
    QuoteArg(date, udate, sizeof(udate));
    QuoteArg(desc, udesc, sizeof(udesc));
    snprintf(args, sizeof(args), "pubwild \"%s\" \"%s\" \"%s\"", unext, udate, udesc);
    args[sizeof(args) - 1] = 0;
    char* resp = AdminTalk(args);
    BOOL ok = RespOk(resp);
    free(resp);
    return ok;
}

static void OnUpload(void) {
    if (g_busy) return;
    if (g_fileCount == 0) {
        MessageBoxW(g_hMain, L"请先扫描文件夹", L"提示", MB_ICONINFORMATION);
        return;
    }
    int n = CountUploadable();
    if (n == 0) {
        MessageBoxW(g_hMain, L"没有需要上传的新文件（全部与云端重复或已上传）", L"提示", MB_ICONINFORMATION);
        return;
    }

    wchar_t msg[768];
    swprintf(msg, 768, L"将把 %d 个文件的特征（大小、MD5、名称）上传到云端病毒库，是否继续？\n\n"
                       L"说明：共需 %d 次请求，文件较多时可能需要几分钟。", n, n * 2);
    if (MessageBoxW(g_hMain, msg, L"批量上传特征", MB_YESNO | MB_ICONQUESTION) != IDYES) return;

    SetBusy(TRUE);
    SetProgress(0);

    int okCount = 0, failCount = 0, done = 0;
    for (int i = 0; i < g_fileCount; i++) {
        FileItem* it = &g_files[i];
        if (it->status != ST_NEW && it->status != ST_SAMESIZE) continue;

        done++;
        SetStatusFmt(L"正在上传特征（%d/%d）：%s", done, n, it->rel);
        SetProgress(done * 1000 / n);

        if (UploadOneFeature(it)) {
            it->status = ST_UPLOADED;
            okCount++;
        } else {
            failCount++;   /* 保持“新增”状态，方便重试 */
        }
        RefillList();
    }

    RefillList();
    UpdateSummary();

    /* 重新读取云端病毒库，核对 MD5 是否真的写进去了 */
    SetStatusFmt(L"正在核对上传结果...");
    int verified = 0, missing = 0;
    BOOL verifiedOk = FALSE;
    if (FetchWildlist()) {
        verifiedOk = TRUE;
        for (int i = 0; i < g_fileCount; i++) {
            if (g_files[i].status != ST_UPLOADED) continue;
            if (CloudMatch(g_files[i].size, g_files[i].md5) == 1) verified++;
            else missing++;
        }
    }

    /* 自动发布新病毒库版本，客户端下次启动才会拉取新库 */
    BOOL pubWanted = (SendMessageW(g_chkPublish, BM_GETCHECK, 0, 0) == BST_CHECKED);
    BOOL pubOk = FALSE;
    if (pubWanted && okCount > 0) {
        SetStatusFmt(L"正在发布新病毒库版本...");
        pubOk = AutoPublishWildlist(okCount);
    }

    SetProgress(1000);
    SetBusy(FALSE);
    SetStatusFmt(L"上传完成：成功 %d 条，失败 %d 条，校验通过 %d 条%s",
                 okCount, failCount, verified,
                 pubWanted ? (pubOk ? L"，病毒库版本已发布" : L"，但病毒库版本发布失败") : L"");

    wchar_t tail[400];
    if (!verifiedOk) {
        wcscpy(tail, L"上传后无法重新读取云端病毒库，未能核对 MD5。");
    } else if (missing > 0) {
        swprintf(tail, 400,
                 L"有 %d 条记录在云端找不到对应 MD5。\n可能原因：服务器上的 server.php 版本较旧，"
                 L"editvirus 不支持哈希参数。请用管理程序确认病毒库内容。", missing);
    } else if (failCount > 0) {
        wcscpy(tail, L"部分条目上传失败，可重新点击“上传新增特征”重试。");
    } else {
        wcscpy(tail, L"全部条目已写入云端病毒库。");
    }

    wchar_t pubTail[200];
    if (!pubWanted) {
        wcscpy(pubTail, L"\n\n注意：未发布新病毒库版本，客户端不会自动更新病毒库，请到管理程序里发布病毒库。");
    } else if (pubOk) {
        wcscpy(pubTail, L"\n\n病毒库版本号已升一位并发布，客户端下次启动即可自动更新。");
    } else {
        wcscpy(pubTail, L"\n\n病毒库版本发布失败，请到管理程序里手动发布病毒库。");
    }

    swprintf(msg, 768, L"上传完成。\n\n成功 %d 条，失败 %d 条，校验通过 %d 条。\n%s%s",
             okCount, failCount, verified, tail, pubTail);
    MessageBoxW(g_hMain, msg,
                (missing > 0 || failCount > 0) ? L"部分完成" : L"完成",
                (missing > 0 || failCount > 0) ? MB_ICONWARNING : MB_ICONINFORMATION);
}

static void OnClear(void) {
    if (g_busy) return;
    g_fileCount = 0;
    SendMessageW(g_lstFiles, LVM_DELETEALLITEMS, 0, 0);
    SetProgress(0);
    SetStatusFmt(L"已清空列表");
}

/* ========== 登录对话框 ========== */
static LRESULT CALLBACK LoginProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        MkStatic(hwnd, L"管理密码：", 20, 22, 90, 22, 0);
        MkEdit(hwnd, ID_EDT_PWD, 110, 20, 240, 26, ES_PASSWORD);
        MkButton(hwnd, ID_BTN_LOGIN_OK, L"登录", 110, 66, 90, 28);
        MkButton(hwnd, ID_BTN_LOGIN_NO, L"退出", 230, 66, 90, 28);
        return 0;
    case WM_COMMAND:
        if (LOWORD(w) == ID_BTN_LOGIN_OK) {
            wchar_t pwd[256];
            GetWindowTextW(GetDlgItem(hwnd, ID_EDT_PWD), pwd, 256);
            if (!pwd[0]) {
                MessageBoxW(hwnd, L"请输入管理密码", L"提示", MB_ICONWARNING);
                return 0;
            }
            W2U(pwd, g_pwd, sizeof(g_pwd));
            SetWindowTextW(GetDlgItem(hwnd, ID_BTN_LOGIN_OK), L"正在登录...");
            EnableWindow(GetDlgItem(hwnd, ID_BTN_LOGIN_OK), FALSE);
            PumpMessages();

            char* resp = AdminTalk("check");
            if (!resp) {
                g_pwd[0] = 0;
                MessageBoxW(hwnd, L"无法连接服务器。\n请检查 IPconfig.ini 中的地址和端口。",
                            L"连接失败", MB_ICONERROR);
            } else if (!RespOk(resp)) {
                g_pwd[0] = 0;
                MessageBoxW(hwnd, L"管理密码错误", L"提示", MB_ICONWARNING);
            } else {
                g_loginOk = TRUE;
                free(resp);
                DestroyWindow(hwnd);
                return 0;
            }
            free(resp);
            SetWindowTextW(GetDlgItem(hwnd, ID_BTN_LOGIN_OK), L"登录");
            EnableWindow(GetDlgItem(hwnd, ID_BTN_LOGIN_OK), TRUE);
        } else if (LOWORD(w) == ID_BTN_LOGIN_NO) {
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_modalDone = TRUE; return 0;
    case WM_CTLCOLORSTATIC: SetBkMode((HDC)w, TRANSPARENT); return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static BOOL AskLogin(void) {
    g_loginOk = FALSE;
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = LoginProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BatchUploadLogin";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BatchUploadLogin", L"批量上传程序 - 登录",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 380, 145, NULL, NULL, wc.hInstance, NULL);
    CenterWindow(dlg, 380, 145);
    RunModal(NULL, dlg);
    return g_loginOk;
}

/* ========== 主窗口 ========== */
#define WM_APP_SHOW_MAIN (WM_APP + 1)

static void CreateListColumns(HWND lst) {
    const wchar_t* titles[] = { L"文件名", L"大小（字节）", L"MD5", L"状态", L"病毒名" };
    int widths[] = { 300, 110, 230, 190, 130 };
    for (int i = 0; i < 5; i++) {
        LVCOLUMNW c = {0};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = (LPWSTR)titles[i];
        c.cx = widths[i];
        c.iSubItem = i;
        SendMessageW(lst, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
    }
}

static void OnChooseFolder(void) {
    if (g_busy) return;
    BROWSEINFOW bi = {0};
    bi.hwndOwner = g_hMain;
    bi.lpszTitle = L"选择要批量上传特征的文件夹";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    wchar_t path[MAX_PATH];
    if (SHGetPathFromIDListW(pidl, path)) SetWindowTextW(g_edtFolder, path);
    CoTaskMemFree(pidl);
}

static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        g_hMain = hwnd;
        MkStatic(hwnd, L"文件夹：", 20, 22, 70, 22, 0);
        g_edtFolder = MkEdit(hwnd, ID_EDT_FOLDER, 90, 18, 680, 26, 0);
        g_btnBrowse = MkButton(hwnd, ID_BTN_BROWSE, L"浏览...", 782, 18, 90, 26);
        g_chkRecurse = MkCheck(hwnd, ID_CHK_RECURSE, L"包含子文件夹", 20, 54, 130, 24, TRUE);
        g_chkPublish = MkCheck(hwnd, ID_CHK_PUBLISH, L"上传后自动发布新病毒库版本（推荐）", 165, 54, 330, 24, TRUE);
        g_btnScan = MkButton(hwnd, ID_BTN_SCAN, L"扫描文件夹", 540, 50, 100, 30);
        g_btnUpload = MkButton(hwnd, ID_BTN_UPLOAD, L"上传新增特征", 650, 50, 120, 30);
        g_btnClear = MkButton(hwnd, ID_BTN_CLEAR, L"清空", 780, 50, 92, 30);

        g_lstFiles = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            20, 90, 852, 430, hwnd, (HMENU)ID_LST_FILES, NULL, NULL);
        SendMessageW(g_lstFiles, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
        SendMessageW(g_lstFiles, LVM_SETEXTENDEDLISTVIEWSTYLE,
                     LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES,
                     LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        CreateListColumns(g_lstFiles);

        g_prog = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 20, 528, 852, 18, hwnd, (HMENU)ID_PROGRESS, NULL, NULL);
        SendMessageW(g_prog, PBM_SETRANGE32, 0, 1000);

        g_lblStatus = MkStatic(hwnd, L"请选择文件夹后点击“扫描文件夹”。扫描会计算每个文件的 MD5 并与云端病毒库对比。",
                               20, 552, 852, 22, ID_LBL_STATUS);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(w)) {
        case ID_BTN_BROWSE: OnChooseFolder(); return 0;
        case ID_BTN_SCAN:   OnScan(); return 0;
        case ID_BTN_UPLOAD: OnUpload(); return 0;
        case ID_BTN_CLEAR:  OnClear(); return 0;
        }
        return 0;

    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)w, TRANSPARENT);
        return (LRESULT)GetStockObject(WHITE_BRUSH);

    case WM_CLOSE:
        if (g_busy) return 0;   /* 正在扫描/上传时不允许关闭，避免数据竞争 */
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR cmd, int show) {
    (void)hPrev; (void)cmd;

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    g_fontBody = MakeFont(17, FW_NORMAL);

    if (!LoadServerCfg(&g_cfg)) {
        MessageBoxW(NULL, L"读取 IPconfig.ini 失败。\n请在程序同目录创建：\n\nserver_ip=152.136.44.200\nserver_port=28586",
                    L"批量上传程序", MB_ICONERROR);
        return 1;
    }

    /* 先创建主窗口（隐藏），登录成功后再显示，登录框以主窗口为父级居中 */
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainProc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BatchUploadMain";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);

    int W = 900, H = 620;
    int x = (GetSystemMetrics(SM_CXSCREEN) - W) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - H) / 2;
    HWND mainWnd = CreateWindowExW(0, L"BatchUploadMain", L"BDProtect 批量特征上传工具",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        x, y, W, H, NULL, NULL, hInst, NULL);
    if (!mainWnd) return 1;

    if (!AskLogin()) {
        DestroyWindow(mainWnd);
        return 0;
    }

    ShowWindow(mainWnd, show);
    UpdateWindow(mainWnd);
    SetForegroundWindow(mainWnd);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    FreeCloud();
    free(g_files);
    free(g_localTab);
    CoUninitialize();
    return 0;
}
