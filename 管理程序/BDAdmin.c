/*
 * BDAdmin - BDProtect 管理程序
 *
 * 功能：
 *   1. 启动后要求输入管理密码，与服务器 data/admin_password.txt 对比（服务器无此文件时自动创建为 admin）
 *   2. 审核用户上传的病毒样本：下载样本 / 同意该样本（写入病毒库并删除样本）/ 不同意该样本（仅删除样本）
 *   3. 发布新的病毒库（二次确认后服务器 WildlistVersion.txt 版本号升一位）
 *   4. 发布新的程序（选择 .exe，填写发布版本/更改内容/发布时间，均有缺省规则）
 *   5. 修改管理密码
 *   6. 查看病毒库数据，双击一条可 修改（病毒名/大小）/ 删除
 *   7. 实用工具箱管理：新增工具（可上传 exe）、修改名称/说明/文件名、删除、上移/下移排序
 *
 * 服务器配置读取 exe 同目录 IPconfig.ini：
 *   server_ip=back1.idcfengye.com
 *   server_port=28586
 */
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>

/* ========== 控件 ID ========== */
#define ID_EDT_LOGIN_PWD   1301
#define ID_BTN_LOGIN       1302

#define ID_BTN_PUBWILD     1001
#define ID_BTN_PUBAPP      1002
#define ID_BTN_PWD         1003
#define ID_BTN_REFRESH     1004
#define ID_BTN_TOOLS       1005
#define ID_LST_SAMPLES     1101
#define ID_LST_WILD        1102
#define ID_LST_TOOLS       1103
#define ID_BTN_DL          1201
#define ID_BTN_ACCEPT      1202
#define ID_BTN_REJECT      1203
#define ID_STATIC_INFO     1401

#define IDOK_SAFE          IDOK
#define IDCANCEL_SAFE      IDCANCEL

#define IDC_EDIT_DELETE    2003

/* ========== 全局状态 ========== */
typedef struct { char host[256]; int port; } ServerCfg;
static ServerCfg g_cfg;
static char g_pwd[256] = {0};          /* 当前管理密码（UTF-8） */
static wchar_t g_verWild[64] = L"?";
static wchar_t g_verApp[64]  = L"?";

typedef struct { wchar_t name[128]; unsigned long long size; wchar_t time[48]; } SampleItem;
typedef struct { unsigned long long size; wchar_t hash[33]; wchar_t name[128]; } WildItem;
static SampleItem g_samples[512]; static int g_sampleCount = 0;
static WildItem   g_wild[2048];    static int g_wildCount = 0;

static HWND g_hMain = NULL;
static HWND g_lblInfo = NULL, g_lstSamples = NULL, g_lstWild = NULL;

static HFONT g_fontBody = NULL, g_fontBold = NULL;
static BOOL  g_modalDone = FALSE;

static HFONT MakeFont(int px, int weight) {
    return CreateFontW(-px, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
}

static void PumpMessages(void) {
    MSG m;
    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
}

/* 可重入的分词（MinGW 的 wcstok 只有两参数版本） */
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
/* 转为可放入引号参数的 UTF-8 文本（去掉引号/换行） */
static void QuoteArg(const wchar_t* w, char* out, int cap) {
    W2U(w, out, cap);
    for (char* p = out; *p; p++) {
        if (*p == '"' || *p == '\r' || *p == '\n' || *p == '\t') *p = '_';
    }
}

/* ========== 网络客户端 ========== */
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
            /* 所有连接统一设置读写超时，避免服务器无响应时界面卡死 */
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

/* 读取全部数据直到服务器关闭连接 */
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

/* 通过 read 命令读取服务器文本文件，返回 malloc 的缓冲区 */
static char* ReadServerFile(const char* name, size_t* outLen) {
    SOCKET s;
    if (!ConnectServer(&g_cfg, &s)) return NULL;
    char req[512];
    sprintf(req, "read %s\r\n", name);
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

/* 计算 SHA-256，输出小写十六进制（用于认证证明，密码不直接上网） */
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

/* ========== 认证：挑战-应答 ==========
   1) 连接后发送 hello，服务器返回一次性随机数
   2) 发送 admin <随机数> sha256(随机数+密码) <子命令> ...
   密码本身从不在网络上传输。 */
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

/* 在已认证的 socket 上发送一条管理命令（不含数据体） */
static BOOL AdminWriteCmd(SOCKET s, const char* args) {
    char payload[1024], proof[65], cmd[4096];
    snprintf(payload, sizeof(payload), "%s%s", g_nonce, g_pwd);
    if (!Sha256Hex(payload, (int)strlen(payload), proof, sizeof(proof))) return FALSE;
    snprintf(cmd, sizeof(cmd), "admin %s %s %s\r\n", g_nonce, proof, args);
    cmd[sizeof(cmd) - 1] = 0;
    return send(s, cmd, (int)strlen(cmd), 0) > 0;
}

/* 发送一条管理命令，读取全部文本响应。返回 NULL 表示连接失败 */
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
/* 从版本文件内容解析 "Version: a.b.c" */
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

/* 版本号升一位：1.0.1->1.0.2，1.0.9->1.1.1 */
static void BumpVersion(const wchar_t* cur, wchar_t* out, int cap) {
    int a = 1, b = 0, c = 0;
    swscanf(cur, L"%d.%d.%d", &a, &b, &c);
    if (c < 9) c++;
    else { c = 1; b++; }
    swprintf(out, cap, L"%d.%d.%d", a, b, c);
}

/* 版本号必须是 a.b.c（每段 1-4 位数字），防止把随意文本写进版本文件 */
static BOOL ValidVersion(const wchar_t* v) {
    int a = 0, b = 0, c = 0, n = 0;
    if (swscanf(v, L"%4d.%4d.%4d%n", &a, &b, &c, &n) != 3) return FALSE;
    if (n != (int)wcslen(v)) return FALSE;
    return a >= 0 && b >= 0 && c >= 0;
}

static void TodayStr(wchar_t* out, int cap) {
    time_t t = time(NULL);
    struct tm* tmv = localtime(&t);
    swprintf(out, cap, L"%04d-%02d-%02d", tmv->tm_year + 1900, tmv->tm_mon + 1, tmv->tm_mday);
}

/* ========== 进度窗口 ========== */
typedef struct { HWND hwnd, lbl, bar; } DLWIN;

static LRESULT CALLBACK DLProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_CTLCOLORSTATIC) {
        SetBkMode((HDC)w, TRANSPARENT);
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static void CreateProgressWindow(DLWIN* d, const wchar_t* title) {
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DLProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminProgressCls";
    RegisterClassExW(&wc);
    int w = 420, h = 140;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    d->hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"BDAdminProgressCls", title,
        WS_POPUP | WS_CAPTION, x, y, w, h, NULL, NULL, wc.hInstance, NULL);
    d->lbl = CreateWindowW(L"STATIC", L"正在连接服务器...", WS_CHILD | WS_VISIBLE | SS_LEFT,
                           20, 18, 380, 20, d->hwnd, NULL, NULL, NULL);
    SendMessageW(d->lbl, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
    d->bar = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                             20, 48, 380, 22, d->hwnd, NULL, NULL, NULL);
    SendMessageW(d->bar, PBM_SETRANGE32, 0, 1000);
    ShowWindow(d->hwnd, SW_SHOW);
    UpdateWindow(d->hwnd);
}

static void SetProgressText(DLWIN* d, const wchar_t* text, int permille) {
    if (!IsWindow(d->hwnd)) return;
    SetWindowTextW(d->lbl, text);
    SendMessageW(d->bar, PBM_SETPOS, permille, 0);
    PumpMessages();
}

/* ========== 服务器操作 ========== */

/* 拉取样本列表（admin samples） */
static BOOL FetchSamples(void) {
    char* resp = AdminTalk("samples");
    if (!RespOk(resp)) { free(resp); return FALSE; }
    wchar_t* wresp = (wchar_t*)malloc((strlen(resp) + 1) * sizeof(wchar_t));
    if (!wresp) { free(resp); return FALSE; }
    U2W(resp, wresp, (int)strlen(resp) + 1);
    free(resp);

    g_sampleCount = 0;
    wchar_t* save = NULL;
    wchar_t* line = WTok(wresp, L"\n", &save);
    while (line && g_sampleCount < 512) {
        if (line[0] == L'O' && line[1] == L'K') { line = WTok(NULL, L"\n", &save); continue; }
        /* 格式: 名称\t大小\t时间 */
        wchar_t* t1 = wcschr(line, L'\t');
        if (t1) {
            *t1 = 0;
            wchar_t* t2 = wcschr(t1 + 1, L'\t');
            if (t2) {
                *t2 = 0;
                SampleItem* it = &g_samples[g_sampleCount];
                wcsncpy(it->name, line, 127); it->name[127] = 0;
                it->size = _wcstoui64(t1 + 1, NULL, 10);
                wcsncpy(it->time, t2 + 1, 47); it->time[47] = 0;
                size_t l = wcslen(it->time);
                while (l > 0 && (it->time[l-1] == L'\r' || it->time[l-1] == L'\n')) it->time[--l] = 0;
                g_sampleCount++;
            }
        }
        line = WTok(NULL, L"\n", &save);
    }
    free(wresp);
    return TRUE;
}

/* 拉取病毒库（read Wildlist.txt） */
static BOOL FetchWildlist(void) {
    size_t len = 0;
    char* resp = ReadServerFile("Wildlist.txt", &len);
    if (!resp) return FALSE;
    wchar_t* wresp = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    if (!wresp) { free(resp); return FALSE; }
    U2W(resp, wresp, (int)len + 1);
    free(resp);

    g_wildCount = 0;
    wchar_t* save = NULL;
    wchar_t* line = WTok(wresp, L"\n", &save);
    while (line && g_wildCount < 2048) {
        wchar_t* p = line;
        while (*p == L' ' || *p == L'\t') p++;
        if (*p && *p != L'#' && *p != L';') {
            wchar_t* end = NULL;
            unsigned long long sz = _wcstoui64(p, &end, 10);
            if (end != p) {
                while (*end == L' ' || *end == L'\t') end++;
                /* 第二段是 32 位十六进制时视为 MD5 哈希（新格式：大小 哈希 病毒名） */
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
                if (isHash) {
                    while (*end == L' ' || *end == L'\t') end++;
                } else {
                    end -= ti;   /* 不是哈希，退回名字起点 */
                }
                size_t l = wcslen(end);
                while (l > 0 && (end[l-1] == L'\r' || end[l-1] == L'\n')) end[--l] = 0;
                if (*end) {
                    WildItem* it = &g_wild[g_wildCount];
                    it->size = sz;
                    if (isHash) { wcsncpy(it->hash, token, 32); it->hash[32] = 0; }
                    else it->hash[0] = 0;
                    wcsncpy(it->name, end, 127);
                    it->name[127] = 0;
                    g_wildCount++;
                }
            }
        }
        line = WTok(NULL, L"\n", &save);
    }
    free(wresp);
    return TRUE;
}

static void FetchVersions(void) {
    size_t len;
    char* v = ReadServerFile("WildlistVersion.txt", &len);
    if (v) { if (!ParseVersion(v, g_verWild, 64)) wcscpy(g_verWild, L"?"); free(v); }
    else wcscpy(g_verWild, L"读取失败");
    v = ReadServerFile("BDProtectVersion.txt", &len);
    if (v) { if (!ParseVersion(v, g_verApp, 64)) wcscpy(g_verApp, L"?"); free(v); }
    else wcscpy(g_verApp, L"读取失败");
}

/* 下载样本到本地文件 */
static BOOL DownloadSample(const SampleItem* it, const wchar_t* dest) {
    SOCKET s;
    if (!AdminConnect(&s)) return FALSE;
    char uname[512], args[600];
    QuoteArg(it->name, uname, sizeof(uname));
    snprintf(args, sizeof(args), "getsample \"%s\"", uname);
    args[sizeof(args) - 1] = 0;
    if (!AdminWriteCmd(s, args)) { closesocket(s); return FALSE; }

    char line[256];
    if (!RecvLine(s, line, sizeof(line)) || strncmp(line, "OK", 2) != 0) { closesocket(s); return FALSE; }
    char* p = line + 2; while (*p == ' ') p++;
    unsigned long long size = _strtoui64(p, NULL, 10);

    DLWIN d;
    CreateProgressWindow(&d, L"下载样本");
    wchar_t msg[256];
    swprintf(msg, 256, L"正在下载样本 %s ...", it->name);
    SetProgressText(&d, msg, 0);

    HANDLE hFile = CreateFileW(dest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { DestroyWindow(d.hwnd); closesocket(s); return FALSE; }

    char buf[8192];
    unsigned long long got = 0;
    BOOL ok = TRUE;
    while (got < size) {
        int want = (int)((size - got > sizeof(buf)) ? sizeof(buf) : (size - got));
        int r = recv(s, buf, want, 0);
        if (r <= 0) { ok = FALSE; break; }
        DWORD written = 0;
        WriteFile(hFile, buf, r, &written, NULL);
        got += r;
        int permille = size ? (int)(got * 1000 / size) : 0;
        swprintf(msg, 256, L"正在下载样本 %s ... %d%%", it->name, permille / 10);
        SetProgressText(&d, msg, permille);
    }
    CloseHandle(hFile);
    closesocket(s);
    Sleep(200);
    DestroyWindow(d.hwnd);
    return ok && got == size;
}

/* 上传新安装包并发布（admin pubapp） */
static BOOL UploadApp(const wchar_t* path, const wchar_t* ver, const wchar_t* date, const wchar_t* desc) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER li; GetFileSizeEx(hFile, &li);
    unsigned long long size = (unsigned long long)li.QuadPart;

    SOCKET s;
    if (!AdminConnect(&s)) { CloseHandle(hFile); return FALSE; }

    char uver[128], udate[128], udesc[512];
    QuoteArg(ver, uver, sizeof(uver));
    QuoteArg(date, udate, sizeof(udate));
    QuoteArg(desc, udesc, sizeof(udesc));

    char args[1024];
    snprintf(args, sizeof(args), "pubapp %llu \"%s\" \"%s\" \"%s\"", size, uver, udate, udesc);
    args[sizeof(args) - 1] = 0;
    if (!AdminWriteCmd(s, args)) { CloseHandle(hFile); closesocket(s); return FALSE; }

    DLWIN d;
    CreateProgressWindow(&d, L"发布新程序");
    wchar_t msg[256];
    SetProgressText(&d, L"正在上传安装包...", 0);

    char buf[8192];
    DWORD r = 0;
    unsigned long long sentTotal = 0;
    BOOL ok = TRUE;
    while (ReadFile(hFile, buf, sizeof(buf), &r, NULL) && r > 0) {
        int sent = 0;
        while (sent < (int)r) {
            int n = send(s, buf + sent, (int)r - sent, 0);
            if (n <= 0) { ok = FALSE; break; }
            sent += n;
        }
        if (!ok) break;
        sentTotal += r;
        int permille = size ? (int)(sentTotal * 1000 / size) : 0;
        swprintf(msg, 256, L"正在上传安装包... %d%%", permille / 10);
        SetProgressText(&d, msg, permille);
    }
    CloseHandle(hFile);

    if (ok) {
        SetProgressText(&d, L"等待服务器确认...", 1000);
        char resp[128] = {0};
        int n = recv(s, resp, sizeof(resp) - 1, 0);
        ok = (n > 0 && strncmp(resp, "OK", 2) == 0);
    }
    closesocket(s);
    Sleep(200);
    DestroyWindow(d.hwnd);
    return ok;
}

/* ========== 通用模态窗口 ========== */
static void CenterWindow(HWND hwnd, int w, int h) {
    RECT rc;
    if (g_hMain && IsWindow(g_hMain)) GetWindowRect(g_hMain, &rc);
    else { rc.left = 0; rc.top = 0; rc.right = GetSystemMetrics(SM_CXSCREEN); rc.bottom = GetSystemMetrics(SM_CYSCREEN); }
    int x = rc.left + ((rc.right - rc.left) - w) / 2;
    int y = rc.top + ((rc.bottom - rc.top) - h) / 2;
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

static HWND MkStatic(HWND p, const wchar_t* t, int x, int y, int w, int h) {
    HWND c = CreateWindowW(L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT, x, y, w, h, p, NULL, NULL, NULL);
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
    g_modalDone = FALSE;   /* 支持对话框内再打开对话框（嵌套模态） */
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

/* ========== 修改密码对话框 ========== */
static BOOL  g_pwdDlgOk = FALSE;
static wchar_t g_pwdDlgNew[128] = {0};

static LRESULT CALLBACK PwdDlgProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        MkStatic(hwnd, L"新密码：", 20, 20, 80, 22);
        MkEdit(hwnd, 101, 110, 18, 220, 24, ES_PASSWORD);
        MkStatic(hwnd, L"确认新密码：", 20, 54, 90, 22);
        MkEdit(hwnd, 102, 110, 52, 220, 24, ES_PASSWORD);
        MkButton(hwnd, IDOK, L"确定", 90, 92, 90, 28);
        MkButton(hwnd, IDCANCEL, L"取消", 200, 92, 90, 28);
        return 0;
    case WM_COMMAND:
        if (LOWORD(w) == IDOK) {
            wchar_t p1[128], p2[128];
            GetWindowTextW(GetDlgItem(hwnd, 101), p1, 128);
            GetWindowTextW(GetDlgItem(hwnd, 102), p2, 128);
            if (!p1[0]) { MessageBoxW(hwnd, L"新密码不能为空", L"提示", MB_ICONWARNING); return 0; }
            if (wcscmp(p1, p2) != 0) { MessageBoxW(hwnd, L"两次输入的密码不一致", L"提示", MB_ICONWARNING); return 0; }
            if (wcschr(p1, L'"')) { MessageBoxW(hwnd, L"密码不能包含引号", L"提示", MB_ICONWARNING); return 0; }
            wcsncpy(g_pwdDlgNew, p1, 127); g_pwdDlgNew[127] = 0;
            g_pwdDlgOk = TRUE;
            DestroyWindow(hwnd);
        } else if (LOWORD(w) == IDCANCEL) {
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_modalDone = TRUE; return 0;
    case WM_CTLCOLORSTATIC: SetBkMode((HDC)w, TRANSPARENT); return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static BOOL AskNewPassword(void) {
    g_pwdDlgOk = FALSE;
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = PwdDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminPwdDlg";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BDAdminPwdDlg", L"修改管理密码",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 370, 165, g_hMain, NULL, wc.hInstance, NULL);
    CenterWindow(dlg, 370, 165);
    RunModal(g_hMain, dlg);
    return g_pwdDlgOk;
}

/* ========== 发布新程序对话框 ========== */
static BOOL  g_pubOk = FALSE;
static wchar_t g_pubVer[64] = {0}, g_pubDesc[512] = {0}, g_pubDate[64] = {0};
static wchar_t g_pubNextVer[64] = L"";

static LRESULT CALLBACK PubDlgProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE: {
        wchar_t hint[256];
        swprintf(hint, 256, L"发布版本（留空则自动升为 V%s）：", g_pubNextVer);
        MkStatic(hwnd, hint, 20, 16, 330, 22);
        MkEdit(hwnd, 101, 20, 40, 330, 24, 0);
        MkStatic(hwnd, L"更改内容（留空则记录“修改已知问题”）：", 20, 74, 330, 22);
        MkEdit(hwnd, 102, 20, 98, 330, 24, 0);
        wchar_t today[64]; TodayStr(today, 64);
        swprintf(hint, 256, L"发布时间（留空则记录当日时间 %s）：", today);
        MkStatic(hwnd, hint, 20, 132, 360, 22);
        MkEdit(hwnd, 103, 20, 156, 330, 24, 0);
        MkButton(hwnd, IDOK, L"确定发布", 110, 196, 90, 28);
        MkButton(hwnd, IDCANCEL, L"取消", 220, 196, 90, 28);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDOK) {
            GetWindowTextW(GetDlgItem(hwnd, 101), g_pubVer, 64);
            GetWindowTextW(GetDlgItem(hwnd, 102), g_pubDesc, 512);
            GetWindowTextW(GetDlgItem(hwnd, 103), g_pubDate, 64);
            if (g_pubVer[0] && !ValidVersion(g_pubVer)) {
                MessageBoxW(hwnd, L"发布版本格式不正确，应为 a.b.c（例如 1.0.2）", L"提示", MB_ICONWARNING);
                return 0;
            }
            g_pubOk = TRUE;
            DestroyWindow(hwnd);
        } else if (LOWORD(w) == IDCANCEL) {
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_modalDone = TRUE; return 0;
    case WM_CTLCOLORSTATIC: SetBkMode((HDC)w, TRANSPARENT); return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static BOOL AskPublishInfo(const wchar_t* nextVer) {
    g_pubOk = FALSE;
    g_pubVer[0] = 0; g_pubDesc[0] = 0; g_pubDate[0] = 0;
    wcsncpy(g_pubNextVer, nextVer, 63); g_pubNextVer[63] = 0;
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = PubDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminPubDlg";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BDAdminPubDlg", L"发布新程序",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 380, 270, g_hMain, NULL, wc.hInstance, NULL);
    CenterWindow(dlg, 380, 270);
    RunModal(g_hMain, dlg);
    return g_pubOk;
}

/* ========== 病毒库条目编辑对话框 ========== */
static int  g_editResult = 0; /* 0=取消 1=保存 2=删除 */
static wchar_t g_editSize[32] = {0}, g_editName[128] = {0}, g_editHash[33] = {0};

static LRESULT CALLBACK EditDlgProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        MkStatic(hwnd, L"文件大小（字节）：", 20, 16, 200, 22);
        MkEdit(hwnd, 101, 20, 40, 300, 24, 0);
        SetWindowTextW(GetDlgItem(hwnd, 101), g_editSize);
        MkStatic(hwnd, L"MD5 哈希（32 位十六进制，留空则只按大小匹配）：", 20, 74, 340, 22);
        MkEdit(hwnd, 103, 20, 98, 330, 24, 0);
        SetWindowTextW(GetDlgItem(hwnd, 103), g_editHash);
        MkStatic(hwnd, L"病毒名：", 20, 132, 200, 22);
        MkEdit(hwnd, 102, 20, 156, 330, 24, 0);
        SetWindowTextW(GetDlgItem(hwnd, 102), g_editName);
        MkButton(hwnd, IDOK, L"保存修改", 20, 198, 90, 28);
        MkButton(hwnd, IDC_EDIT_DELETE, L"删除该条", 125, 198, 90, 28);
        MkButton(hwnd, IDCANCEL, L"取消", 230, 198, 90, 28);
        return 0;
    case WM_COMMAND:
        if (LOWORD(w) == IDOK) {
            wchar_t sz[32], nm[128], hs[64];
            GetWindowTextW(GetDlgItem(hwnd, 101), sz, 32);
            GetWindowTextW(GetDlgItem(hwnd, 102), nm, 128);
            GetWindowTextW(GetDlgItem(hwnd, 103), hs, 64);
            wchar_t* end = NULL;
            unsigned long long v = _wcstoui64(sz, &end, 10);
            if (end == sz || v == 0) { MessageBoxW(hwnd, L"大小必须是大于 0 的数字", L"提示", MB_ICONWARNING); return 0; }
            if (!nm[0]) { MessageBoxW(hwnd, L"病毒名不能为空", L"提示", MB_ICONWARNING); return 0; }
            /* 哈希必须为空或 32 位十六进制 */
            size_t hl = wcslen(hs);
            if (hl != 0 && hl != 32) {
                MessageBoxW(hwnd, L"MD5 哈希必须是 32 位十六进制，或留空", L"提示", MB_ICONWARNING);
                return 0;
            }
            for (size_t k = 0; k < hl; k++) {
                wchar_t c = hs[k];
                if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))) {
                    MessageBoxW(hwnd, L"MD5 哈希只能包含 0-9 / a-f", L"提示", MB_ICONWARNING);
                    return 0;
                }
            }
            wcsncpy(g_editSize, sz, 31); g_editSize[31] = 0;
            wcsncpy(g_editName, nm, 127); g_editName[127] = 0;
            wcsncpy(g_editHash, hs, 32); g_editHash[32] = 0;
            g_editResult = 1;
            DestroyWindow(hwnd);
        } else if (LOWORD(w) == IDC_EDIT_DELETE) {
            g_editResult = 2;
            DestroyWindow(hwnd);
        } else if (LOWORD(w) == IDCANCEL) {
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_modalDone = TRUE; return 0;
    case WM_CTLCOLORSTATIC: SetBkMode((HDC)w, TRANSPARENT); return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static int AskEditVirus(const wchar_t* size, const wchar_t* name, const wchar_t* hash) {
    g_editResult = 0;
    wcsncpy(g_editSize, size, 31); g_editSize[31] = 0;
    wcsncpy(g_editName, name, 127); g_editName[127] = 0;
    wcsncpy(g_editHash, hash ? hash : L"", 32); g_editHash[32] = 0;
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = EditDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminEditDlg";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BDAdminEditDlg", L"病毒库条目 - 修改/删除",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 390, 275, g_hMain, NULL, wc.hInstance, NULL);
    CenterWindow(dlg, 390, 275);
    RunModal(g_hMain, dlg);
    return g_editResult;
}

/* ========== 主窗口刷新 ========== */
static void DoRefresh(HWND hwnd) {
    wchar_t buf[512];
    SetWindowTextW(g_lblInfo, L"正在连接服务器...");
    PumpMessages();

    FetchVersions();
    BOOL okS = FetchSamples();
    BOOL okW = FetchWildlist();

    swprintf(buf, 512, L"服务器：%S:%d      病毒库版本：V%s      程序版本：V%s      待审核样本：%d 条      病毒库：%d 条",
             g_cfg.host, g_cfg.port, g_verWild, g_verApp, okS ? g_sampleCount : -1, okW ? g_wildCount : -1);
    if (!okS || !okW) {
        wchar_t tmp[600];
        swprintf(tmp, 600, L"%s（部分数据读取失败，请检查服务器）", buf);
        wcscpy(buf, tmp);
    }
    SetWindowTextW(g_lblInfo, buf);

    SendMessageW(g_lstSamples, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_sampleCount; i++) {
        swprintf(buf, 512, L"%s | %llu 字节 | %s", g_samples[i].time, g_samples[i].size, g_samples[i].name);
        SendMessageW(g_lstSamples, LB_ADDSTRING, 0, (LPARAM)buf);
    }
    SendMessageW(g_lstWild, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_wildCount; i++) {
        swprintf(buf, 512, L"%llu | %s | %s", g_wild[i].size,
                 g_wild[i].hash[0] ? g_wild[i].hash : L"（无哈希，仅按大小匹配）",
                 g_wild[i].name);
        SendMessageW(g_lstWild, LB_ADDSTRING, 0, (LPARAM)buf);
    }
}

/* ========== 主窗口命令处理 ========== */
static int SelectedSample(void) {
    int sel = (int)SendMessageW(g_lstSamples, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= g_sampleCount) {
        MessageBoxW(g_hMain, L"请先在列表中选择一条样本", L"提示", MB_ICONINFORMATION);
        return -1;
    }
    return sel;
}

static void OnDownloadSample(void) {
    int sel = SelectedSample();
    if (sel < 0) return;
    SampleItem* it = &g_samples[sel];

    /* 保持样本原来的扩展名（test.bat 就下载成 test.bat）；
       只有样本名本身没有扩展名时才补 .exe */
    wchar_t defName[160];
    const wchar_t* dot = wcsrchr(it->name, L'.');
    BOOL hasExt = dot && dot != it->name && dot[1] != 0;
    if (hasExt) swprintf(defName, 160, L"%s", it->name);
    else swprintf(defName, 160, L"%s.exe", it->name);
    wchar_t path[MAX_PATH] = {0};
    wcsncpy(path, defName, MAX_PATH - 1);

    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMain;
    ofn.lpstrFilter = L"所有文件 (*.*)\0*.*\0可执行文件 (*.exe)\0*.exe\0批处理文件 (*.bat)\0*.bat\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"下载样本到...";
    /* 不加 OFN_EXTENSIONDIFFERENT 检查，默认名已带原扩展名 */
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return;

    if (DownloadSample(it, path))
        MessageBoxW(g_hMain, L"样本下载完成", L"提示", MB_ICONINFORMATION);
    else
        MessageBoxW(g_hMain, L"样本下载失败（网络错误或服务器上不存在）", L"错误", MB_ICONERROR);
}

static void OnAcceptSample(void) {
    int sel = SelectedSample();
    if (sel < 0) return;
    SampleItem* it = &g_samples[sel];
    wchar_t msg[512];
    swprintf(msg, 512, L"同意该样本「%s」？\n\n将把 大小=%llu 写入病毒库，并删除服务器上的样本文件。", it->name, it->size);
    if (MessageBoxW(g_hMain, msg, L"同意该样本", MB_YESNO | MB_ICONQUESTION) != IDYES) return;

    char uname[512], args[2048];
    QuoteArg(it->name, uname, sizeof(uname));
    /* 附带样本名：服务器据此计算 MD5 写入病毒库，实现大小 + 哈希双重校验 */
    snprintf(args, sizeof(args), "addvirus %llu \"%s\" \"%s\"", it->size, uname, uname);
    args[sizeof(args) - 1] = 0;
    char* resp = AdminTalk(args);
    if (!RespOk(resp)) {
        free(resp);
        MessageBoxW(g_hMain, L"写入病毒库失败", L"错误", MB_ICONERROR);
        return;
    }
    free(resp);
    snprintf(args, sizeof(args), "delsample \"%s\"", uname);
    args[sizeof(args) - 1] = 0;
    resp = AdminTalk(args);
    free(resp);
    MessageBoxW(g_hMain, L"已写入病毒库并删除服务器样本", L"提示", MB_ICONINFORMATION);
    DoRefresh(g_hMain);
}

static void OnRejectSample(void) {
    int sel = SelectedSample();
    if (sel < 0) return;
    SampleItem* it = &g_samples[sel];
    wchar_t msg[512];
    swprintf(msg, 512, L"不同意该样本「%s」？\n\n服务器上的样本文件将被删除，不会写入病毒库。", it->name);
    if (MessageBoxW(g_hMain, msg, L"不同意该样本", MB_YESNO | MB_ICONWARNING) != IDYES) return;

    char uname[512], args[1024];
    QuoteArg(it->name, uname, sizeof(uname));
    snprintf(args, sizeof(args), "delsample \"%s\"", uname);
    args[sizeof(args) - 1] = 0;
    char* resp = AdminTalk(args);
    BOOL ok = RespOk(resp);
    free(resp);
    MessageBoxW(g_hMain, ok ? L"已删除服务器样本" : L"删除失败", ok ? L"提示" : L"错误",
                ok ? MB_ICONINFORMATION : MB_ICONERROR);
    DoRefresh(g_hMain);
}

static void OnPublishWild(void) {
    if (!ValidVersion(g_verWild)) {
        MessageBoxW(g_hMain, L"无法获取服务器上的当前病毒库版本，暂时不能发布。\n请先“刷新数据”并确认服务器正常。",
                    L"发布新病毒库", MB_ICONWARNING);
        return;
    }
    wchar_t next[64];
    BumpVersion(g_verWild, next, 64);
    wchar_t msg[256];
    swprintf(msg, 256, L"确定发布病毒库V%s吗？", next);
    if (MessageBoxW(g_hMain, msg, L"发布新病毒库", MB_YESNO | MB_ICONQUESTION) != IDYES) return;

    wchar_t today[64]; TodayStr(today, 64);
    char uver[128], udate[128], udesc[128], args[1024];
    QuoteArg(next, uver, sizeof(uver));
    QuoteArg(today, udate, sizeof(udate));
    QuoteArg(L"病毒库更新", udesc, sizeof(udesc));
    snprintf(args, sizeof(args), "pubwild \"%s\" \"%s\" \"%s\"", uver, udate, udesc);
    args[sizeof(args) - 1] = 0;
    char* resp = AdminTalk(args);
    BOOL ok = RespOk(resp);
    free(resp);
    if (ok) {
        wchar_t done[256];
        swprintf(done, 256, L"病毒库 V%s 发布成功", next);
        MessageBoxW(g_hMain, done, L"提示", MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_hMain, L"发布失败（无法连接服务器）", L"错误", MB_ICONERROR);
    }
    DoRefresh(g_hMain);
}

static void OnPublishApp(void) {
    wchar_t path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMain;
    ofn.lpstrFilter = L"安装程序 (*.exe)\0*.exe\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"选择要发布的安装程序 (.exe)";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;

    if (!ValidVersion(g_verApp)) {
        MessageBoxW(g_hMain, L"无法获取服务器上的当前程序版本，暂时不能发布。\n请先“刷新数据”并确认服务器正常。",
                    L"发布新程序", MB_ICONWARNING);
        return;
    }

    wchar_t next[64];
    BumpVersion(g_verApp, next, 64);
    if (!AskPublishInfo(next)) return;

    wchar_t ver[64], desc[512], date[64];
    if (g_pubVer[0]) wcscpy(ver, g_pubVer); else wcscpy(ver, next);
    if (g_pubDesc[0]) wcscpy(desc, g_pubDesc); else wcscpy(desc, L"修改已知问题");
    if (g_pubDate[0]) wcscpy(date, g_pubDate); else TodayStr(date, 64);

    if (UploadApp(path, ver, date, desc)) {
        wchar_t done[256];
        swprintf(done, 256, L"程序 V%s 发布成功", ver);
        MessageBoxW(g_hMain, done, L"提示", MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_hMain, L"发布失败（网络错误或服务器拒绝）", L"错误", MB_ICONERROR);
    }
    DoRefresh(g_hMain);
}

static void OnChangePwd(void) {
    if (!AskNewPassword()) return;
    char unew[256], args[512];
    QuoteArg(g_pwdDlgNew, unew, sizeof(unew));
    snprintf(args, sizeof(args), "setpwd \"%s\"", unew);
    args[sizeof(args) - 1] = 0;
    char* resp = AdminTalk(args);
    BOOL ok = RespOk(resp);
    free(resp);
    if (ok) {
        W2U(g_pwdDlgNew, g_pwd, sizeof(g_pwd));   /* 保持原样，用于下次认证 */
        MessageBoxW(g_hMain, L"管理密码修改成功", L"提示", MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_hMain, L"密码修改失败", L"错误", MB_ICONERROR);
    }
}

static void OnEditWildEntry(void) {
    int sel = (int)SendMessageW(g_lstWild, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= g_wildCount) return;
    WildItem old = g_wild[sel];

    wchar_t szStr[32];
    swprintf(szStr, 32, L"%llu", old.size);
    int r = AskEditVirus(szStr, old.name, old.hash);
    if (r == 0) return;

    char uold[512], args[2048];
    QuoteArg(old.name, uold, sizeof(uold));

    if (r == 2) {
        wchar_t msg[512];
        swprintf(msg, 512, L"确定删除病毒库条目「%s」（大小 %llu）吗？", old.name, old.size);
        if (MessageBoxW(g_hMain, msg, L"删除确认", MB_YESNO | MB_ICONWARNING) != IDYES) return;
        snprintf(args, sizeof(args), "delvirus %llu \"%s\"", old.size, uold);
        args[sizeof(args) - 1] = 0;
        char* resp = AdminTalk(args);
        BOOL ok = RespOk(resp);
        free(resp);
        MessageBoxW(g_hMain, ok ? L"已删除" : L"删除失败（条目可能不存在）",
                    ok ? L"提示" : L"错误", ok ? MB_ICONINFORMATION : MB_ICONERROR);
    } else {
        unsigned long long newSize = _wcstoui64(g_editSize, NULL, 10);
        if (newSize == old.size && wcscmp(g_editName, old.name) == 0 &&
            _wcsicmp(g_editHash, old.hash) == 0) return; /* 无变化 */
        char unew[512], uhash[64];
        QuoteArg(g_editName, unew, sizeof(unew));
        W2U(g_editHash, uhash, sizeof(uhash));
        snprintf(args, sizeof(args), "editvirus %llu \"%s\" %llu \"%s\" \"%s\"",
                  old.size, uold, newSize, unew, uhash);
        args[sizeof(args) - 1] = 0;
        char* resp = AdminTalk(args);
        BOOL ok = RespOk(resp);
        free(resp);
        MessageBoxW(g_hMain, ok ? L"修改已保存" : L"修改失败（条目可能不存在）",
                    ok ? L"提示" : L"错误", ok ? MB_ICONINFORMATION : MB_ICONERROR);
    }
    DoRefresh(g_hMain);
}

/* ========== 实用工具箱管理 ========== */
#define MAX_ADMIN_TOOLS 128
#define ID_TOOL_BROWSE  2107

typedef struct { wchar_t name[128]; wchar_t desc[256]; wchar_t exe[128]; } ToolItem;
static ToolItem g_tools[MAX_ADMIN_TOOLS];
static int  g_toolCount = 0;
static HWND g_toolList = NULL, g_toolStatus = NULL;

static BOOL g_toolEditOk = FALSE;
static wchar_t g_toolEditName[128] = {0};
static wchar_t g_toolEditDesc[256] = {0};
static wchar_t g_toolEditExe[128] = {0};
static wchar_t g_toolEditLocal[MAX_PATH] = {0};

static wchar_t* TrimLeftW(wchar_t* s) {
    while (*s == L' ' || *s == L'\t') s++;
    return s;
}
static void TrimRightW(wchar_t* s) {
    size_t l = wcslen(s);
    while (l > 0 && (s[l-1] == L' ' || s[l-1] == L'\t')) s[--l] = 0;
}

/* 发送带原始数据体的管理命令（settools） */
static char* AdminSendBody(const char* args, const char* body, size_t len) {
    SOCKET s;
    if (!AdminConnect(&s)) return NULL;
    if (!AdminWriteCmd(s, args)) { closesocket(s); return NULL; }
    size_t sent = 0;
    while (sent < len) {
        int chunk = (int)((len - sent > 8192) ? 8192 : (len - sent));
        int n = send(s, body + sent, chunk, 0);
        if (n <= 0) { closesocket(s); return NULL; }
        sent += (size_t)n;
    }
    char* resp = RecvAll(s, NULL);
    closesocket(s);
    return resp;
}

/* 从服务器读取 PracticalToolbox.txt 并解析 */
static BOOL FetchTools(void) {
    g_toolCount = 0;
    size_t len = 0;
    char* resp = ReadServerFile("PracticalToolbox.txt", &len);
    if (!resp) return FALSE;
    wchar_t* w = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    if (!w) { free(resp); return FALSE; }
    U2W(resp, w, (int)len + 1);
    free(resp);

    wchar_t* save = NULL;
    wchar_t* line = WTok(w, L"\n", &save);
    while (line && g_toolCount < MAX_ADMIN_TOOLS) {
        wchar_t* p = TrimLeftW(line);
        TrimRightW(p);
        if (*p && *p != L'#') {
            /* 格式：名称 说明 文件名（说明可含空格） */
            wchar_t* sp1 = wcschr(p, L' ');
            if (sp1) {
                *sp1 = 0;
                wchar_t* rest = TrimLeftW(sp1 + 1);
                wchar_t* sp2 = wcsrchr(rest, L' ');
                if (sp2) {
                    *sp2 = 0;
                    TrimRightW(rest);
                    wchar_t* exe = TrimLeftW(sp2 + 1);
                    TrimRightW(exe);
                    if (*p && *rest && *exe) {
                        ToolItem* t = &g_tools[g_toolCount++];
                        wcsncpy(t->name, p, 127); t->name[127] = 0;
                        wcsncpy(t->desc, rest, 255); t->desc[255] = 0;
                        wcsncpy(t->exe, exe, 127); t->exe[127] = 0;
                    }
                }
            }
        }
        line = WTok(NULL, L"\n", &save);
    }
    free(w);
    return TRUE;
}

static void SetToolStatus(const wchar_t* text) {
    if (g_toolStatus) SetWindowTextW(g_toolStatus, text);
}

/* 把当前工具列表写回服务器 */
static BOOL SaveToolsToServer(void) {
    size_t cap = (size_t)g_toolCount * 520 + 64;
    wchar_t* text = (wchar_t*)malloc(cap * sizeof(wchar_t));
    if (!text) return FALSE;
    text[0] = 0;
    /* 空列表也写一行注释，保证文件非空、下次仍能正常读取管理 */
    if (g_toolCount == 0) wcscpy(text, L"# 工具箱为空\n");
    for (int i = 0; i < g_toolCount; i++) {
        wcscat(text, g_tools[i].name); wcscat(text, L" ");
        wcscat(text, g_tools[i].desc); wcscat(text, L" ");
        wcscat(text, g_tools[i].exe);  wcscat(text, L"\n");
    }
    int bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (bytes <= 0) { free(text); return FALSE; }
    bytes -= 1; /* 去掉结尾 \0 */
    char* u = (char*)malloc((size_t)bytes + 1);
    if (!u) { free(text); return FALSE; }
    WideCharToMultiByte(CP_UTF8, 0, text, -1, u, bytes + 1, NULL, NULL);
    free(text);

    char args[64];
    snprintf(args, sizeof(args), "settools %d", bytes);
    args[sizeof(args) - 1] = 0;
    char* resp = AdminSendBody(args, u, (size_t)bytes);
    free(u);
    BOOL ok = RespOk(resp);
    free(resp);
    return ok;
}

/* 上传工具程序到服务器 data 目录 */
static BOOL UploadToolFile(const wchar_t* local, const wchar_t* serverName) {
    HANDLE h = CreateFileW(local, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER li; GetFileSizeEx(h, &li);
    unsigned long long size = (unsigned long long)li.QuadPart;

    SOCKET s;
    if (!AdminConnect(&s)) { CloseHandle(h); return FALSE; }

    char uname[256], args[512];
    QuoteArg(serverName, uname, sizeof(uname));
    snprintf(args, sizeof(args), "puttool %llu \"%s\"", size, uname);
    args[sizeof(args) - 1] = 0;
    if (!AdminWriteCmd(s, args)) { CloseHandle(h); closesocket(s); return FALSE; }

    DLWIN d;
    CreateProgressWindow(&d, L"上传工具程序");
    SetProgressText(&d, L"正在上传工具程序...", 0);

    char buf[8192];
    DWORD r = 0;
    unsigned long long sentTotal = 0;
    BOOL ok = TRUE;
    while (ReadFile(h, buf, sizeof(buf), &r, NULL) && r > 0) {
        int sent = 0;
        while (sent < (int)r) {
            int n = send(s, buf + sent, (int)r - sent, 0);
            if (n <= 0) { ok = FALSE; break; }
            sent += n;
        }
        if (!ok) break;
        sentTotal += r;
        int pm = size ? (int)(sentTotal * 1000 / size) : 0;
        wchar_t msg[256];
        swprintf(msg, 256, L"正在上传工具程序... %d%%", pm / 10);
        SetProgressText(&d, msg, pm);
    }
    CloseHandle(h);
    if (ok) {
        char line[128];
        if (!RecvLine(s, line, sizeof(line)) || strncmp(line, "OK", 2) != 0) ok = FALSE;
    }
    closesocket(s);
    Sleep(200);
    DestroyWindow(d.hwnd);
    return ok;
}

static void FillToolList(int keepSel) {
    if (!g_toolList) return;
    SendMessageW(g_toolList, LB_RESETCONTENT, 0, 0);
    wchar_t buf[800];
    for (int i = 0; i < g_toolCount; i++) {
        swprintf(buf, 800, L"%d.  %s    |    %s    |    %s",
                 i + 1, g_tools[i].name, g_tools[i].desc, g_tools[i].exe);
        SendMessageW(g_toolList, LB_ADDSTRING, 0, (LPARAM)buf);
    }
    if (g_toolCount == 0)
        SendMessageW(g_toolList, LB_ADDSTRING, 0, (LPARAM)L"（暂无工具，点击“添加工具”新增）");
    if (keepSel >= 0 && keepSel < g_toolCount)
        SendMessageW(g_toolList, LB_SETCURSEL, keepSel, 0);
}

static BOOL SaveToolsAndReport(void) {
    if (!SaveToolsToServer()) {
        SetToolStatus(L"保存到服务器失败，请检查网络后重试（当前修改尚未生效）");
        return FALSE;
    }
    wchar_t msg[256];
    swprintf(msg, 256, L"共 %d 个工具，修改已保存到服务器。", g_toolCount);
    SetToolStatus(msg);
    return TRUE;
}

static int SelectedTool(void) {
    int sel = (int)SendMessageW(g_toolList, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= g_toolCount) {
        SetToolStatus(L"请先在列表中选择一条工具");
        return -1;
    }
    return sel;
}

/* ---- 添加 / 修改工具条目对话框 ---- */
static void NextToolExeName(wchar_t* out, int cap);

static LRESULT CALLBACK ToolEditProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        MkStatic(hwnd, L"工具名称（不能包含空格）：", 20, 12, 400, 20);
        MkEdit(hwnd, 101, 20, 34, 470, 24, 0);
        MkStatic(hwnd, L"功能说明（显示在客户端）：", 20, 68, 400, 20);
        MkEdit(hwnd, 102, 20, 90, 470, 24, 0);
        MkStatic(hwnd, L"程序文件名（自动编号）：", 20, 124, 220, 20);
        MkEdit(hwnd, 103, 20, 146, 220, 24, ES_READONLY);
        MkStatic(hwnd, L"自动为 1.exe、2.exe…，无需手动填写", 250, 148, 280, 20);
        MkStatic(hwnd, L"本地程序文件（可选，选择后会上传到服务器）：", 20, 182, 420, 20);
        MkEdit(hwnd, 104, 20, 204, 370, 24, ES_READONLY);
        MkButton(hwnd, ID_TOOL_BROWSE, L"浏览...", 400, 202, 90, 28);
        MkButton(hwnd, IDOK, L"确定", 160, 250, 100, 30);
        MkButton(hwnd, IDCANCEL, L"取消", 280, 250, 100, 30);

        SetWindowTextW(GetDlgItem(hwnd, 101), g_toolEditName);
        SetWindowTextW(GetDlgItem(hwnd, 102), g_toolEditDesc);
        SetWindowTextW(GetDlgItem(hwnd, 103), g_toolEditExe);
        SetWindowTextW(GetDlgItem(hwnd, 104), g_toolEditLocal);
        return 0;

    case WM_COMMAND:
        if (LOWORD(w) == ID_TOOL_BROWSE) {
            wchar_t path[MAX_PATH] = {0};
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"可执行文件 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0";
            ofn.lpstrFile = path;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrTitle = L"选择要上传的工具程序";
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                SetWindowTextW(GetDlgItem(hwnd, 104), path);
                wchar_t exe[128];
                GetWindowTextW(GetDlgItem(hwnd, 103), exe, 128);
                if (!exe[0]) {
                    wchar_t autoName[32];
                    NextToolExeName(autoName, 32);
                    SetWindowTextW(GetDlgItem(hwnd, 103), autoName);
                }
            }
            return 0;
        }
        if (LOWORD(w) == IDOK) {
            wchar_t name[128], desc[256], exe[128], local[MAX_PATH];
            GetWindowTextW(GetDlgItem(hwnd, 101), name, 128);
            GetWindowTextW(GetDlgItem(hwnd, 102), desc, 256);
            GetWindowTextW(GetDlgItem(hwnd, 103), exe, 128);
            GetWindowTextW(GetDlgItem(hwnd, 104), local, MAX_PATH);
            wchar_t* n = TrimLeftW(name); TrimRightW(n);
            wchar_t* de = TrimLeftW(desc); TrimRightW(de);
            wchar_t* ex = TrimLeftW(exe); TrimRightW(ex);

            if (!*n) { MessageBoxW(hwnd, L"工具名称不能为空", L"提示", MB_ICONWARNING); return 0; }
            if (wcschr(n, L' ') || wcschr(n, L'\t')) {
                MessageBoxW(hwnd, L"工具名称不能包含空格（用短横线代替）", L"提示", MB_ICONWARNING);
                return 0;
            }
            if (!*de) { MessageBoxW(hwnd, L"功能说明不能为空", L"提示", MB_ICONWARNING); return 0; }
            if (!*ex) { MessageBoxW(hwnd, L"程序文件名不能为空", L"提示", MB_ICONWARNING); return 0; }
            if (wcschr(ex, L' ') || wcschr(ex, L'\t')) {
                MessageBoxW(hwnd, L"程序文件名不能包含空格", L"提示", MB_ICONWARNING);
                return 0;
            }

            wcsncpy(g_toolEditName, n, 127); g_toolEditName[127] = 0;
            wcsncpy(g_toolEditDesc, de, 255); g_toolEditDesc[255] = 0;
            wcsncpy(g_toolEditExe, ex, 127); g_toolEditExe[127] = 0;
            wcsncpy(g_toolEditLocal, local, MAX_PATH - 1); g_toolEditLocal[MAX_PATH - 1] = 0;
            g_toolEditOk = TRUE;
            DestroyWindow(hwnd);
        } else if (LOWORD(w) == IDCANCEL) {
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_modalDone = TRUE; return 0;   /* 必须通知模态循环退出，否则会卡死 */
    case WM_CTLCOLORSTATIC: SetBkMode((HDC)w, TRANSPARENT); return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

/* 自动生成下一个程序文件名：1.exe、2.exe、3.exe ... */
static void NextToolExeName(wchar_t* out, int cap) {
    int maxN = 0;
    for (int i = 0; i < g_toolCount; i++) {
        const wchar_t* e = g_tools[i].exe;
        wchar_t* end = NULL;
        long n = wcstol(e, &end, 10);
        if (end && end != e && n > 0 && _wcsicmp(end, L".exe") == 0 && n > maxN) maxN = (int)n;
    }
    swprintf(out, cap, L"%d.exe", maxN + 1);
}

static BOOL AskToolInfo(HWND owner, const wchar_t* title, const ToolItem* init, const wchar_t* defExe) {
    g_toolEditOk = FALSE;
    if (init) {
        wcsncpy(g_toolEditName, init->name, 127); g_toolEditName[127] = 0;
        wcsncpy(g_toolEditDesc, init->desc, 255); g_toolEditDesc[255] = 0;
        wcsncpy(g_toolEditExe, init->exe, 127); g_toolEditExe[127] = 0;
    } else {
        g_toolEditName[0] = 0; g_toolEditDesc[0] = 0;
        g_toolEditExe[0] = 0;
        if (defExe && *defExe) {
            wcsncpy(g_toolEditExe, defExe, 127); g_toolEditExe[127] = 0;
        }
    }
    g_toolEditLocal[0] = 0;

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = ToolEditProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminToolEditDlg";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BDAdminToolEditDlg", title,
        WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 520, 325, g_hMain, NULL, wc.hInstance, NULL);
    CenterWindow(dlg, 520, 325);
    RunModal(owner, dlg);
    return g_toolEditOk;
}

/* ---- 工具列表操作 ---- */
static void OnToolAdd(HWND hwnd) {
    if (g_toolCount >= MAX_ADMIN_TOOLS) {
        SetToolStatus(L"工具数量已达上限");
        return;
    }
    wchar_t autoExe[32];
    NextToolExeName(autoExe, 32);
    if (!AskToolInfo(hwnd, L"添加工具", NULL, autoExe)) return;

    if (g_toolEditLocal[0]) {
        SetToolStatus(L"正在上传工具程序...");
        if (!UploadToolFile(g_toolEditLocal, g_toolEditExe)) {
            MessageBoxW(hwnd, L"工具程序上传失败，未添加该工具。", L"错误", MB_ICONERROR);
            SetToolStatus(L"工具程序上传失败");
            return;
        }
    }

    ToolItem* t = &g_tools[g_toolCount++];
    wcsncpy(t->name, g_toolEditName, 127); t->name[127] = 0;
    wcsncpy(t->desc, g_toolEditDesc, 255); t->desc[255] = 0;
    wcsncpy(t->exe, g_toolEditExe, 127); t->exe[127] = 0;
    FillToolList(g_toolCount - 1);
    SaveToolsAndReport();
}

static void OnToolEdit(HWND hwnd) {
    int sel = SelectedTool();
    if (sel < 0) return;
    ToolItem old = g_tools[sel];
    if (!AskToolInfo(hwnd, L"修改工具", &old, NULL)) return;

    if (g_toolEditLocal[0]) {
        SetToolStatus(L"正在上传工具程序...");
        if (!UploadToolFile(g_toolEditLocal, g_toolEditExe)) {
            MessageBoxW(hwnd, L"工具程序上传失败，修改未保存。", L"错误", MB_ICONERROR);
            SetToolStatus(L"工具程序上传失败");
            return;
        }
    }

    ToolItem* t = &g_tools[sel];
    wcsncpy(t->name, g_toolEditName, 127); t->name[127] = 0;
    wcsncpy(t->desc, g_toolEditDesc, 255); t->desc[255] = 0;
    wcsncpy(t->exe, g_toolEditExe, 127); t->exe[127] = 0;
    FillToolList(sel);
    SaveToolsAndReport();
}

static void OnToolDelete(HWND hwnd) {
    int sel = SelectedTool();
    if (sel < 0) return;
    wchar_t msg[512];
    swprintf(msg, 512, L"确定从工具箱中删除「%s」吗？\n\n客户端将不再显示该工具。"
                       L"（服务器上的程序文件会保留）", g_tools[sel].name);
    if (MessageBoxW(hwnd, msg, L"删除工具", MB_YESNO | MB_ICONWARNING) != IDYES) return;

    for (int i = sel; i < g_toolCount - 1; i++) g_tools[i] = g_tools[i + 1];
    g_toolCount--;
    int keep = sel < g_toolCount ? sel : g_toolCount - 1;
    FillToolList(keep);
    SaveToolsAndReport();
}

static void OnToolMove(HWND hwnd, int delta) {
    int sel = SelectedTool();
    if (sel < 0) return;
    int to = sel + delta;
    if (to < 0 || to >= g_toolCount) return;
    ToolItem tmp = g_tools[sel];
    g_tools[sel] = g_tools[to];
    g_tools[to] = tmp;
    FillToolList(to);
    SaveToolsAndReport();
}

static void OnToolsRefresh(void) {
    if (FetchTools()) {
        FillToolList(-1);
        SetToolStatus(L"已从服务器重新读取工具箱列表");
    } else {
        SetToolStatus(L"读取服务器工具箱失败，请检查网络");
    }
}

/* ---- 工具箱管理窗口 ---- */
static LRESULT CALLBACK ToolsDlgProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        MkStatic(hwnd, L"实用工具箱条目（顺序即客户端显示顺序；双击一条可修改）：", 16, 10, 600, 20);
        g_toolList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            16, 34, 688, 300, hwnd, (HMENU)(INT_PTR)ID_LST_TOOLS, NULL, NULL);
        SendMessageW(g_toolList, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
        SendMessageW(g_toolList, LB_SETHORIZONTALEXTENT, 2000, 0);

        MkButton(hwnd, 2101, L"添加工具", 16, 348, 100, 30);
        MkButton(hwnd, 2102, L"修改选中", 126, 348, 100, 30);
        MkButton(hwnd, 2103, L"删除选中", 236, 348, 100, 30);
        MkButton(hwnd, 2104, L"上移", 376, 348, 90, 30);
        MkButton(hwnd, 2105, L"下移", 476, 348, 90, 30);
        MkButton(hwnd, 2106, L"重新读取", 566, 348, 138, 30);

        g_toolStatus = MkStatic(hwnd, L"", 16, 392, 688, 20);
        MkButton(hwnd, IDCANCEL, L"关闭", 604, 420, 100, 30);

        FillToolList(-1);
        return 0;

    case WM_COMMAND:
        if (HIWORD(w) == LBN_DBLCLK && LOWORD(w) == ID_LST_TOOLS) { OnToolEdit(hwnd); return 0; }
        switch (LOWORD(w)) {
        case 2101: OnToolAdd(hwnd); return 0;
        case 2102: OnToolEdit(hwnd); return 0;
        case 2103: OnToolDelete(hwnd); return 0;
        case 2104: OnToolMove(hwnd, -1); return 0;
        case 2105: OnToolMove(hwnd, +1); return 0;
        case 2106: OnToolsRefresh(); return 0;
        case IDCANCEL: DestroyWindow(hwnd); return 0;
        }
        return 0;

    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: g_toolList = NULL; g_toolStatus = NULL; g_modalDone = TRUE; return 0;
    case WM_CTLCOLORSTATIC: SetBkMode((HDC)w, TRANSPARENT); return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static void OnManageTools(HWND owner) {
    /* 读取失败时不允许编辑，避免把空列表覆盖到服务器 */
    if (!FetchTools()) {
        MessageBoxW(owner, L"读取服务器上的实用工具箱失败，请检查网络或服务器配置。",
                    L"工具箱管理", MB_ICONERROR);
        return;
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = ToolsDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminToolsDlg";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"BDAdminToolsDlg", L"实用工具箱管理",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 720, 490, owner, NULL, wc.hInstance, NULL);
    CenterWindow(dlg, 720, 490);
    RunModal(owner, dlg);
}

/* ========== 主窗口 ========== */
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE: {
        g_lblInfo = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  16, 14, 860, 22, hwnd, (HMENU)(INT_PTR)ID_STATIC_INFO, NULL, NULL);
        SendMessageW(g_lblInfo, WM_SETFONT, (WPARAM)g_fontBold, TRUE);

        MkButton(hwnd, ID_BTN_PUBWILD, L"发布新病毒库", 16, 46, 160, 30);
        MkButton(hwnd, ID_BTN_PUBAPP, L"发布新程序", 186, 46, 160, 30);
        MkButton(hwnd, ID_BTN_PWD, L"修改管理密码", 356, 46, 160, 30);
        MkButton(hwnd, ID_BTN_TOOLS, L"工具箱管理", 526, 46, 160, 30);
        MkButton(hwnd, ID_BTN_REFRESH, L"刷新数据", 716, 46, 160, 30);

        HWND lbl1 = MkStatic(hwnd, L"待审核样本（用户上传）：", 16, 88, 400, 20);
        SendMessageW(lbl1, WM_SETFONT, (WPARAM)g_fontBold, TRUE);
        g_lstSamples = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            16, 112, 860, 150, hwnd, (HMENU)(INT_PTR)ID_LST_SAMPLES, NULL, NULL);
        SendMessageW(g_lstSamples, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
        SendMessageW(g_lstSamples, LB_SETHORIZONTALEXTENT, 2000, 0);

        MkButton(hwnd, ID_BTN_DL, L"下载样本", 16, 270, 160, 30);
        MkButton(hwnd, ID_BTN_ACCEPT, L"同意该样本", 186, 270, 160, 30);
        MkButton(hwnd, ID_BTN_REJECT, L"不同意该样本", 356, 270, 160, 30);

        HWND lbl2 = MkStatic(hwnd, L"病毒库数据（大小 | MD5 | 病毒名，双击一条数据进行 修改 / 删除）：", 16, 312, 600, 20);
        SendMessageW(lbl2, WM_SETFONT, (WPARAM)g_fontBold, TRUE);
        g_lstWild = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            16, 336, 860, 300, hwnd, (HMENU)(INT_PTR)ID_LST_WILD, NULL, NULL);
        SendMessageW(g_lstWild, WM_SETFONT, (WPARAM)g_fontBody, TRUE);
        SendMessageW(g_lstWild, LB_SETHORIZONTALEXTENT, 2000, 0);
        return 0;
    }
    case WM_COMMAND:
        if (HIWORD(w) == LBN_DBLCLK && LOWORD(w) == ID_LST_WILD) { OnEditWildEntry(); return 0; }
        switch (LOWORD(w)) {
        case ID_BTN_PUBWILD: OnPublishWild(); return 0;
        case ID_BTN_PUBAPP:  OnPublishApp();  return 0;
        case ID_BTN_PWD:     OnChangePwd();   return 0;
        case ID_BTN_TOOLS:   OnManageTools(hwnd); return 0;
        case ID_BTN_REFRESH: DoRefresh(hwnd); return 0;
        case ID_BTN_DL:      OnDownloadSample(); return 0;
        case ID_BTN_ACCEPT:  OnAcceptSample(); return 0;
        case ID_BTN_REJECT:  OnRejectSample(); return 0;
        }
        return 0;
    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)w, TRANSPARENT);
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    case WM_DESTROY:
        g_hMain = NULL;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static HWND CreateMainWindow(void) {
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminMainCls";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);

    RECT rc = {0, 0, 908, 692};
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, FALSE);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    HWND hwnd = CreateWindowExW(0, L"BDAdminMainCls", L"XDH防护控制中心服务器 管理程序",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        x, y, w, h, NULL, NULL, wc.hInstance, NULL);
    return hwnd;
}

/* ========== 登录窗口 ========== */
static LRESULT CALLBACK LoginProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
    case WM_CREATE:
        MkStatic(hwnd, L"请输入管理密码：", 24, 24, 200, 22);
        MkEdit(hwnd, ID_EDT_LOGIN_PWD, 24, 50, 292, 26, ES_PASSWORD);
        MkButton(hwnd, ID_BTN_LOGIN, L"登录", 24, 92, 110, 30);
        MkStatic(hwnd, L"@徐小小的电子制作", 24, 134, 330, 40);
        SetFocus(GetDlgItem(hwnd, ID_EDT_LOGIN_PWD));
        return 0;
    case WM_COMMAND:
        if (LOWORD(w) == ID_BTN_LOGIN) {
            wchar_t pwd[128];
            GetWindowTextW(GetDlgItem(hwnd, ID_EDT_LOGIN_PWD), pwd, 128);
            if (!pwd[0]) { MessageBoxW(hwnd, L"请输入密码", L"提示", MB_ICONWARNING); return 0; }
            /* 密码按原样（UTF-8）保存到 g_pwd，用于计算认证证明，
               不再做引号转义——转义会改变密码本身导致验证失败 */
            W2U(pwd, g_pwd, sizeof(g_pwd));
            char* resp = AdminTalk("check");
            if (!resp) {
                MessageBoxW(hwnd, L"无法连接服务器，请检查 IPconfig.ini 配置与网络", L"错误", MB_ICONERROR);
                return 0;
            }
            if (!RespOk(resp)) {
                BOOL limited = (strncmp(resp, "ERR ratelimit", 13) == 0);
                free(resp);
                MessageBoxW(hwnd, limited
                                  ? L"密码错误次数过多，请 10 分钟后再试"
                                  : L"密码错误",
                            L"错误", MB_ICONERROR);
                return 0;
            }
            free(resp);
            HWND mainWnd = CreateMainWindow();
            if (mainWnd) {
                g_hMain = mainWnd;
                ShowWindow(mainWnd, SW_SHOW);
                UpdateWindow(mainWnd);
                DoRefresh(mainWnd);
                DestroyWindow(hwnd); /* 关闭登录窗口 */
            }
        }
        return 0;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        if (!g_hMain) PostQuitMessage(0); /* 未登录就关闭则退出 */
        return 0;
    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)w, TRANSPARENT);
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

/* ========== 入口 ========== */
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR cmd, int show) {
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icex);

    g_fontBody = MakeFont(14, FW_NORMAL);
    g_fontBold = MakeFont(14, FW_BOLD);

    if (!LoadServerCfg(&g_cfg)) {
        MessageBoxW(NULL, L"无法读取 IPconfig.ini（需与本程序放在同一目录）\n内容示例：\nserver_ip=back1.idcfengye.com\nserver_port=28586",
                    L"BDProtect 管理程序", MB_ICONERROR);
        return 1;
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = LoginProc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDAdminLoginCls";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExW(&wc);

    int w = 360, h = 220;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    HWND login = CreateWindowExW(0, L"BDAdminLoginCls", L"BDProtect 管理程序 - 登录",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y, w, h, NULL, NULL, hInst, NULL);
    if (!login) return 1;
    ShowWindow(login, SW_SHOW);
    UpdateWindow(login);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        /* 登录窗口里回车 = 点击登录 */
        if (m.message == WM_KEYDOWN && m.wParam == VK_RETURN &&
            IsChild(login, GetFocus()) && IsWindow(login)) {
            HWND foc = GetFocus();
            if (foc == GetDlgItem(login, ID_EDT_LOGIN_PWD)) {
                SendMessageW(login, WM_COMMAND, ID_BTN_LOGIN, 0);
                continue;
            }
        }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}
