#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <pdh.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>
#include "bd_paths.h"

/* 运行状态目录（配置 / 退出标志）。与 bd_common.h 保持一致。 */
#define BD_STATE_DIR       L"C:\\ProgramData\\BDProtect"
#define BD_STOP_FLAG_FILE  BD_STATE_DIR L"\\stop.flag"
#define BD_CONFIG_FILE     BD_STATE_DIR L"\\config.ini"
#define BD_OLD_CONFIG_FILE bd_cache_path(L"config.ini")

/* 样本大小限制：必须大于 3KB 且小于 500MB；不限制文件类型 */
#define SAMPLE_MIN_SIZE (3ULL * 1024)                  /* 判据：size > 3072 字节 */
#define SAMPLE_MAX_SIZE (500ULL * 1024ULL * 1024ULL)   /* 判据：size < 500MB */

/* 与 bd_util.c 中的实现保持一致：只允许 SYSTEM / Administrators 写入 */
static void HardenStateDir(void)
{
    SHCreateDirectoryExW(NULL, BD_STATE_DIR, NULL);

    PSECURITY_DESCRIPTOR sd = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)(A;OICI;FR;;;WD)",
            SDDL_REVISION_1, &sd, NULL)) {
        PACL dacl = NULL;
        BOOL present = FALSE, def = FALSE;
        if (GetSecurityDescriptorDacl(sd, &present, &dacl, &def) && present)
            SetNamedSecurityInfoW((LPWSTR)BD_STATE_DIR, SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                  NULL, NULL, dacl, NULL);
        LocalFree(sd);
    }

    if (GetFileAttributesW(BD_CONFIG_FILE) == INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesW(BD_OLD_CONFIG_FILE) != INVALID_FILE_ATTRIBUTES)
        CopyFileW(BD_OLD_CONFIG_FILE, BD_CONFIG_FILE, FALSE);
}

static BOOL ProcessRunningName(const wchar_t* name)
{
    BOOL found = FALSE;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { found = TRUE; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

/* 卸载/更新前会留下 stop.flag；控制中心识别后自动退出，避免阻塞卸载 */
static DWORD WINAPI StopFlagWatchThread(LPVOID p)
{
    HWND hwnd = (HWND)p;
    while (1) {
        if (GetFileAttributesW(BD_STOP_FLAG_FILE) != INVALID_FILE_ATTRIBUTES) {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            return 0;
        }
        Sleep(500);
    }
    return 0;
}

#ifndef PDH_MORE_DATA
#define PDH_MORE_DATA ((PDH_STATUS)0x800007D2L)
#endif

/* ========== 布局与颜色 ========== */
#define HEADER_H        152
#define SETTINGS_Y      168
#define CARD_TOP        (SETTINGS_Y + 26)
#define CARD_H          40
#define CARD_GAP        10
#define CARD_ROWS       3
#define RECORDS_Y       (CARD_TOP + CARD_ROWS * (CARD_H + CARD_GAP) + 16)
#define RECORD_TOP      (RECORDS_Y + 26)
#define RECORD_ROWS     4
#define RECORD_ROW_H    26
#define TOOLS_Y         (RECORD_TOP + RECORD_ROWS * RECORD_ROW_H + 16)
#define TOOL_TOP        (TOOLS_Y + 26)

#define WIN_W           820
#define WIN_H           800

#define CLR_HEADER_BG   RGB( 26,  32,  46)
#define CLR_HEADER_LINE RGB( 56, 132, 220)
#define CLR_BODY_BG     RGB(246, 247, 251)
#define CLR_TITLE       RGB( 90, 175, 255)
#define CLR_TEXT        RGB(238, 243, 252)
#define CLR_TEXT_DIM    RGB(150, 168, 195)
#define CLR_BAR_BG      RGB( 52,  60,  78)

#define CLR_CARD_BG     RGB(255, 255, 255)
#define CLR_CARD_BORDER RGB(220, 225, 235)
#define CLR_CARD_TEXT   RGB( 50,  60,  80)
#define CLR_CARD_HOVER  RGB(235, 245, 255)
#define CLR_TOOL_BG     RGB(255, 255, 255)
#define CLR_TOOL_HOVER  RGB(240, 248, 255)
#define CLR_TOOL_TEXT   RGB( 50,  60,  80)
#define CLR_ACCENT      RGB( 56, 132, 220)

#define MAX_RECORDS 2000
#define MAX_TOOLS   50
#define WM_APP_TOOLS_REFRESH (WM_APP + 1)
#define WM_APP_UPLOAD_DONE   (WM_APP + 2)
#define WM_APP_DB_DONE       (WM_APP + 3)

/* ========== 路径 ========== */
static wchar_t g_AppDir[MAX_PATH];

static void InitAppDir(void)
{
    GetModuleFileNameW(NULL, g_AppDir, MAX_PATH);
    wchar_t* s = wcsrchr(g_AppDir, L'\\');
    if (s) *s = 0;
}

static void AppFile(const wchar_t* name, wchar_t* out, int cap)
{
    swprintf(out, cap, L"%s\\%s", g_AppDir, name);
}

/* ========== 监控数据 ========== */
typedef struct {
    double cpu_total;
    double cpu_core[64];
    int    core_count;
    double mem_pct;
    struct { char letter; double rate; double storage; } disks[26];
    int       disk_count;
    double rx_pct, tx_pct, total_pct;
    double rx_kb, tx_kb;
} MonitorData;

static MonitorData g_data;
static PDH_HQUERY g_cpuQuery = NULL, g_diskQuery = NULL;
static PDH_HCOUNTER g_cpuCounter = NULL, g_diskTime = NULL;

/* ========== 业务状态 ========== */
static BOOL g_ProtectFile = TRUE, g_ProtectReg = TRUE, g_ProtectMbr = TRUE, g_ProtectNet = TRUE;
static BOOL g_ProtectInject = TRUE, g_ProtectCloud = FALSE;
static int g_ScrollY = 0;
static int g_HoverTool = -1;
static int g_HoverSetting = -1;
static int g_HoverRecord = -1;
static HWND g_hMainWnd = NULL;
static BOOL g_bToolsReady = FALSE;
static BOOL g_hasWildlist = FALSE;
static BOOL g_dbDownloading = FALSE;
static BOOL g_recordsDlgOpen = FALSE;

#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#endif

/* 拦截记录 */
typedef struct {
    wchar_t time[32];
    wchar_t type[48];
    wchar_t target[MAX_PATH];
    wchar_t choice[32];
} Record;
static Record g_records[MAX_RECORDS];
static int g_recordCount = 0;

/* 云端工具箱 */
static wchar_t g_ToolName[MAX_TOOLS][128];
static wchar_t g_ToolDesc[MAX_TOOLS][256];
static wchar_t g_ToolExe[MAX_TOOLS][128];
static int g_ToolCount = 0;

/* ========== 字体 ========== */
static HFONT g_fontSmall = NULL, g_fontBody = NULL, g_fontBold = NULL, g_fontBig = NULL;

static HFONT MakeFont(int px, int weight) {
    return CreateFontW(-px, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
}

/* ========== 绘制辅助 ========== */
static void FillRectC(HDC hdc, int x, int y, int w, int h, COLORREF c) { RECT r = { x, y, x + w, y + h }; HBRUSH b = CreateSolidBrush(c); FillRect(hdc, &r, b); DeleteObject(b); }
static void FillRoundC(HDC hdc, int x, int y, int w, int h, int rad, COLORREF c) {
    HBRUSH b = CreateSolidBrush(c); HPEN p = CreatePen(PS_SOLID, 1, c);
    HGDIOBJ ob = SelectObject(hdc, b); HGDIOBJ op = SelectObject(hdc, p); RoundRect(hdc, x, y, x + w, y + h, rad, rad);
    SelectObject(hdc, ob); SelectObject(hdc, op); DeleteObject(b); DeleteObject(p);
}
static void DrawStrL(HDC hdc, int x, int y, const wchar_t *s, COLORREF c, HFONT f) {
    HFONT old = (HFONT)SelectObject(hdc, f); SetTextColor(hdc, c); SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, x, y, s, (int)wcslen(s)); SelectObject(hdc, old);
}
static void DrawStrR(HDC hdc, int xr, int y, const wchar_t *s, COLORREF c, HFONT f) {
    HFONT old = (HFONT)SelectObject(hdc, f); SIZE sz; GetTextExtentPoint32W(hdc, s, (int)wcslen(s), &sz);
    SetTextColor(hdc, c); SetBkMode(hdc, TRANSPARENT); TextOutW(hdc, xr - sz.cx, y, s, (int)wcslen(s)); SelectObject(hdc, old);
}
static void DrawStrEllipsis(HDC hdc, int x, int y, int w, int h, const wchar_t* s, COLORREF c, HFONT f) {
    HFONT old = (HFONT)SelectObject(hdc, f);
    SetTextColor(hdc, c); SetBkMode(hdc, TRANSPARENT);
    RECT r = { x, y, x + w, y + h };
    DrawTextW(hdc, s, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(hdc, old);
}
static COLORREF BarColor(double pct) { if (pct >= 85.0) return RGB(255, 96, 96); if (pct >= 60.0) return RGB(255, 190, 70); return RGB( 86, 196, 255); }
static void DrawProgress(HDC hdc, int x, int y, int w, int h, double pct) {
    if (pct < 0.0) pct = 0.0;
    if (pct > 100.0) pct = 100.0;
    FillRoundC(hdc, x, y, w, h, h, CLR_BAR_BG); int fw = (int)(w * pct / 100.0 + 0.5);
    if (fw > 0) { int rr = (fw < h) ? fw : h; FillRoundC(hdc, x, y, fw, h, rr, BarColor(pct)); }
}

/* ========== 监控采集 ========== */
static void CollectCPU(void) {
    DWORD bufSize = 0, itemCount = 0;
    PdhCollectQueryData(g_cpuQuery);
    if (PdhGetFormattedCounterArrayW(g_cpuCounter, PDH_FMT_DOUBLE, &bufSize, &itemCount, NULL) != PDH_MORE_DATA || bufSize == 0) return;
    PPDH_FMT_COUNTERVALUE_ITEM_W items = (PPDH_FMT_COUNTERVALUE_ITEM_W)malloc(bufSize);
    if (items && PdhGetFormattedCounterArrayW(g_cpuCounter, PDH_FMT_DOUBLE, &bufSize, &itemCount, items) == ERROR_SUCCESS) {
        int maxIdx = 0; memset(g_data.cpu_core, 0, sizeof(g_data.cpu_core)); g_data.cpu_total = 0.0;
        for (DWORD i = 0; i < itemCount; i++) {
            if (wcscmp(items[i].szName, L"_Total") == 0) g_data.cpu_total = items[i].FmtValue.doubleValue;
            else if (items[i].szName[0] >= L'0' && items[i].szName[0] <= L'9') {
                int idx = _wtoi(items[i].szName);
                if (idx >= 0 && idx < 64) { g_data.cpu_core[idx] = items[i].FmtValue.doubleValue; if (idx + 1 > maxIdx) maxIdx = idx + 1; }
            }
        }
        g_data.core_count = maxIdx;
    }
    if (items) free(items);
    MEMORYSTATUSEX memStatus; memStatus.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memStatus)) g_data.mem_pct = (double)memStatus.dwMemoryLoad;
}
static void CollectDisk(void) {
    DWORD bufSize = 0, itemCount = 0; PPDH_FMT_COUNTERVALUE_ITEM_W items = NULL;
    PdhCollectQueryData(g_diskQuery);
    if (PdhGetFormattedCounterArrayW(g_diskTime, PDH_FMT_DOUBLE, &bufSize, &itemCount, NULL) == PDH_MORE_DATA && bufSize > 0) {
        items = (PPDH_FMT_COUNTERVALUE_ITEM_W)malloc(bufSize);
        if (items) { if (PdhGetFormattedCounterArrayW(g_diskTime, PDH_FMT_DOUBLE, &bufSize, &itemCount, items) != ERROR_SUCCESS) { free(items); items = NULL; } }
    }
    DWORD drives = GetLogicalDrives(); int n = 0;
    for (int i = 0; i < 26 && n < 26; i++) {
        if (!(drives & (1u << i))) continue;
        char root[4] = { (char)('A' + i), ':', '\\', 0 };
        UINT type = GetDriveTypeA(root);
        if (type != DRIVE_FIXED) continue;
        double storage = 0.0; ULARGE_INTEGER freeAvail, total, totalFree;
        if (GetDiskFreeSpaceExA(root, &freeAvail, &total, &totalFree) && total.QuadPart > 0) storage = (double)(total.QuadPart - totalFree.QuadPart) / (double)total.QuadPart * 100.0;
        double rate = 0.0;
        if (items) { wchar_t key[4] = { (wchar_t)L' ', (wchar_t)(L'A' + i), (wchar_t)L':', 0 }; for (DWORD j = 0; j < itemCount; j++) if (wcsstr(items[j].szName, key) != NULL) rate += items[j].FmtValue.doubleValue; }
        g_data.disks[n].letter = (char)('A' + i); g_data.disks[n].storage = storage; g_data.disks[n].rate = rate > 100.0 ? 100.0 : rate; n++;
    }
    g_data.disk_count = n; if (items) free(items);
}
static void CollectNetwork(void) {
    PMIB_IFTABLE pIfTable = NULL; DWORD dwSize = 0;
    if (GetIfTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pIfTable = (PMIB_IFTABLE)malloc(dwSize);
        if (pIfTable && GetIfTable(pIfTable, &dwSize, FALSE) == NO_ERROR) {
            unsigned long long rx = 0, tx = 0;
            for (DWORD i = 0; i < pIfTable->dwNumEntries; i++) {
                MIB_IFROW *p = &pIfTable->table[i]; if (p->dwType != IF_TYPE_SOFTWARE_LOOPBACK) { rx += p->dwInOctets; tx += p->dwOutOctets; }
            }
            static unsigned long long p_rx = 0, p_tx = 0;
            if (p_rx > 0) { g_data.rx_kb = (double)(rx - p_rx) / 1024.0; g_data.tx_kb = (double)(tx - p_tx) / 1024.0; }
            p_rx = rx; p_tx = tx;
            g_data.rx_pct = g_data.rx_kb / 1024.0 > 100 ? 100 : g_data.rx_kb / 10.24;
            g_data.tx_pct = g_data.tx_kb / 1024.0 > 100 ? 100 : g_data.tx_kb / 10.24;
        }
        if (pIfTable) free(pIfTable);
    }
}

/* ========== 头部绘制 ========== */
static void DrawHeader(HDC hdc, int W) {
    FillRectC(hdc, 0, 0, W, HEADER_H, CLR_HEADER_BG); FillRectC(hdc, 0, HEADER_H - 2, W, 2, CLR_HEADER_LINE);
    int x1 = 20, w1 = 200, x2 = 240, x3 = 540, w3 = W - 560, cy = 15;
    wchar_t buf[64];

    DrawStrL(hdc, x1, cy, L"CPU", CLR_TITLE, g_fontBold);
    swprintf(buf, 64, L"%.0f%%", g_data.cpu_total); DrawStrR(hdc, x1 + w1, cy - 8, buf, CLR_TEXT, g_fontBig);
    DrawProgress(hdc, x1, cy + 44, w1, 12, g_data.cpu_total);
    for (int i = 0; i < g_data.core_count && i < 8; i++) {
        swprintf(buf, 64, L"%d:%.0f%%", i + 1, g_data.cpu_core[i]); DrawStrL(hdc, x1 + (i%4)*50, cy + 66 + (i/4)*16, buf, CLR_TEXT_DIM, g_fontSmall);
    }

    DrawStrL(hdc, x2, cy, L"Disk", CLR_TITLE, g_fontBold); int ry = cy + 28;
    for (int i = 0; i < g_data.disk_count && i < 5; i++) {
        swprintf(buf, 64, L"%c:", g_data.disks[i].letter); DrawStrL(hdc, x2, ry, buf, CLR_TEXT, g_fontBody);
        DrawProgress(hdc, x2 + 28, ry + 4, 100, 10, g_data.disks[i].storage);
        swprintf(buf, 64, L"%.0f%%", g_data.disks[i].storage); DrawStrL(hdc, x2 + 136, ry, buf, CLR_TEXT, g_fontBody);
        swprintf(buf, 64, L"IO %.0f%%", g_data.disks[i].rate); DrawStrL(hdc, x2 + 182, ry + 2, buf, CLR_TEXT_DIM, g_fontSmall);
        ry += 22;
    }

    DrawStrL(hdc, x3, cy, L"Network", CLR_TITLE, g_fontBold); ry = cy + 28;
    DrawStrL(hdc, x3, ry, L"RX", CLR_TEXT, g_fontSmall); DrawProgress(hdc, x3 + 38, ry + 3, w3 - 60, 8, g_data.rx_pct);
    ry += 22;
    DrawStrL(hdc, x3, ry, L"TX", CLR_TEXT, g_fontSmall); DrawProgress(hdc, x3 + 38, ry + 3, w3 - 60, 8, g_data.tx_pct);
    ry += 24;
    if (g_data.rx_kb >= 1024.0) swprintf(buf, 64, L"D:%.1fM U:%.1fM", g_data.rx_kb/1024.0, g_data.tx_kb/1024.0);
    else swprintf(buf, 64, L"D:%.0fK U:%.0fK", g_data.rx_kb, g_data.tx_kb);
    DrawStrL(hdc, x3, ry, buf, CLR_TEXT_DIM, g_fontSmall);
}

/* ========== 配置读写 ========== */
static void LoadConfig(void) {
    g_ProtectFile   = GetPrivateProfileIntW(L"Config", L"File",   1, BD_CONFIG_FILE);
    g_ProtectReg    = GetPrivateProfileIntW(L"Config", L"Reg",    1, BD_CONFIG_FILE);
    g_ProtectMbr    = GetPrivateProfileIntW(L"Config", L"Mbr",    1, BD_CONFIG_FILE);
    g_ProtectNet    = GetPrivateProfileIntW(L"Config", L"Net",    1, BD_CONFIG_FILE);
    g_ProtectInject = GetPrivateProfileIntW(L"Config", L"Inject", 1, BD_CONFIG_FILE);
    g_ProtectCloud  = GetPrivateProfileIntW(L"Config", L"Cloud",  0, BD_CONFIG_FILE);
}

static void SaveConfig(void) {
    WritePrivateProfileStringW(L"Config", L"File",   g_ProtectFile   ? L"1" : L"0", BD_CONFIG_FILE);
    WritePrivateProfileStringW(L"Config", L"Reg",    g_ProtectReg    ? L"1" : L"0", BD_CONFIG_FILE);
    WritePrivateProfileStringW(L"Config", L"Mbr",    g_ProtectMbr    ? L"1" : L"0", BD_CONFIG_FILE);
    WritePrivateProfileStringW(L"Config", L"Net",    g_ProtectNet    ? L"1" : L"0", BD_CONFIG_FILE);
    WritePrivateProfileStringW(L"Config", L"Inject", g_ProtectInject ? L"1" : L"0", BD_CONFIG_FILE);
    WritePrivateProfileStringW(L"Config", L"Cloud",  g_ProtectCloud  ? L"1" : L"0", BD_CONFIG_FILE);
}

/* ========== 云端试用状态 ========== */
static int ReadIntFile(const wchar_t* path, int def, BOOL createDefault)
{
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) {
        if (createDefault) {
            wchar_t dir[MAX_PATH];
            wcscpy(dir, path);
            wchar_t* s = wcsrchr(dir, L'\\');
            if (s) { *s = 0; SHCreateDirectoryExW(NULL, dir, NULL); }
            f = _wfopen(path, L"w, ccs=UTF-8");
            if (f) { fwprintf(f, L"%d\n", def); fclose(f); }
        }
        return def;
    }
    wchar_t line[64] = {0};
    int v = def;
    if (fgetws(line, 64, f)) v = _wtoi(line);
    fclose(f);
    return v;
}
static void WriteIntFile(const wchar_t* path, int v)
{
    FILE* f = _wfopen(path, L"w, ccs=UTF-8");
    if (f) { fwprintf(f, L"%d\n", v); fclose(f); }
}

#define STORE_DIR   L"C:\\ProgramData\\Microsoft\\Windows\\Caches\\BDProtectData"
#define RESTRICTED  STORE_DIR L"\\Restricted.txt"
#define USERUP      STORE_DIR L"\\UserUp.txt"

static int  CloudMinutes(void) { return ReadIntFile(RESTRICTED, 90, TRUE); }
static int  CloudUserUp(void)  { return ReadIntFile(USERUP, 0, TRUE); }
static BOOL CloudUnlocked(void) { return CloudUserUp() >= 3; }
static BOOL CloudExpired(void) { return !CloudUnlocked() && CloudMinutes() <= 0; }

/* ========== 病毒库是否已下载 ========== */
static BOOL HasWildlist(void)
{
    wchar_t path[MAX_PATH];
    AppFile(L"Wildlist.txt", path, MAX_PATH);
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

/* ========== 样本去重（SHA-256） ========== */
#define SUBMIT_HASH_FILE STORE_DIR L"\\SubmittedHashes.txt"

static BOOL Sha256FileHex(const wchar_t* path, wchar_t* hexOut, int cap)
{
    if (cap < 65) return FALSE;
    BOOL ok = FALSE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PBYTE obj = NULL, digest = NULL, buf = NULL;
    DWORD objLen = 0, digestLen = 0, cb = 0;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(objLen), &cb, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&digestLen, sizeof(digestLen), &cb, 0))) goto done;
    obj = (PBYTE)malloc(objLen);
    digest = (PBYTE)malloc(digestLen);
    buf = (PBYTE)malloc(65536);
    if (!obj || !digest || !buf) goto done;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, obj, objLen, NULL, 0, 0))) goto done;

    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto done;

    for (;;) {
        DWORD got = 0;
        if (!ReadFile(hFile, buf, 65536, &got, NULL)) goto done;
        if (got == 0) break;
        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buf, got, 0))) goto done;
    }
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest, digestLen, 0))) goto done;

    static const wchar_t* hex = L"0123456789abcdef";
    for (DWORD i = 0; i < digestLen && (int)(i * 2 + 2) <= cap; i++) {
        hexOut[i * 2] = hex[digest[i] >> 4];
        hexOut[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    hexOut[digestLen * 2] = 0;
    ok = TRUE;

done:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    free(obj); free(digest); free(buf);
    return ok;
}

static BOOL SampleHashExists(const wchar_t* hash)
{
    if (!hash || !hash[0]) return FALSE;
    FILE* f = _wfopen(SUBMIT_HASH_FILE, L"r, ccs=UTF-8");
    if (!f) return FALSE;
    wchar_t line[128];
    BOOL found = FALSE;
    while (fgetws(line, 128, f)) {
        size_t l = wcslen(line);
        while (l > 0 && (line[l-1] == L'\r' || line[l-1] == L'\n' || line[l-1] == L' ')) line[--l] = 0;
        if (l > 0 && _wcsicmp(line, hash) == 0) { found = TRUE; break; }
    }
    fclose(f);
    return found;
}

static void SampleHashAdd(const wchar_t* hash)
{
    if (!hash || !hash[0]) return;
    SHCreateDirectoryExW(NULL, STORE_DIR, NULL);
    FILE* f = _wfopen(SUBMIT_HASH_FILE, L"a, ccs=UTF-8");
    if (f) { fwprintf(f, L"%s\n", hash); fclose(f); }
}

/* ========== 拦截记录 ========== */
static wchar_t* NextField(wchar_t** p)
{
    if (!p || !*p) return NULL;
    wchar_t* s = *p;
    wchar_t* t = wcschr(s, L'\t');
    if (t) { *t = 0; *p = t + 1; } else *p = NULL;
    return s;
}

static void LoadRecords(void)
{
    const wchar_t* path = bd_cache_path(L"records.log");
    g_recordCount = 0;

    /* 记录文件可能很长：先统计行数，只加载最新的 MAX_RECORDS 条 */
    int total = 0;
    wchar_t line[1024];
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return;
    while (fgetws(line, 1024, f)) total++;
    fclose(f);

    f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return;

    int skip = total > MAX_RECORDS ? total - MAX_RECORDS : 0;
    while (skip > 0 && fgetws(line, 1024, f)) skip--;

    while (fgetws(line, 1024, f) && g_recordCount < MAX_RECORDS) {
        size_t l = wcslen(line);
        while (l > 0 && (line[l-1] == L'\r' || line[l-1] == L'\n')) line[--l] = 0;
        if (!line[0]) continue;
        wchar_t* p = line;
        wchar_t* a = NextField(&p);
        wchar_t* b = NextField(&p);
        wchar_t* c = NextField(&p);
        wchar_t* d = NextField(&p);
        if (!a || !b || !c || !d) continue;
        Record* r = &g_records[g_recordCount++];
        wcsncpy(r->time, a, 31); r->time[31] = 0;
        wcsncpy(r->type, b, 47); r->type[47] = 0;
        wcsncpy(r->target, c, MAX_PATH - 1); r->target[MAX_PATH - 1] = 0;
        wcsncpy(r->choice, d, 31); r->choice[31] = 0;
    }
    fclose(f);
}

/* ========== 云端工具箱 ========== */
static void ParseTools(const wchar_t* file)
{
    g_ToolCount = 0;
    FILE* f = _wfopen(file, L"r, ccs=UTF-8");
    if (!f) return;
    g_bToolsReady = TRUE;
    wchar_t line[512];
    while (fgetws(line, 512, f) && g_ToolCount < MAX_TOOLS) {
        size_t l = wcslen(line);
        while (l > 0 && (line[l-1] == L'\r' || line[l-1] == L'\n' ||
                         line[l-1] == L' '  || line[l-1] == L'\t')) line[--l] = 0;
        wchar_t* p = line;
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p || *p == L'#') continue;

        wchar_t* sp1 = wcschr(p, L' ');
        if (!sp1) continue;
        *sp1 = 0;
        wchar_t* rest = sp1 + 1;
        while (*rest == L' ') rest++;

        wchar_t* sp2 = wcsrchr(rest, L' ');
        if (!sp2) continue;
        *sp2 = 0;
        wchar_t* desc = rest;
        wchar_t* exe = sp2 + 1;
        while (*exe == L' ') exe++;

        wcsncpy(g_ToolName[g_ToolCount], p, 127); g_ToolName[g_ToolCount][127] = 0;
        wcsncpy(g_ToolDesc[g_ToolCount], desc, 255); g_ToolDesc[g_ToolCount][255] = 0;
        wcsncpy(g_ToolExe[g_ToolCount], exe, 127); g_ToolExe[g_ToolCount][127] = 0;
        g_ToolCount++;
    }
    fclose(f);
}

static void LoadCachedTools(void)
{
    ParseTools(bd_cache_path(L"PracticalToolbox.txt"));
}

/* ========== 网络客户端 ========== */
typedef struct { char host[256]; int port; } ServerCfg;

static BOOL LoadServerCfg(ServerCfg* cfg)
{
    wchar_t path[MAX_PATH];
    AppFile(L"IPconfig.ini", path, MAX_PATH);
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
        if (_wcsicmp(key, L"server_ip") == 0) {
            WideCharToMultiByte(CP_UTF8, 0, val, -1, cfg->host, sizeof(cfg->host), NULL, NULL);
        } else if (_wcsicmp(key, L"server_port") == 0) {
            cfg->port = _wtoi(val);
        }
    }
    fclose(f);
    return cfg->host[0] && cfg->port > 0;
}

static BOOL WSAReady(void)
{
    static BOOL ready = FALSE;
    if (!ready) {
        WSADATA w;
        if (WSAStartup(MAKEWORD(2, 2), &w) == 0) ready = TRUE;
    }
    return ready;
}

static BOOL ConnectServer(const ServerCfg* cfg, SOCKET* out)
{
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
        nb = 0;
        ioctlsocket(s, FIONBIO, &nb);

        if (connected) { *out = s; ok = TRUE; break; }
        closesocket(s);
    }
    freeaddrinfo(res);
    return ok;
}

/* 发送 read 命令并读取响应头 "OK <size>\n" */
static BOOL RequestRead(SOCKET s, const char* name, unsigned long long* size)
{
    char req[512];
    sprintf(req, "read %s\r\n", name);
    if (send(s, req, (int)strlen(req), 0) <= 0) return FALSE;

    char line[256]; int i = 0; char c;
    while (i < 255) {
        int r = recv(s, &c, 1, 0);
        if (r <= 0) return FALSE;
        if (c == '\n') break;
        if (c != '\r') line[i++] = c;
    }
    line[i] = 0;
    if (strncmp(line, "OK", 2) != 0) return FALSE;
    char* p = line + 2;
    while (*p == ' ') p++;
    *size = _strtoui64(p, NULL, 10);
    return TRUE;
}

static BOOL RecvExact(SOCKET s, char* buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int r = recv(s, buf + got, (int)(len - got), 0);
        if (r <= 0) return FALSE;
        got += r;
    }
    return TRUE;
}

static char* FetchText(const ServerCfg* cfg, const char* name, size_t* outLen)
{
    SOCKET s;
    if (!ConnectServer(cfg, &s)) return NULL;
    unsigned long long size = 0;
    if (!RequestRead(s, name, &size) || size == 0 || size > 64ULL * 1024 * 1024) {
        closesocket(s);
        return NULL;
    }
    char* buf = (char*)malloc((size_t)size + 1);
    if (!buf) { closesocket(s); return NULL; }
    if (!RecvExact(s, buf, (size_t)size)) { free(buf); closesocket(s); return NULL; }
    buf[size] = 0;
    closesocket(s);
    if (outLen) *outLen = (size_t)size;
    return buf;
}

/* ---------- 下载进度窗口 ---------- */
typedef struct { HWND hwnd, lbl, bar; } DLWIN;

static LRESULT CALLBACK DLProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg) {
        case WM_CTLCOLORSTATIC:
            SetBkMode((HDC)w, TRANSPARENT);
            return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static void PumpMessages(void)
{
    MSG m;
    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

static HWND CreateProgressWindow(DLWIN* d, const wchar_t* title)
{
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DLProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDProgressCls";
    RegisterClassExW(&wc);

    int w = 420, h = 140;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    HWND hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"BDProgressCls", title,
        WS_POPUP | WS_CAPTION, x, y, w, h, NULL, NULL, wc.hInstance, NULL);
    d->hwnd = hwnd;
    d->lbl = CreateWindowW(L"STATIC", L"正在连接服务器...", WS_CHILD | WS_VISIBLE | SS_LEFT,
                           20, 18, 380, 20, hwnd, NULL, NULL, NULL);
    d->bar = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                             20, 48, 380, 22, hwnd, NULL, NULL, NULL);
    SendMessageW(d->bar, PBM_SETRANGE32, 0, 1000);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    return hwnd;
}

static void SetProgressText(DLWIN* d, const wchar_t* text, int permille)
{
    if (!IsWindow(d->hwnd)) return;
    SetWindowTextW(d->lbl, text);
    SendMessageW(d->bar, PBM_SETPOS, permille, 0);
    PumpMessages();
}

static BOOL DownloadFile(const ServerCfg* cfg, const char* name, const wchar_t* dest, const wchar_t* title)
{
    SOCKET s;
    if (!ConnectServer(cfg, &s)) return FALSE;
    unsigned long long size = 0;
    if (!RequestRead(s, name, &size)) { closesocket(s); return FALSE; }

    DLWIN d;
    CreateProgressWindow(&d, title);
    wchar_t msg[256];
    swprintf(msg, 256, L"正在下载 %S ...", name);
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
        swprintf(msg, 256, L"正在下载 %S ... %d%%", name, permille / 10);
        SetProgressText(&d, msg, permille);
    }
    CloseHandle(hFile);
    closesocket(s);
    Sleep(200);
    DestroyWindow(d.hwnd);
    return ok && got == size;
}

/* ---------- 上传样本 ---------- */
static BOOL UploadSample(const ServerCfg* cfg, const wchar_t* sampleName, const wchar_t* filePath)
{
    SOCKET s;
    if (!ConnectServer(cfg, &s)) return FALSE;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { closesocket(s); return FALSE; }

    LARGE_INTEGER li; GetFileSizeEx(hFile, &li);
    unsigned long long size = (unsigned long long)li.QuadPart;
    /* 上传前再校验一次大小，避免绕过界面检查 */
    if (size <= SAMPLE_MIN_SIZE || size >= SAMPLE_MAX_SIZE) { CloseHandle(hFile); closesocket(s); return FALSE; }

    char uname[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, sampleName, -1, uname, sizeof(uname), NULL, NULL);
    for (char* p = uname; *p; p++) {
        if (*p == '"' || *p == '\r' || *p == '\n') *p = '_';
    }

    char req[1024];
    sprintf(req, "up \"%s\" %llu\r\n", uname, size);
    if (send(s, req, (int)strlen(req), 0) <= 0) { CloseHandle(hFile); closesocket(s); return FALSE; }

    char buf[8192];
    DWORD r = 0;
    BOOL ok = TRUE;
    while (ReadFile(hFile, buf, sizeof(buf), &r, NULL) && r > 0) {
        int sent = 0;
        while (sent < (int)r) {
            int n = send(s, buf + sent, (int)r - sent, 0);
            if (n <= 0) { ok = FALSE; break; }
            sent += n;
        }
        if (!ok) break;
    }
    CloseHandle(hFile);

    char resp[128] = {0};
    int n = recv(s, resp, sizeof(resp) - 1, 0);
    closesocket(s);
    return ok && n > 0 && strncmp(resp, "OK", 2) == 0;
}

/* ========== 病毒库查询 ========== */
static BOOL IsHex32(const wchar_t* s)
{
    if (!s) return FALSE;
    for (int i = 0; i < 32; i++) {
        wchar_t c = s[i];
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')))
            return FALSE;
    }
    return s[32] == 0;
}

static BOOL FindWildBySize(unsigned long long size, wchar_t* virusName, int cap)
{
    wchar_t path[MAX_PATH];
    AppFile(L"Wildlist.txt", path, MAX_PATH);
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return FALSE;
    wchar_t line[512];
    BOOL found = FALSE;
    while (fgetws(line, 512, f)) {
        wchar_t* p = line;
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p || *p == L'#' || *p == L';') continue;
        wchar_t* end = NULL;
        unsigned long long sz = (unsigned long long)_wcstoui64(p, &end, 10);
        if (end == p) continue;
        if (sz == size) {
            /* 第二段可能是可选的 32 位 MD5 哈希（新格式：size hash name） */
            wchar_t token[64];
            int ti = 0;
            while (*end && *end != L' ' && *end != L'\t' && ti < 63)
                token[ti++] = *end++;
            token[ti] = 0;
            if (token[0] && IsHex32(token)) {
                while (*end == L' ' || *end == L'\t') end++;
            } else {
                end -= ti;   /* 不是哈希，退回名字起点 */
            }
            wcsncpy(virusName, end, cap - 1);
            virusName[cap - 1] = 0;
            size_t l = wcslen(virusName);
            while (l > 0 && (virusName[l-1] == L'\r' || virusName[l-1] == L'\n')) virusName[--l] = 0;
            found = TRUE;
            break;
        }
    }
    fclose(f);
    return found;
}

/* ========== 计划任务（只保留一个） ========== */
static void EnsureGuardTask(void)
{
    /* 卸载/更新期间不要重新拉起后台防护进程 */
    if (GetFileAttributesW(BD_STOP_FLAG_FILE) != INVALID_FILE_ATTRIBUTES) return;

    wchar_t exePath[MAX_PATH];
    AppFile(L"BDProtect.exe", exePath, MAX_PATH);
    if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) return;

    wchar_t cmd[2048];
    STARTUPINFO si; PROCESS_INFORMATION pi;

    /* 清理旧版本留下的第二个任务 */
    wcscpy(cmd, L"schtasks /delete /tn \"BDAppProtect\" /f");
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    /* 唯一任务：路径含空格时 schtasks 必须给 /tr 再包一层引号 */
    swprintf(cmd, 2048,
             L"schtasks /create /tn \"BDProtect_System_Guard\" /tr \"\\\"%s\\\"\" /sc onlogon /rl highest /f",
             exePath);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    /* 拉起后台防护进程（已在运行就不要重复拉起，否则会出现多个托盘图标） */
    if (!ProcessRunningName(L"BDProtect.exe"))
        ShellExecuteW(NULL, L"open", exePath, L"-silent", g_AppDir, SW_HIDE);
}

/* ========== 提权 ========== */
static BOOL IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    return isAdmin;
}

/* ========== 升级检查线程 ========== */
static void GetField(const char* text, const char* key, char* out, int cap)
{
    out[0] = 0;
    const char* p = strstr(text, key);
    if (!p) return;
    p += strlen(key);
    while (*p == ' ') p++;
    int i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < cap - 1) out[i++] = *p++;
    out[i] = 0;
}

static DWORD WINAPI UpdateCheckThread(LPVOID param)
{
    Sleep(1200);

    ServerCfg cfg;
    if (!LoadServerCfg(&cfg)) return 0;

    /* ---------------- 主程序升级 ---------------- */
    char* remoteVer = FetchText(&cfg, "BDProtectVersion.txt", NULL);
    if (remoteVer) {
        wchar_t localPath[MAX_PATH];
        AppFile(L"BDProtectVersion.txt", localPath, MAX_PATH);

        char localVer[8192] = {0};
        FILE* lf = _wfopen(localPath, L"rb");
        if (lf) { fread(localVer, 1, sizeof(localVer) - 1, lf); fclose(lf); }

        char rv[64], lv[64];
        GetField(remoteVer, "Version:", rv, sizeof(rv));
        GetField(localVer, "Version:", lv, sizeof(lv));

        if (rv[0] && strcmp(rv, lv) != 0) {
            char build[64], author[256];
            GetField(remoteVer, "Build:", build, sizeof(build));
            GetField(remoteVer, "Author:", author, sizeof(author));

            wchar_t wVer[64], wBuild[64], wAuthor[256];
            MultiByteToWideChar(CP_UTF8, 0, rv, -1, wVer, 64);
            MultiByteToWideChar(CP_UTF8, 0, build, -1, wBuild, 64);
            MultiByteToWideChar(CP_UTF8, 0, author, -1, wAuthor, 256);

            wchar_t text[1024];
            swprintf(text, 1024,
                     L"发现新版本，是否立即升级？\n\n版本号：%s\n更新内容：%s\n更新日期：%s",
                     wVer, wAuthor, wBuild);

            if (MessageBoxW(NULL, text, L"BDProtect 自动升级",
                            MB_YESNO | MB_ICONQUESTION | MB_TOPMOST) == IDYES) {
                wchar_t tmpDir[MAX_PATH], tmpExe[MAX_PATH];
                GetTempPathW(MAX_PATH, tmpDir);
                swprintf(tmpExe, MAX_PATH, L"%sBDProtectSetup.exe", tmpDir);

                if (DownloadFile(&cfg, "BDProtectSetup.exe", tmpExe, L"正在下载更新程序")) {
                    /* 下载成功后再写本地版本号，避免失败后误判为已升级 */
                    FILE* f = _wfopen(localPath, L"wb");
                    if (f) { fwrite(remoteVer, 1, strlen(remoteVer), f); fclose(f); }
                    ShellExecuteW(NULL, L"open", tmpExe, L"/UPDATE", NULL, SW_SHOWNORMAL);
                    free(remoteVer);
                    return 0;
                } else {
                    MessageBoxW(NULL, L"更新程序下载失败，请检查网络后重试。", L"升级失败",
                                MB_OK | MB_ICONERROR | MB_TOPMOST);
                }
            }
        }
        free(remoteVer);
    }

    /* ---------------- 病毒库升级 ---------------- */
    char* remoteWv = FetchText(&cfg, "WildlistVersion.txt", NULL);
    if (remoteWv) {
        wchar_t localPath[MAX_PATH], wlPath[MAX_PATH];
        AppFile(L"WildlistVersion.txt", localPath, MAX_PATH);
        AppFile(L"Wildlist.txt", wlPath, MAX_PATH);

        /* 安装包不再自带病毒库：本机没有病毒库时直接静默下载，不打扰用户 */
        BOOL firstDb = (GetFileAttributesW(wlPath) == INVALID_FILE_ATTRIBUTES);

        char localWv[4096] = {0};
        FILE* lf = _wfopen(localPath, L"rb");
        if (lf) { fread(localWv, 1, sizeof(localWv) - 1, lf); fclose(lf); }

        /* 去掉末尾空白后比较 */
        char* a = remoteWv; char* b = localWv;
        size_t la = strlen(a), lb = strlen(b);
        while (la > 0 && (a[la-1] == '\r' || a[la-1] == '\n' || a[la-1] == ' ')) a[--la] = 0;
        while (lb > 0 && (b[lb-1] == '\r' || b[lb-1] == '\n' || b[lb-1] == ' ')) b[--lb] = 0;

        if (la > 0 && (firstDb || strcmp(a, b) != 0)) {
            if (firstDb ||
                MessageBoxW(NULL, L"病毒库有更新，是否立即更新？", L"BDProtect 病毒库升级",
                            MB_YESNO | MB_ICONQUESTION | MB_TOPMOST) == IDYES) {
                if (DownloadFile(&cfg, "Wildlist.txt", wlPath, L"正在下载病毒库")) {
                    FILE* f = _wfopen(localPath, L"wb");
                    if (f) { fwrite(remoteWv, 1, strlen(remoteWv), f); fclose(f); }
                }
            }
        }
        free(remoteWv);
    }

    /* ---------------- 云端工具箱列表 ---------------- */
    char* tb = FetchText(&cfg, "PracticalToolbox.txt", NULL);
    if (tb) {
        FILE* f = _wfopen(bd_cache_path(L"PracticalToolbox.txt"), L"wb");
        if (f) { fwrite(tb, 1, strlen(tb), f); fclose(f); }
        free(tb);
        if (g_hMainWnd) PostMessageW(g_hMainWnd, WM_APP_TOOLS_REFRESH, 0, 0);
    }
    return 0;
}

/* ========== 样本名称输入对话框 ========== */
typedef struct { wchar_t name[128]; wchar_t defName[128]; BOOL ok; HWND edit; HWND hwnd; } SAMPLE_DLG;

static WNDPROC g_oldEditProc = NULL;

static LRESULT CALLBACK EditSubProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    if (msg == WM_KEYDOWN && w == VK_RETURN) {
        SendMessageW(GetParent(hwnd), WM_COMMAND, IDOK, 0);
        return 0;
    }
    if (msg == WM_KEYDOWN && w == VK_ESCAPE) {
        SendMessageW(GetParent(hwnd), WM_COMMAND, IDCANCEL, 0);
        return 0;
    }
    return CallWindowProcW(g_oldEditProc, hwnd, msg, w, l);
}

static LRESULT CALLBACK SampleDlgProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    SAMPLE_DLG* d = (SAMPLE_DLG*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
        case WM_CREATE: {
            d = (SAMPLE_DLG*)((CREATESTRUCTW*)l)->lpCreateParams;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)d);
            d->hwnd = hwnd;
            CreateWindowW(L"STATIC", L"请输入提交样本的名称：", WS_CHILD | WS_VISIBLE | SS_LEFT,
                          20, 16, 360, 22, hwnd, NULL, NULL, NULL);
            d->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                          20, 44, 360, 26, hwnd, (HMENU)100, NULL, NULL);
            SendMessageW(d->edit, EM_SETLIMITTEXT, 100, 0);
            CreateWindowW(L"BUTTON", L"确认提交", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                          130, 88, 110, 32, hwnd, (HMENU)IDOK, NULL, NULL);
            CreateWindowW(L"BUTTON", L"取消提交", WS_CHILD | WS_VISIBLE,
                          255, 88, 110, 32, hwnd, (HMENU)IDCANCEL, NULL, NULL);
            g_oldEditProc = (WNDPROC)SetWindowLongPtrW(d->edit, GWLP_WNDPROC, (LONG_PTR)EditSubProc);
            if (d->defName[0]) SetWindowTextW(d->edit, d->defName);
            SetFocus(d->edit);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDOK) {
                GetWindowTextW(d->edit, d->name, 128);
                if (d->name[0] == 0) {
                    MessageBoxW(hwnd, L"请输入样本名称。", L"提示", MB_OK | MB_ICONINFORMATION);
                    return 0;
                }
                d->ok = TRUE;
                DestroyWindow(hwnd);
            } else if (LOWORD(w) == IDCANCEL) {
                DestroyWindow(hwnd);
            }
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static BOOL PromptSampleName(HWND owner, const wchar_t* defName, wchar_t* out, int cap)
{
    SAMPLE_DLG d;
    ZeroMemory(&d, sizeof(d));
    if (defName) {
        wcsncpy(d.defName, defName, 127);
        d.defName[127] = 0;
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = SampleDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BDSampleDlgCls";
    RegisterClassExW(&wc);

    int w = 410, h = 170;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    EnableWindow(owner, FALSE);
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"BDSampleDlgCls",
                                L"提交病毒样本",
                                WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                x, y, w, h, owner, NULL, wc.hInstance, &d);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (IsWindow(hwnd)) {
        if (GetMessageW(&msg, NULL, 0, 0) <= 0) break;
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);

    if (d.ok) {
        wcsncpy(out, d.name, cap - 1);
        out[cap - 1] = 0;
    }
    return d.ok;
}

/* ========== 上传线程 ========== */
typedef struct {
    wchar_t path[MAX_PATH];
    wchar_t name[128];
    wchar_t hash[65];
} UPLOAD_ARG;

static DWORD WINAPI UploadThread(LPVOID p)
{
    UPLOAD_ARG* arg = (UPLOAD_ARG*)p;
    ServerCfg cfg;
    BOOL ok = FALSE;
    if (LoadServerCfg(&cfg)) ok = UploadSample(&cfg, arg->name, arg->path);

    BOOL unlock = FALSE;
    if (ok) {
        /* 只有真正上传成功的样本才登记哈希，避免失败后无法重试 */
        SampleHashAdd(arg->hash);
        int cnt = CloudUserUp() + 1;
        WriteIntFile(USERUP, cnt);
        if (cnt >= 3) unlock = TRUE;
    }

    if (g_hMainWnd)
        PostMessageW(g_hMainWnd, WM_APP_UPLOAD_DONE, ok ? 1 : 0, unlock ? 1 : 0);

    free(arg);
    return 0;
}

/* ========== 云端工具下载并运行 ========== */
typedef struct { wchar_t exe[128]; } TOOL_ARG;

static DWORD WINAPI ToolDownloadThread(LPVOID p)
{
    TOOL_ARG* arg = (TOOL_ARG*)p;
    ServerCfg cfg;
    wchar_t dest[MAX_PATH];
    swprintf(dest, MAX_PATH, L"%s\\%s", g_AppDir, arg->exe);

    wchar_t base[128];
    wcsncpy(base, arg->exe, 127); base[127] = 0;
    wchar_t* dot = wcsrchr(base, L'.');
    if (dot) *dot = 0;

    char cmd[256];
    WideCharToMultiByte(CP_UTF8, 0, base, -1, cmd, sizeof(cmd), NULL, NULL);

    BOOL ok = FALSE;
    if (LoadServerCfg(&cfg)) {
        ok = DownloadFile(&cfg, cmd, dest, L"正在下载实用工具");
        if (!ok) {
            /* 有些服务器上的文件名带 .exe 后缀 */
            char cmd2[256];
            WideCharToMultiByte(CP_UTF8, 0, arg->exe, -1, cmd2, sizeof(cmd2), NULL, NULL);
            ok = DownloadFile(&cfg, cmd2, dest, L"正在下载实用工具");
        }
    }

    if (ok) {
        ShellExecuteW(NULL, L"open", dest, NULL, g_AppDir, SW_SHOWNORMAL);
    } else {
        MessageBoxW(NULL, L"工具下载失败，请检查网络或服务器配置。", L"实用工具箱",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
    }
    if (g_hMainWnd) PostMessageW(g_hMainWnd, WM_APP_TOOLS_REFRESH, 0, 0);
    free(arg);
    return 0;
}

/* ========== 病毒库下载 ========== */
static DWORD WINAPI DbDownloadThread(LPVOID p)
{
    HWND hwnd = (HWND)p;
    ServerCfg cfg;
    BOOL ok = FALSE;

    if (LoadServerCfg(&cfg)) {
        wchar_t wl[MAX_PATH], wv[MAX_PATH];
        AppFile(L"Wildlist.txt", wl, MAX_PATH);
        AppFile(L"WildlistVersion.txt", wv, MAX_PATH);
        ok = DownloadFile(&cfg, "Wildlist.txt", wl, L"正在下载病毒库");
        if (ok) DownloadFile(&cfg, "WildlistVersion.txt", wv, L"正在下载病毒库版本");
    }

    if (hwnd) PostMessageW(hwnd, WM_APP_DB_DONE, ok ? 1 : 0, 0);
    return 0;
}

/* ========== 主界面绘制 ========== */
static void SettingCardRect(int idx, int W, int* x, int* y, int* w, int* h)
{
    int boxW = (W - 40 - 15) / 2;
    *x = 20 + (idx % 2) * (boxW + 15);
    *y = CARD_TOP + (idx / 2) * (CARD_H + CARD_GAP);
    *w = boxW;
    *h = CARD_H;
}

static int RecordDisplayCount(void)
{
    return g_recordCount < RECORD_ROWS ? g_recordCount : RECORD_ROWS;
}

static BOOL ToolExists(int idx)
{
    if (idx < 0 || idx >= g_ToolCount) return FALSE;
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%s\\%s", g_AppDir, g_ToolExe[idx]);
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static void DrawUI(HDC hdc, int W, int H) {
    FillRectC(hdc, 0, 0, W, H, CLR_BODY_BG);
    DrawHeader(hdc, W);

    int y = SETTINGS_Y;
    DrawStrL(hdc, 20, y, L"实时防护设置", CLR_CARD_TEXT, g_fontBold);

    BOOL dbReady = g_hasWildlist;
    BOOL states[6] = { g_ProtectFile, g_ProtectReg, g_ProtectMbr, g_ProtectNet, g_ProtectInject,
                       g_ProtectCloud && dbReady };
    const wchar_t* names[6] = { L"文件防修改", L"注册表防篡改", L"MBR防篡改",
                                L"网络防护", L"进程注入防护", L"比对云端病毒库" };
    const wchar_t* tips[6] = {
        L"监控文件被批量修改或删除",
        L"保护开机启动项等关键注册表",
        L"防止主引导记录被恶意改写",
        L"拦截程序擅自建立网络连接",
        L"阻止未知线程注入系统进程",
        NULL
    };
    for (int i = 0; i < 6; i++) {
        int cx, cy, boxW, boxH;
        SettingCardRect(i, W, &cx, &cy, &boxW, &boxH);

        COLORREF bg = (g_HoverSetting == i) ? CLR_CARD_HOVER : CLR_CARD_BG;
        FillRoundC(hdc, cx, cy, boxW, boxH, 6, bg);

        HPEN p = CreatePen(PS_SOLID, 1, CLR_CARD_BORDER); HGDIOBJ op = SelectObject(hdc, p);
        HGDIOBJ ob = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, cx, cy, cx + boxW, cy + boxH, 6, 6);
        SelectObject(hdc, op); SelectObject(hdc, ob); DeleteObject(p);

        BOOL disabled = (i == 5 && !dbReady);
        DrawStrL(hdc, cx + 15, cy + 5, names[i],
                 disabled ? RGB(160, 168, 182) : CLR_CARD_TEXT, g_fontBody);

        if (i == 5) {
            wchar_t sub[96];
            if (!dbReady) {
                swprintf(sub, 96, L"尚未下载病毒库，点击右侧下载");
            } else if (CloudUnlocked()) {
                swprintf(sub, 96, L"永久版 · 拖入文件可提交样本");
            } else {
                swprintf(sub, 96, L"试用剩余 %d 分钟 · 拖入文件提交样本", CloudMinutes());
            }
            DrawStrEllipsis(hdc, cx + 15, cy + 22, boxW - 50, 16, sub, RGB(130, 140, 158), g_fontSmall);
        } else {
            DrawStrEllipsis(hdc, cx + 15, cy + 22, boxW - 50, 16, tips[i], RGB(130, 140, 158), g_fontSmall);
        }

        if (disabled) {
            int bw = 52, bh = 22;
            int bx = cx + boxW - bw - 12, by = cy + (boxH - bh) / 2;
            FillRoundC(hdc, bx, by, bw, bh, 11, CLR_HEADER_LINE);
            DrawStrL(hdc, bx + 12, by + 3, g_dbDownloading ? L"..." : L"下载", RGB(255,255,255), g_fontSmall);
        } else {
            int chkS = 16, chkX = cx + boxW - 30, chkY = cy + (boxH - chkS) / 2;
            if (states[i]) {
                FillRoundC(hdc, chkX, chkY, chkS, chkS, 3, CLR_HEADER_LINE);
                DrawStrL(hdc, chkX + 4, chkY + 1, L"v", RGB(255,255,255), g_fontSmall);
            } else {
                FillRoundC(hdc, chkX, chkY, chkS, chkS, 3, RGB(200,200,200));
            }
        }
    }

    /* 拦截记录 */
    DrawStrL(hdc, 20, RECORDS_Y, L"拦截记录", CLR_CARD_TEXT, g_fontBold);
    DrawStrR(hdc, W - 105, RECORDS_Y + 1, L"点击记录可更改选择", RGB(150, 158, 172), g_fontSmall);
    DrawStrR(hdc, W - 20, RECORDS_Y + 1, L"查看更多 >", CLR_ACCENT, g_fontSmall);

    int shown = RecordDisplayCount();
    if (shown == 0) {
        DrawStrL(hdc, 22, RECORD_TOP + 4, L"暂无拦截记录", RGB(150, 158, 172), g_fontSmall);
    }
    for (int i = 0; i < shown; i++) {
        int ri = g_recordCount - 1 - i;
        Record* r = &g_records[ri];
        int ry = RECORD_TOP + i * RECORD_ROW_H;

        COLORREF bg = (g_HoverRecord == i) ? CLR_TOOL_HOVER : CLR_CARD_BG;
        FillRoundC(hdc, 20, ry, W - 40, RECORD_ROW_H - 3, 5, bg);

        wchar_t tshort[32];
        if (wcslen(r->time) >= 16) {
            wcsncpy(tshort, r->time + 5, 11); tshort[11] = 0;
        } else {
            wcsncpy(tshort, r->time, 31); tshort[31] = 0;
        }

        DrawStrL(hdc, 32, ry + 5, tshort, RGB(150, 158, 172), g_fontSmall);
        DrawStrL(hdc, 132, ry + 5, r->type, CLR_CARD_TEXT, g_fontSmall);
        DrawStrEllipsis(hdc, 232, ry + 4, W - 232 - 160, RECORD_ROW_H - 8, r->target, RGB(90, 100, 118), g_fontSmall);
        COLORREF cc = RGB(56, 132, 220);
        if (wcscmp(r->choice, L"急停") == 0 || wcscmp(r->choice, L"恢复并急停") == 0 ||
            wcscmp(r->choice, L"拦截运行") == 0 || wcscmp(r->choice, L"已拦截") == 0)
            cc = RGB(220, 80, 80);
        DrawStrR(hdc, W - 34, ry + 5, r->choice, cc, g_fontSmall);
    }

    /* 实用工具箱 */
    DrawStrL(hdc, 20, TOOLS_Y, L"实用工具箱", CLR_CARD_TEXT, g_fontBold);
    DrawStrR(hdc, W - 20, TOOLS_Y + 1, L"双击运行 · 云端获取", RGB(150, 158, 172), g_fontSmall);

    int toolsHeight = H - TOOL_TOP;
    int contentH = g_ToolCount * 60;
    int maxScroll = contentH - toolsHeight + 20;
    if (maxScroll < 0) maxScroll = 0;
    if (g_ScrollY > maxScroll) g_ScrollY = maxScroll;
    if (g_ScrollY < 0) g_ScrollY = 0;

    SCROLLINFO si = { sizeof(si) };
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0; si.nMax = contentH + 20; si.nPage = toolsHeight; si.nPos = g_ScrollY;
    SetScrollInfo(g_hMainWnd, SB_VERT, &si, TRUE);

    if (g_ToolCount == 0) {
        const wchar_t* tip = g_bToolsReady ? L"暂无可用工具" : L"正在从云端获取工具列表...";
        DrawStrL(hdc, 22, TOOL_TOP + 6, tip, RGB(150, 158, 172), g_fontSmall);
    }

    /* 工具箱内容必须裁剪在 TOOL_TOP 以下，否则向上滚动时会盖住“实用工具箱”标题 */
    int savedDC = SaveDC(hdc);
    IntersectClipRect(hdc, 0, TOOL_TOP - 2, W, H);

    for (int i = 0; i < g_ToolCount; i++) {
        int btnY = TOOL_TOP + i * 60 - g_ScrollY;
        if (btnY + 50 < TOOL_TOP || btnY > H) continue;

        COLORREF bg = (g_HoverTool == i) ? CLR_TOOL_HOVER : CLR_TOOL_BG;
        FillRoundC(hdc, 20, btnY, W - 40, 50, 6, bg);

        HPEN p = CreatePen(PS_SOLID, 1, CLR_CARD_BORDER); HGDIOBJ op = SelectObject(hdc, p);
        HGDIOBJ ob = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, 20, btnY, W - 20, btnY + 50, 6, 6);
        SelectObject(hdc, op); SelectObject(hdc, ob); DeleteObject(p);

        DrawStrL(hdc, 40, btnY + 15, g_ToolName[i], CLR_TOOL_TEXT, g_fontBody);

        /* 已下载显示“打开”，未下载显示“下载”，两者分开 */
        BOOL exists = ToolExists(i);
        const wchar_t* action = exists ? L"打开" : L"下载";
        COLORREF ac = exists ? CLR_ACCENT : RGB(214, 120, 40);
        int bw = 48, bh = 26, bx = W - 20 - bw - 14, by = btnY + 12;
        FillRoundC(hdc, bx, by, bw, bh, 13, exists ? RGB(232, 242, 255) : RGB(255, 244, 230));
        DrawStrL(hdc, bx + 11, by + 5, action, ac, g_fontBody);
    }

    RestoreDC(hdc, savedDC);

    /* 工具描述悬浮提示 */
    if (g_HoverTool >= 0 && g_HoverTool < g_ToolCount) {
        POINT pt; GetCursorPos(&pt); ScreenToClient(g_hMainWnd, &pt);
        const wchar_t* desc = g_ToolDesc[g_HoverTool];
        HFONT old = (HFONT)SelectObject(hdc, g_fontSmall);
        SIZE sz; GetTextExtentPoint32W(hdc, desc, (int)wcslen(desc), &sz);

        int tw = sz.cx + 20, th = sz.cy + 10;
        int tx = pt.x + 15, ty = pt.y + 15;
        if (tx + tw > W) tx = W - tw - 5;
        if (ty + th > H) ty = pt.y - th - 10;
        FillRoundC(hdc, tx, ty, tw, th, 4, RGB(40, 40, 40));
        DrawStrL(hdc, tx + 10, ty + 5, desc, RGB(255, 255, 255), g_fontSmall);
        SelectObject(hdc, old);
    }
}

/* ========== 交互辅助 ========== */
static void ShowExpiredMessage(HWND hwnd)
{
    MessageBoxW(hwnd,
                L"云端病毒库比对试用已到期。\n\n解决方法：提交三个病毒样本，以获取永久版。",
                L"试用已到期", MB_OK | MB_ICONINFORMATION);
}

/* ---------- 记录改选后的“真正执行” ---------- */

static void TriggerBsodNow(void)
{
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) return;
    typedef NTSTATUS (WINAPI *RtlAdjustPrivilege_t)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
    typedef NTSTATUS (WINAPI *NtRaiseHardError_t)(NTSTATUS, ULONG, ULONG, PULONG, ULONG, PULONG);
    RtlAdjustPrivilege_t adj = (RtlAdjustPrivilege_t)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    NtRaiseHardError_t raise = (NtRaiseHardError_t)GetProcAddress(ntdll, "NtRaiseHardError");
    if (adj && raise) {
        BOOLEAN prev = FALSE; ULONG resp = 0;
        adj(19, TRUE, FALSE, &prev);
        raise(0xC0000350, 0, 0, NULL, 6, &resp);
    }
}

static void BackupPathFor(const wchar_t* orig, wchar_t* out, int cap)
{
    /* 缓存目录\FileBackup\<原始路径，冒号替换为下划线> */
    size_t base = swprintf(out, cap, L"%s\\%s", bd_cache_path(L"FileBackup"), orig) - wcslen(orig);
    for (size_t i = base; out[i]; i++)
        if (out[i] == L':') out[i] = L'_';
}

static BOOL RollbackFileFromBackup(const wchar_t* path)
{
    wchar_t bak[MAX_PATH * 2];
    BackupPathFor(path, bak, MAX_PATH * 2);
    if (GetFileAttributesW(bak) == INVALID_FILE_ATTRIBUTES) return FALSE;

    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    wchar_t dir[MAX_PATH];
    wcsncpy(dir, path, MAX_PATH - 1); dir[MAX_PATH - 1] = 0;
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) { *slash = 0; SHCreateDirectoryExW(NULL, dir, NULL); }
    return CopyFileW(bak, path, FALSE) ? TRUE : FALSE;
}

static BOOL RestoreMbrBackup(void)
{
    HANDLE src = CreateFileW(bd_cache_path(L"mbr.bak"), GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (src == INVALID_HANDLE_VALUE) return FALSE;
    BYTE buf[512]; DWORD got = 0;
    BOOL ok = ReadFile(src, buf, 512, &got, NULL) && got == 512;
    CloseHandle(src);
    if (!ok) return FALSE;

    HANDLE drive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (drive == INVALID_HANDLE_VALUE) return FALSE;
    DWORD wrote = 0;
    SetFilePointer(drive, 0, NULL, FILE_BEGIN);
    ok = WriteFile(drive, buf, 512, &wrote, NULL) && wrote == 512;
    CloseHandle(drive);
    return ok;
}

static void SetIfeoBlock(const wchar_t* exePath, BOOL block)
{
    const wchar_t* base = wcsrchr(exePath, L'\\');
    base = base ? base + 1 : exePath;
    wchar_t regPath[512];
    swprintf(regPath, 512,
             L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", base);

    if (block) {
        wchar_t dbg[MAX_PATH + 32];
        swprintf(dbg, MAX_PATH + 32, L"\"%s\\BDProtect.exe\" /blocked", g_AppDir);
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0,
                            KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)dbg,
                           (DWORD)((wcslen(dbg) + 1) * sizeof(wchar_t)));
            RegCloseKey(hKey);
        }
    } else {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, L"Debugger");
            RegCloseKey(hKey);
        }
    }
}

static void NetListRemove(const wchar_t* file, const wchar_t* path)
{
    FILE* f = _wfopen(file, L"r, ccs=UTF-8");
    if (!f) return;
    wchar_t** lines = NULL; int n = 0, cap = 64;
    lines = (wchar_t**)malloc(sizeof(wchar_t*) * cap);
    if (!lines) { fclose(f); return; }

    wchar_t buf[MAX_PATH + 8];
    while (fgetws(buf, MAX_PATH + 8, f)) {
        size_t l = wcslen(buf);
        while (l > 0 && (buf[l-1] == L'\r' || buf[l-1] == L'\n')) buf[--l] = 0;
        if (l == 0) continue;
        if (_wcsicmp(buf, path) == 0) continue;
        if (n == cap) {
            cap *= 2;
            wchar_t** nl = (wchar_t**)realloc(lines, sizeof(wchar_t*) * cap);
            if (!nl) break;
            lines = nl;
        }
        lines[n] = (wchar_t*)malloc((l + 2) * sizeof(wchar_t));
        if (!lines[n]) break;
        wcscpy(lines[n], buf);
        n++;
    }
    fclose(f);

    f = _wfopen(file, L"w, ccs=UTF-8");
    if (f) {
        for (int i = 0; i < n; i++) fwprintf(f, L"%s\n", lines[i]);
        fclose(f);
    }
    for (int i = 0; i < n; i++) free(lines[i]);
    free(lines);
}

static void NetListAdd(const wchar_t* file, const wchar_t* path)
{
    FILE* f = _wfopen(file, L"r, ccs=UTF-8");
    if (f) {
        wchar_t buf[MAX_PATH + 8];
        while (fgetws(buf, MAX_PATH + 8, f)) {
            size_t l = wcslen(buf);
            while (l > 0 && (buf[l-1] == L'\r' || buf[l-1] == L'\n')) buf[--l] = 0;
            if (_wcsicmp(buf, path) == 0) { fclose(f); return; }
        }
        fclose(f);
    }
    f = _wfopen(file, L"a, ccs=UTF-8");
    if (f) { fwprintf(f, L"%s\n", path); fclose(f); }
}

/* ---------- 注册表快照恢复（与 bd_reg.c 的文件格式一致） ---------- */
typedef struct {
    wchar_t name[256];
    DWORD type;
    DWORD size;
    BYTE* data;
} MREG_VAL;

static void FreeMRegVals(MREG_VAL* vals, int n)
{
    for (int i = 0; i < n; i++) { free(vals[i].data); vals[i].data = NULL; }
}

static int LoadMRegSnapshot(int idx, MREG_VAL* vals, int cap)
{
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%s\\%d.snap", bd_cache_path(L"RegBackup"), idx);
    FILE* f = _wfopen(path, L"rb");
    if (!f) return 0;

    DWORD magic = 0, count = 0;
    if (fread(&magic, sizeof(DWORD), 1, f) != 1 || magic != 0x52474B53 ||
        fread(&count, sizeof(DWORD), 1, f) != 1 || count > (DWORD)cap) {
        fclose(f); return 0;
    }

    int n = 0;
    for (DWORD i = 0; i < count; i++) {
        DWORD type = 0, nameChars = 0, dataSize = 0;
        if (fread(&type, sizeof(DWORD), 1, f) != 1 ||
            fread(&nameChars, sizeof(DWORD), 1, f) != 1 ||
            fread(&dataSize, sizeof(DWORD), 1, f) != 1) break;
        if (nameChars > 255 || dataSize > 1024 * 1024) break;

        MREG_VAL* v = &vals[n];
        if (fread(v->name, sizeof(wchar_t), nameChars, f) != nameChars) break;
        v->name[nameChars] = 0;
        v->type = type;
        v->size = dataSize;
        v->data = (BYTE*)malloc(dataSize ? dataSize : 1);
        if (!v->data) break;
        if (dataSize && fread(v->data, 1, dataSize, f) != dataSize) break;
        n++;
    }
    fclose(f);
    return n;
}

static BOOL RegRestoreSnapshotForTarget(const wchar_t* target)
{
    int idx = -1;
    FILE* f = _wfopen(bd_cache_path(L"RegBackup\\index.txt"), L"r, ccs=UTF-8");
    if (f) {
        wchar_t line[1024];
        while (fgetws(line, 1024, f)) {
            wchar_t* p = line;
            wchar_t* a = NextField(&p);
            wchar_t* b = NextField(&p);
            if (!a || !b) continue;
            size_t l = wcslen(b);
            while (l > 0 && (b[l-1] == L'\r' || b[l-1] == L'\n')) b[--l] = 0;
            if (_wcsicmp(b, target) == 0) { idx = _wtoi(a); break; }
        }
        fclose(f);
    }
    if (idx < 0) return FALSE;

    MREG_VAL vals[256];
    ZeroMemory(vals, sizeof(vals));
    int n = LoadMRegSnapshot(idx, vals, 256);
    if (n <= 0) { FreeMRegVals(vals, n); return FALSE; }

    HKEY root; const wchar_t* sub;
    if (_wcsnicmp(target, L"HKLM\\", 5) == 0) { root = HKEY_LOCAL_MACHINE; sub = target + 5; }
    else if (_wcsnicmp(target, L"HKCU\\", 5) == 0) { root = HKEY_CURRENT_USER; sub = target + 5; }
    else { FreeMRegVals(vals, n); return FALSE; }

    HKEY hKey;
    BOOL ok = FALSE;
    if (RegOpenKeyExW(root, sub, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        for (DWORD i = 0; ; i++) {
            wchar_t name[256]; DWORD nameLen = 256;
            LONG r = RegEnumValueW(hKey, i, name, &nameLen, NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) break;
            BOOL keep = FALSE;
            for (int j = 0; j < n; j++)
                if (_wcsicmp(vals[j].name, name) == 0) { keep = TRUE; break; }
            if (!keep && RegDeleteValueW(hKey, name) == ERROR_SUCCESS) i--;
        }
        for (int j = 0; j < n; j++)
            RegSetValueExW(hKey, vals[j].name, 0, vals[j].type, vals[j].data, vals[j].size);
        RegCloseKey(hKey);
        ok = TRUE;

        /* 通知后台进程重新载入基线，避免立刻再次告警 */
        wchar_t flag[MAX_PATH];
        swprintf(flag, MAX_PATH, L"%s\\reload_%d.flag", bd_cache_path(L"RegBackup"), idx);
        HANDLE h = CreateFileW(flag, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    FreeMRegVals(vals, n);
    return ok;
}

static void ApplyRecordChoice(HWND hwnd, Record* r, const wchar_t* choice)
{
    if (wcscmp(r->type, L"文件防护") == 0) {
        if (wcscmp(choice, L"回滚") == 0) {
            BOOL ok = RollbackFileFromBackup(r->target);
            MessageBoxW(hwnd, ok ? L"已按备份恢复该文件。" : L"没有找到该文件的备份，无法回滚。",
                        L"回滚结果", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONWARNING));
        } else if (wcscmp(choice, L"同意") == 0) {
            /* 信任当前内容：同步更新备份 */
            wchar_t bak[MAX_PATH * 2];
            BackupPathFor(r->target, bak, MAX_PATH * 2);
            CopyFileW(r->target, bak, FALSE);
        } else if (wcscmp(choice, L"急停") == 0) {
            if (MessageBoxW(hwnd, L"立即触发系统蓝屏（急停）吗？\n未保存的工作将会丢失。",
                            L"急停确认", MB_YESNO | MB_ICONWARNING) == IDYES)
                TriggerBsodNow();
        }
    } else if (wcscmp(r->type, L"注册表防护") == 0) {
        if (wcscmp(choice, L"回滚") == 0) {
            BOOL ok = RegRestoreSnapshotForTarget(r->target);
            MessageBoxW(hwnd, ok ? L"注册表已恢复到修改前的状态。" : L"没有找到可用的注册表快照，无法回滚。",
                        L"回滚结果", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONWARNING));
        } else if (wcscmp(choice, L"急停") == 0) {
            if (MessageBoxW(hwnd, L"立即触发系统蓝屏（急停）吗？\n未保存的工作将会丢失。",
                            L"急停确认", MB_YESNO | MB_ICONWARNING) == IDYES)
                TriggerBsodNow();
        }
    } else if (wcscmp(r->type, L"MBR防护") == 0) {
        if (wcscmp(choice, L"恢复并急停") == 0) {
            if (MessageBoxW(hwnd, L"将恢复主引导记录并立即触发蓝屏，继续吗？",
                            L"恢复并急停", MB_YESNO | MB_ICONWARNING) == IDYES) {
                if (RestoreMbrBackup()) TriggerBsodNow();
                else MessageBoxW(hwnd, L"MBR 备份不存在或恢复失败。", L"Mbr", MB_OK | MB_ICONERROR);
            }
        }
    } else if (wcscmp(r->type, L"网络防护") == 0) {
        const wchar_t* black = bd_cache_path(L"net_black.txt");
        wchar_t white[MAX_PATH];
        wcscpy(white, bd_cache_path(L"net_white.txt"));
        if (wcscmp(choice, L"同意联网") == 0) {
            NetListRemove(black, r->target);
            NetListAdd(white, r->target);
            NetListRemove(black, r->target);
            NetListAdd(white, r->target);
        } else if (wcscmp(choice, L"禁止联网") == 0) {
            NetListRemove(white, r->target);
            NetListAdd(black, r->target);
        } else if (wcscmp(choice, L"禁用程序") == 0) {
            if (MessageBoxW(hwnd, L"禁用后该程序将无法启动，确定执行吗？",
                            L"禁用程序", MB_YESNO | MB_ICONWARNING) == IDYES) {
                NetListRemove(white, r->target);
                NetListAdd(black, r->target);
                SetIfeoBlock(r->target, TRUE);
            }
        }
    } else if (wcscmp(r->type, L"进程注入防护") == 0) {
        /* 线程已被终止，只能更新记录，无法事后放行 */
    } else {
        /* 云端病毒库 */
        if (wcscmp(choice, L"拦截运行") == 0) SetIfeoBlock(r->target, TRUE);
        else if (wcscmp(choice, L"同意运行") == 0) SetIfeoBlock(r->target, FALSE);
    }
}

/* 只改写目标记录行，保留后台进程新追加的记录 */
static void UpdateRecordChoiceInFile(const Record* r)
{
    const wchar_t* path = bd_cache_path(L"records.log");
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return;

    wchar_t** lines = NULL;
    int count = 0, cap = 128;
    lines = (wchar_t**)malloc(sizeof(wchar_t*) * cap);
    if (!lines) { fclose(f); return; }

    wchar_t buf[4096];
    int match = -1;
    while (fgetws(buf, 4096, f)) {
        if (count == cap) {
            cap *= 2;
            wchar_t** nl = (wchar_t**)realloc(lines, sizeof(wchar_t*) * cap);
            if (!nl) break;
            lines = nl;
        }
        size_t l = wcslen(buf);
        lines[count] = (wchar_t*)malloc((l + 1) * sizeof(wchar_t));
        if (!lines[count]) break;
        wcscpy(lines[count], buf);

        wchar_t tmp[4096];
        wcsncpy(tmp, buf, 4095); tmp[4095] = 0;
        wchar_t* p = tmp;
        wchar_t* a = NextField(&p);
        wchar_t* b = NextField(&p);
        wchar_t* c = NextField(&p);
        if (a && b && c && wcscmp(a, r->time) == 0 &&
            wcscmp(b, r->type) == 0 && wcscmp(c, r->target) == 0)
            match = count;
        count++;
    }
    fclose(f);

    if (match >= 0) {
        wchar_t newline[4096];
        swprintf(newline, 4096, L"%s\t%s\t%s\t%s\n", r->time, r->type, r->target, r->choice);
        free(lines[match]);
        size_t l = wcslen(newline);
        lines[match] = (wchar_t*)malloc((l + 1) * sizeof(wchar_t));
        if (lines[match]) {
            wcscpy(lines[match], newline);
            wchar_t tmpPath[MAX_PATH];
            swprintf(tmpPath, MAX_PATH, L"%s.tmp", path);
            FILE* out = _wfopen(tmpPath, L"w, ccs=UTF-8");
            if (out) {
                for (int i = 0; i < count; i++) fputws(lines[i], out);
                fclose(out);
                MoveFileExW(tmpPath, path, MOVEFILE_REPLACE_EXISTING);
            }
        }
    }

    for (int i = 0; i < count; i++) free(lines[i]);
    free(lines);
}

static int RecordOptionsFor(Record* r, const wchar_t* opts[], int max)
{
    if (wcscmp(r->type, L"文件防护") == 0 || wcscmp(r->type, L"注册表防护") == 0) {
        if (max < 3) return 0;
        opts[0] = L"同意"; opts[1] = L"回滚"; opts[2] = L"急停"; return 3;
    } else if (wcscmp(r->type, L"MBR防护") == 0) {
        opts[0] = L"同意"; opts[1] = L"恢复并急停"; return 2;
    } else if (wcscmp(r->type, L"网络防护") == 0) {
        opts[0] = L"同意联网"; opts[1] = L"禁止联网"; opts[2] = L"禁用程序"; return 3;
    } else if (wcscmp(r->type, L"进程注入防护") == 0) {
        opts[0] = L"已拦截"; opts[1] = L"放行"; return 2;
    } else {
        opts[0] = L"拦截运行"; opts[1] = L"同意运行"; return 2;
    }
}

static BOOL PickRecordChoice(HWND hwnd, Record* r, wchar_t* out, int cap)
{
    const wchar_t* opts[3];
    int n = RecordOptionsFor(r, opts, 3);
    if (n <= 0) return FALSE;

    HMENU menu = CreatePopupMenu();
    for (int i = 0; i < n; i++) {
        UINT flags = MF_STRING;
        if (wcscmp(opts[i], r->choice) == 0) flags |= MF_CHECKED;
        AppendMenuW(menu, flags, 100 + i, opts[i]);
    }

    POINT pt; GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(menu);

    if (cmd >= 100 && cmd < 100 + n) {
        wcsncpy(out, opts[cmd - 100], cap - 1);
        out[cap - 1] = 0;
        return TRUE;
    }
    return FALSE;
}

static void ChangeRecordChoice(HWND hwnd, int displayIdx)
{
    int ri = g_recordCount - 1 - displayIdx;
    if (ri < 0 || ri >= g_recordCount) return;
    Record* r = &g_records[ri];

    wchar_t choice[32];
    if (!PickRecordChoice(hwnd, r, choice, 32)) return;
    if (wcscmp(choice, r->choice) == 0) return;

    wcsncpy(r->choice, choice, 31);
    r->choice[31] = 0;
    UpdateRecordChoiceInFile(r);
    ApplyRecordChoice(hwnd, r, choice);
    InvalidateRect(hwnd, NULL, FALSE);
}

/* ========== 全部拦截记录窗口 ========== */
static void FillRecordList(HWND list)
{
    SendMessageW(list, LB_RESETCONTENT, 0, 0);
    for (int i = g_recordCount - 1; i >= 0; i--) {
        Record* r = &g_records[i];
        wchar_t line[600];
        swprintf(line, 600, L"%s   %s   %.90s   [%s]", r->time, r->type, r->target, r->choice);
        SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)line);
    }
}

typedef struct { HWND hwnd, list; } REC_DLG;

static LRESULT CALLBACK RecordsDlgProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    REC_DLG* d = (REC_DLG*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
        case WM_CREATE: {
            d = (REC_DLG*)((CREATESTRUCTW*)l)->lpCreateParams;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)d);
            d->hwnd = hwnd;
            CreateWindowW(L"STATIC", L"全部拦截记录（双击某条记录可更改处理方式）",
                          WS_CHILD | WS_VISIBLE | SS_LEFT,
                          14, 12, 700, 20, hwnd, NULL, NULL, NULL);
            d->list = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                          WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
                          LBS_NOINTEGRALHEIGHT | LBS_NOTIFY,
                          14, 38, 712, 390, hwnd, (HMENU)100, NULL, NULL);
            FillRecordList(d->list);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(w) == 100 && HIWORD(w) == LBN_DBLCLK) {
                int sel = (int)SendMessageW(d->list, LB_GETCURSEL, 0, 0);
                if (sel == LB_ERR) return 0;
                int ri = g_recordCount - 1 - sel;
                if (ri < 0 || ri >= g_recordCount) return 0;
                Record* r = &g_records[ri];

                wchar_t choice[32];
                if (!PickRecordChoice(hwnd, r, choice, 32)) return 0;
                if (wcscmp(choice, r->choice) == 0) return 0;

                wcsncpy(r->choice, choice, 31);
                r->choice[31] = 0;
                UpdateRecordChoiceInFile(r);
                ApplyRecordChoice(hwnd, r, choice);
                FillRecordList(d->list);
                SendMessageW(d->list, LB_SETCURSEL, sel, 0);
            }
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static void ShowRecordsDialog(HWND owner)
{
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = RecordsDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BDRecordsCls";
    RegisterClassExW(&wc);

    REC_DLG d;
    ZeroMemory(&d, sizeof(d));

    int w = 760, h = 480;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    g_recordsDlgOpen = TRUE;
    EnableWindow(owner, FALSE);
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"BDRecordsCls",
                                L"全部拦截记录", WS_POPUP | WS_CAPTION | WS_SYSMENU,
                                x, y, w, h, owner, NULL, wc.hInstance, &d);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (IsWindow(hwnd)) {
        if (GetMessageW(&msg, NULL, 0, 0) <= 0) break;
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    g_recordsDlgOpen = FALSE;
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

static void RunTool(HWND hwnd, int idx)
{
    if (idx < 0 || idx >= g_ToolCount) return;
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%s\\%s", g_AppDir, g_ToolExe[idx]);

    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        ShellExecuteW(hwnd, L"open", path, NULL, g_AppDir, SW_SHOWNORMAL);
        return;
    }

    TOOL_ARG* arg = (TOOL_ARG*)malloc(sizeof(TOOL_ARG));
    if (!arg) return;
    wcsncpy(arg->exe, g_ToolExe[idx], 127);
    arg->exe[127] = 0;
    CreateThread(NULL, 0, ToolDownloadThread, arg, 0, NULL);
}

static void HandleDropFiles(HWND hwnd, HDROP hd)
{
    wchar_t path[MAX_PATH];
    if (DragQueryFileW(hd, 0, path, MAX_PATH) == 0) return;

    /* 不限制文件类型：任何后缀都可作为样本提交 */

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad) ||
        (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        MessageBoxW(hwnd, L"无法读取该文件。", L"无法提交", MB_OK | MB_ICONERROR);
        return;
    }
    unsigned long long size = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (size <= SAMPLE_MIN_SIZE) {
        MessageBoxW(hwnd, L"样本文件必须大于 3KB。", L"无法提交", MB_OK | MB_ICONWARNING);
        return;
    }
    if (size >= SAMPLE_MAX_SIZE) {
        MessageBoxW(hwnd, L"样本文件不能超过 500MB。", L"无法提交", MB_OK | MB_ICONWARNING);
        return;
    }

    /* 同一个程序文件不能重复提交：按内容 SHA-256 判断 */
    wchar_t hash[65] = {0};
    if (!Sha256FileHex(path, hash, 65)) {
        MessageBoxW(hwnd, L"无法读取该文件的内容。", L"无法提交", MB_OK | MB_ICONERROR);
        return;
    }
    if (SampleHashExists(hash)) {
        MessageBoxW(hwnd, L"该样本已经提交过，请勿重复提交同一个程序文件。",
                    L"样本已存在", MB_OK | MB_ICONINFORMATION);
        return;
    }

    /* 再检查病毒库中是否已存在相同大小的样本 */
    wchar_t virus[128] = {0};
    if (FindWildBySize(size, virus, 128)) {
        wchar_t msg[512];
        swprintf(msg, 512, L"病毒库中已存在该样本（%s），无需重复提交。", virus);
        MessageBoxW(hwnd, msg, L"样本已存在", MB_OK | MB_ICONINFORMATION);
        return;
    }

    /* 预填原文件名（含扩展名），让样本在服务器上保持 test.bat 这类真实后缀 */
    wchar_t defName[128] = {0};
    const wchar_t* base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    wcsncpy(defName, base, 127);

    wchar_t name[128];
    if (!PromptSampleName(hwnd, defName, name, 128)) return;

    /* 用户手动输入的名字没带扩展名时，自动补上原文件的扩展名，
       避免 .bat / .vbs 样本在管理端被当成无后缀文件 */
    if (!wcschr(name, L'.')) {
        const wchar_t* ext = wcsrchr(base, L'.');
        if (ext && wcslen(name) + wcslen(ext) < 127) wcscat(name, ext);
    }

    UPLOAD_ARG* arg = (UPLOAD_ARG*)malloc(sizeof(UPLOAD_ARG));
    if (!arg) return;
    wcsncpy(arg->path, path, MAX_PATH - 1); arg->path[MAX_PATH - 1] = 0;
    wcsncpy(arg->name, name, 127); arg->name[127] = 0;
    wcscpy(arg->hash, hash);
    CreateThread(NULL, 0, UploadThread, arg, 0, NULL);
}

/* ========== 窗口过程 ========== */
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch(msg) {
        case WM_CREATE: {
            g_hMainWnd = hwnd;
            InitAppDir();
            EnsureGuardTask();
            LoadConfig();
            LoadRecords();
            LoadCachedTools();
            g_hasWildlist = HasWildlist();

            DragAcceptFiles(hwnd, TRUE);
            /* 以管理员身份运行时，需要放行资源管理器发来的拖放消息 */
            ChangeWindowMessageFilterEx(hwnd, WM_DROPFILES, MSGFLT_ALLOW, NULL);
            ChangeWindowMessageFilterEx(hwnd, 0x0049 /* WM_COPYGLOBALDATA */, MSGFLT_ALLOW, NULL);
            SetTimer(hwnd, 1, 1000, NULL);
            SetTimer(hwnd, 2, 3000, NULL);
            CreateThread(NULL, 0, UpdateCheckThread, NULL, 0, NULL);
            CreateThread(NULL, 0, StopFlagWatchThread, hwnd, 0, NULL);
            return 0;
        }

        case WM_TIMER:
            if (w == 1) {
                CollectCPU(); CollectDisk(); CollectNetwork();
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (w == 2) {
                /* 后台可能因试用到期自动关闭云端病毒库，这里同步一次状态 */
                BOOL cloud = GetPrivateProfileIntW(L"Config", L"Cloud", 0, BD_CONFIG_FILE);
                if (cloud != g_ProtectCloud) {
                    g_ProtectCloud = cloud;
                    InvalidateRect(hwnd, NULL, FALSE);
                }
                /* 病毒库可能在外部被下载/删除 */
                BOOL hasDb = HasWildlist();
                if (hasDb != g_hasWildlist) {
                    g_hasWildlist = hasDb;
                    InvalidateRect(hwnd, NULL, FALSE);
                }
                /* 周期性刷新拦截记录（后台进程会持续追加；
                   记录窗口打开期间不改动，避免列表内容错位） */
                if (g_HoverRecord == -1 && !g_recordsDlgOpen) {
                    int old = g_recordCount;
                    LoadRecords();
                    if (g_recordCount != old) InvalidateRect(hwnd, NULL, FALSE);
                }
            }
            return 0;

        case WM_APP_TOOLS_REFRESH:
            ParseTools(bd_cache_path(L"PracticalToolbox.txt"));
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;

        case WM_APP_UPLOAD_DONE: {
            if (!w) {
                MessageBoxW(hwnd, L"样本提交失败，请检查网络或服务器配置。", L"提交失败",
                            MB_OK | MB_ICONERROR);
            } else if (l) {
                MessageBoxW(hwnd, L"已解锁永久版！\n\n感谢您提交病毒样本。", L"提交成功",
                            MB_OK | MB_ICONINFORMATION);
            } else {
                int left = 3 - CloudUserUp();
                wchar_t msg[256];
                if (left > 0) swprintf(msg, 256, L"样本提交成功！\n\n再提交 %d 个样本即可解锁永久版。", left);
                else swprintf(msg, 256, L"样本提交成功！");
                MessageBoxW(hwnd, msg, L"提交成功", MB_OK | MB_ICONINFORMATION);
            }
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_APP_DB_DONE: {
            g_dbDownloading = FALSE;
            g_hasWildlist = HasWildlist();
            if (w && g_hasWildlist) {
                g_ProtectCloud = TRUE;
                SaveConfig();
                MessageBoxW(hwnd, L"云端病毒库下载完成，已自动启用“比对云端病毒库”。",
                            L"病毒库", MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(hwnd, L"病毒库下载失败，请检查网络或服务器配置后重试。",
                            L"病毒库", MB_OK | MB_ICONERROR);
            }
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps); RECT rc; GetClientRect(hwnd, &rc);
            HDC mem = CreateCompatibleDC(hdc); HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
            HBITMAP old = (HBITMAP)SelectObject(mem, bmp);
            DrawUI(mem, rc.right, rc.bottom);
            BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old); DeleteObject(bmp); DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_ERASEBKGND: return 1;

        case WM_MOUSEMOVE: {
            int mx = GET_X_LPARAM(l); int my = GET_Y_LPARAM(l);
            RECT rc; GetClientRect(hwnd, &rc);
            int oldTool = g_HoverTool, oldSet = g_HoverSetting, oldRec = g_HoverRecord;
            g_HoverTool = -1; g_HoverSetting = -1; g_HoverRecord = -1;

            if (my >= CARD_TOP && my < CARD_TOP + CARD_ROWS * (CARD_H + CARD_GAP)) {
                for (int i = 0; i < 6; i++) {
                    int cx, cy, boxW, boxH;
                    SettingCardRect(i, rc.right, &cx, &cy, &boxW, &boxH);
                    if (mx >= cx && mx <= cx + boxW && my >= cy && my <= cy + boxH) { g_HoverSetting = i; break; }
                }
            }

            if (g_HoverSetting == -1 && my >= RECORD_TOP && my < RECORD_TOP + RECORD_ROWS * RECORD_ROW_H) {
                int shown = RecordDisplayCount();
                for (int i = 0; i < shown; i++) {
                    int ry = RECORD_TOP + i * RECORD_ROW_H;
                    if (mx >= 20 && mx <= rc.right - 20 && my >= ry && my <= ry + RECORD_ROW_H - 3) {
                        g_HoverRecord = i; break;
                    }
                }
            }

            if (g_HoverSetting == -1 && g_HoverRecord == -1 && my >= TOOL_TOP) {
                for (int i = 0; i < g_ToolCount; i++) {
                    int btnY = TOOL_TOP + i * 60 - g_ScrollY;
                    if (mx >= 20 && mx <= rc.right - 20 && my >= btnY && my <= btnY + 50) {
                        g_HoverTool = i; break;
                    }
                }
            }

            if (oldTool != g_HoverTool || oldSet != g_HoverSetting || oldRec != g_HoverRecord)
                InvalidateRect(hwnd, NULL, FALSE);

            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
            return 0;
        }

        case WM_MOUSELEAVE:
            if (g_HoverTool != -1 || g_HoverSetting != -1 || g_HoverRecord != -1) {
                g_HoverTool = -1; g_HoverSetting = -1; g_HoverRecord = -1;
                InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;

        case WM_LBUTTONDOWN: {
            RECT wrc; GetClientRect(hwnd, &wrc);
            int mx0 = GET_X_LPARAM(l), my0 = GET_Y_LPARAM(l);

            /* 拦截记录右上角“查看更多” */
            if (my0 >= RECORDS_Y && my0 <= RECORDS_Y + 20 && mx0 >= wrc.right - 100) {
                ShowRecordsDialog(hwnd);
                return 0;
            }

            /* 工具箱右侧的“下载 / 打开”按钮 */
            if (g_HoverTool >= 0 && mx0 >= wrc.right - 100) {
                RunTool(hwnd, g_HoverTool);
                return 0;
            }

            if (g_HoverSetting >= 0 && g_HoverSetting < 6) {
                if (g_HoverSetting == 5) {
                    if (!g_hasWildlist) {
                        if (!g_dbDownloading) {
                            g_dbDownloading = TRUE;
                            InvalidateRect(hwnd, NULL, FALSE);
                            CreateThread(NULL, 0, DbDownloadThread, hwnd, 0, NULL);
                        }
                        return 0;
                    }
                    if (!g_ProtectCloud && CloudExpired()) {
                        ShowExpiredMessage(hwnd);
                        return 0;
                    }
                    g_ProtectCloud = !g_ProtectCloud;
                } else if (g_HoverSetting == 0) g_ProtectFile = !g_ProtectFile;
                else if (g_HoverSetting == 1) g_ProtectReg = !g_ProtectReg;
                else if (g_HoverSetting == 2) g_ProtectMbr = !g_ProtectMbr;
                else if (g_HoverSetting == 3) g_ProtectNet = !g_ProtectNet;
                else if (g_HoverSetting == 4) g_ProtectInject = !g_ProtectInject;
                SaveConfig();
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (g_HoverRecord >= 0) {
                ChangeRecordChoice(hwnd, g_HoverRecord);
            }
            return 0;
        }

        case WM_LBUTTONDBLCLK:
            if (g_HoverTool >= 0) RunTool(hwnd, g_HoverTool);
            return 0;

        case WM_DROPFILES:
            HandleDropFiles(hwnd, (HDROP)w);
            DragFinish((HDROP)w);
            return 0;

        case WM_VSCROLL: {
            int nScrollCode = LOWORD(w);
            SCROLLINFO si = { sizeof(si) };
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            int oldPos = si.nPos;
            switch (nScrollCode) {
                case SB_THUMBTRACK: case SB_THUMBPOSITION: si.nPos = HIWORD(w); break;
                case SB_LINEUP: si.nPos -= 30; break;
                case SB_LINEDOWN: si.nPos += 30; break;
                case SB_PAGEUP: si.nPos -= si.nPage; break;
                case SB_PAGEDOWN: si.nPos += si.nPage; break;
            }
            RECT rc; GetClientRect(hwnd, &rc);
            int toolsHeight = rc.bottom - TOOL_TOP;
            int contentH = g_ToolCount * 60;
            int maxScroll = contentH - toolsHeight + 20;
            if (maxScroll < 0) maxScroll = 0;

            if (si.nPos < 0) si.nPos = 0;
            if (si.nPos > maxScroll) si.nPos = maxScroll;
            if (si.nPos != oldPos) {
                g_ScrollY = si.nPos;
                SetScrollPos(hwnd, SB_VERT, si.nPos, TRUE);
                InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;
        }

        case WM_MOUSEWHEEL: {
            int zDelta = GET_WHEEL_DELTA_WPARAM(w);
            RECT rc; GetClientRect(hwnd, &rc);
            int toolsHeight = rc.bottom - TOOL_TOP;
            int contentH = g_ToolCount * 60;
            int maxScroll = contentH - toolsHeight + 20;
            if (maxScroll < 0) maxScroll = 0;

            if (zDelta > 0) g_ScrollY -= 60; else g_ScrollY += 60;
            if (g_ScrollY < 0) g_ScrollY = 0;
            if (g_ScrollY > maxScroll) g_ScrollY = maxScroll;

            SetScrollPos(hwnd, SB_VERT, g_ScrollY, TRUE);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE h, HINSTANCE p, LPWSTR cmdLine, int show) {
    SetConsoleOutputCP(GetACP());   /* 强制使用 ANSI 代码页 */

    if (!IsRunAsAdmin()) {
        if (wcsstr(cmdLine, L"/elevated") == NULL) {
            wchar_t selfPath[MAX_PATH];
            GetModuleFileNameW(NULL, selfPath, MAX_PATH);

            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = selfPath;
            sei.lpParameters = L"/elevated";
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;

            if (ShellExecuteExW(&sei)) {
                return 0;
            } else {
                MessageBoxW(NULL, L"必须获取管理员权限才能运行主控中心！", L"权限不足", MB_ICONERROR);
                return 0;
            }
        }
    }

    /* 单实例：避免同时打开多个控制中心 */
    HANDLE hInstMutex = CreateMutexW(NULL, TRUE, L"Global\\BDProtect_MainMutex");
    DWORD instErr = GetLastError();
    if (hInstMutex == NULL || instErr == ERROR_ALREADY_EXISTS || instErr == ERROR_ACCESS_DENIED) {
        HWND old = FindWindowW(L"BDMainCls", NULL);
        if (old) { ShowWindow(old, SW_RESTORE); SetForegroundWindow(old); }
        if (hInstMutex) CloseHandle(hInstMutex);
        return 0;
    }

    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icex);
    bd_paths_init();              /* 读取缓存目录记录；缓存目录消失时回退默认 */
    CreateDirectoryW(bd_cache_root(), NULL);
    HardenStateDir();

    g_fontSmall = MakeFont(12, FW_NORMAL); g_fontBody  = MakeFont(15, FW_NORMAL);
    g_fontBold  = MakeFont(15, FW_BOLD);   g_fontBig   = MakeFont(30, FW_BOLD);

    if (PdhOpenQueryW(NULL, 0, &g_cpuQuery) == ERROR_SUCCESS) {
        PdhAddCounterW(g_cpuQuery, L"\\Processor(*)\\% Processor Time", 0, &g_cpuCounter);
        PdhCollectQueryData(g_cpuQuery);
    }
    if (PdhOpenQueryW(NULL, 0, &g_diskQuery) == ERROR_SUCCESS) {
        PdhAddCounterW(g_diskQuery, L"\\PhysicalDisk(*)\\% Disk Time", 0, &g_diskTime);
        PdhCollectQueryData(g_diskQuery);
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainProc;
    wc.hInstance = h;
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"BDMainCls";
    wc.hIcon = LoadIconW(NULL, (LPCWSTR)32518);
    wc.style = CS_DBLCLKS;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(WS_EX_ACCEPTFILES, L"BDMainCls", L"XDH防护系统",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VSCROLL,
        CW_USEDEFAULT, CW_USEDEFAULT, WIN_W, WIN_H, NULL, NULL, h, NULL);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hwnd, NULL, (screenW - WIN_W)/2, (screenH - WIN_H)/2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(hwnd, show);
    MSG msg; while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }

    if (g_cpuQuery) PdhCloseQuery(g_cpuQuery);
    if (g_diskQuery) PdhCloseQuery(g_diskQuery);
    DeleteObject(g_fontSmall); DeleteObject(g_fontBody); DeleteObject(g_fontBold); DeleteObject(g_fontBig);
    return 0;
}
