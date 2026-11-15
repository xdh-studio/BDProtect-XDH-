#include "bd_common.h"
#include <tlhelp32.h>
#include <shlobj.h>
#include <wchar.h>

/* 云端病毒库比对（受限功能）
 *
 * Wildlist.txt 格式（与程序同目录）：
 *     110012 3c59dc048e8850243be8079a5c74d079 mzmz
 *     250582 petset
 * 第一段为病毒样本的文件大小；如果第二段是 32 位十六进制，则为 MD5 哈希，
 * 其后为病毒名称；否则第二段直接是病毒名称（旧格式，仅按大小匹配）。
 *
 * 匹配规则：
 *   大小 + 哈希都一致  -> “已发现 X 病毒”，弹窗 5 秒，超时默认拦截
 *   大小一致但哈希不同 -> “疑似 X 病毒”，弹窗 15 秒，超时默认拦截
 *   旧条目只有大小     -> 同样按“疑似”处理（15 秒，默认拦截）
 */

#define MAX_WILD 8192
typedef struct {
    unsigned long long size;
    wchar_t name[128];
    wchar_t hash[33];   /* 空表示旧格式条目，没有哈希 */
} WILD_ENTRY;

#define MATCH_NONE     0
#define MATCH_EXACT    1
#define MATCH_SUSPECT  2

/* 常用用户目录：这些位置里的文件只要大小命中就弹 15 秒疑似窗；
   其它位置必须大小 + MD5 都一致才弹窗（5 秒），否则放行不弹。 */
static BOOL is_user_dir(const wchar_t* path)
{
    if (!path || wcslen(path) < 3) return FALSE;
    wchar_t buf[MAX_PATH];

    /* 当前用户桌面 */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, buf)) &&
        _wcsnicmp(path, buf, wcslen(buf)) == 0 &&
        (path[wcslen(buf)] == L'\\' || path[wcslen(buf)] == 0)) return TRUE;
    /* 公共桌面 */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, buf)) &&
        _wcsnicmp(path, buf, wcslen(buf)) == 0 &&
        (path[wcslen(buf)] == L'\\' || path[wcslen(buf)] == 0)) return TRUE;

    /* 当前用户 Downloads（从 文档 目录反推用户根目录，兼容非中文系统） */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, buf))) {
        size_t l = wcslen(buf);
        wchar_t userRoot[MAX_PATH];
        if (l > 10 && _wcsicmp(buf + l - 10, L"\\Documents") == 0) {
            wcsncpy(userRoot, buf, l - 10);
            userRoot[l - 10] = 0;
        } else {
            wcsncpy(userRoot, buf, MAX_PATH - 1);
            userRoot[MAX_PATH - 1] = 0;
        }
        wchar_t dl[MAX_PATH];
        swprintf(dl, MAX_PATH, L"%s\\Downloads", userRoot);
        if (_wcsnicmp(path, dl, wcslen(dl)) == 0 &&
            (path[wcslen(dl)] == L'\\' || path[wcslen(dl)] == 0)) return TRUE;
    }
    /* 公共下载 */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_DOCUMENTS, NULL, 0, buf))) {
        wchar_t dl[MAX_PATH];
        swprintf(dl, MAX_PATH, L"%s\\Downloads", buf);
        if (_wcsnicmp(path, dl, wcslen(dl)) == 0) return TRUE;
    }

    /* 路径中明确含 Downloads / Desktop 目录的也视为常用位置 */
    if (wcsstr(path, L"\\Downloads\\")) return TRUE;
    if (wcsstr(path, L"\\Desktop\\")) return TRUE;

    return FALSE;
}

/* 路径是否位于回收站（各盘根下的 $RECYCLE.BIN） */
static BOOL is_recycle_path(const wchar_t* path)
{
    if (!path) return FALSE;
    size_t n = wcslen(path);
    for (size_t i = 0; i + 14 < n; i++) {
        if (path[i] == L'\\' &&
            _wcsnicmp(path + i + 1, L"$RECYCLE.BIN\\", 13) == 0)
            return TRUE;
    }
    return FALSE;
}

static WILD_ENTRY g_wild[MAX_WILD];
static int g_wildCount = 0;
static FILETIME g_wildStamp = {0, 0};

static CRITICAL_SECTION g_scan_cs;
static volatile LONG g_scan_inited = 0;

static void scan_init(void)
{
    if (InterlockedCompareExchange(&g_scan_inited, 1, 0) == 0)
        InitializeCriticalSection(&g_scan_cs);
}

static void trim_w(wchar_t* str)
{
    wchar_t* p = str;
    while (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n') p++;
    wchar_t* q = p + wcslen(p);
    while (q > p && (q[-1] == L' ' || q[-1] == L'\t' || q[-1] == L'\r' || q[-1] == L'\n')) *--q = 0;
    if (p != str) wmemmove(str, p, wcslen(p) + 1);
}

static void load_wildlist(void)
{
    wchar_t path[MAX_PATH];
    bd_get_app_file(L"Wildlist.txt", path, MAX_PATH);

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) {
        g_wildCount = 0;
        return;
    }
    if (CompareFileTime(&fad.ftLastWriteTime, &g_wildStamp) == 0) return;
    g_wildStamp = fad.ftLastWriteTime;

    g_wildCount = 0;
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return;

    wchar_t line[512];
    while (fgetws(line, 512, f) && g_wildCount < MAX_WILD) {
        trim_w(line);
        if (line[0] == 0 || line[0] == L'#' || line[0] == L';') continue;

        wchar_t* end = NULL;
        unsigned long long sz = (unsigned long long)_wcstoui64(line, &end, 10);
        if (end == line) continue;
        while (*end == L' ' || *end == L'\t') end++;
        if (*end == 0) continue;

        WILD_ENTRY* e = &g_wild[g_wildCount];
        e->size = sz;
        e->hash[0] = 0;

        /* 第二段是 32 位十六进制时视为 MD5 哈希 */
        wchar_t token[64];
        int ti = 0;
        while (*end && *end != L' ' && *end != L'\t' && ti < 63)
            token[ti++] = *end++;
        token[ti] = 0;
        if (bd_is_hex32(token)) {
            wcsncpy(e->hash, token, 32);
            e->hash[32] = 0;
            while (*end == L' ' || *end == L'\t') end++;
        }
        wcsncpy(e->name, end, 127);
        e->name[127] = 0;
        trim_w(e->name);
        if (e->name[0] == 0) continue;
        g_wildCount++;
    }
    fclose(f);
    bd_log(L"[Cloud] 已加载病毒库，共 %d 条", g_wildCount);
}

static unsigned long long get_file_size(const wchar_t* path)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return (unsigned long long)-1;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return (unsigned long long)-1;
    return ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
}

/* 按大小筛选候选；哈希一致返回 MATCH_EXACT，否则 MATCH_SUSPECT。
   只有大小命中的旧条目也按疑似处理，避免仅凭大小就判定为“已发现”。 */
static int match_wildlist(unsigned long long size, const wchar_t* hash, const wchar_t** outName)
{
    int result = MATCH_NONE;
    for (int i = 0; i < g_wildCount; i++) {
        if (g_wild[i].size != size) continue;

        if (g_wild[i].hash[0] && hash && hash[0] &&
            _wcsicmp(g_wild[i].hash, hash) == 0) {
            *outName = g_wild[i].name;
            return MATCH_EXACT;
        }

        if (result == MATCH_NONE) {
            *outName = g_wild[i].name;
            result = MATCH_SUSPECT;
        }
    }
    return result;
}

/* 已告警路径表，避免同一文件反复弹窗 */
#define MAX_ALERTED 512
static wchar_t g_alerted[MAX_ALERTED][MAX_PATH];
static int g_alertedCount = 0;

static BOOL was_alerted(const wchar_t* path)
{
    for (int i = 0; i < g_alertedCount; i++)
        if (_wcsicmp(g_alerted[i], path) == 0) return TRUE;
    return FALSE;
}

static void mark_alerted(const wchar_t* path)
{
    if (g_alertedCount >= MAX_ALERTED) g_alertedCount = 0;
    wcsncpy(g_alerted[g_alertedCount], path, MAX_PATH - 1);
    g_alerted[g_alertedCount][MAX_PATH - 1] = 0;
    g_alertedCount++;
}

/* 映像劫持：让被拦截的程序启动时显示“因为疑似病毒而无法运行” */
static void image_hijack_block(const wchar_t* path)
{
    const wchar_t* base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    if (!base || !*base) return;

    wchar_t appExe[MAX_PATH];
    bd_get_app_file(L"BDProtect.exe", appExe, MAX_PATH);

    wchar_t regPath[512];
    swprintf(regPath, 512,
             L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
             base);

    wchar_t debugger[MAX_PATH + 32];
    swprintf(debugger, MAX_PATH + 32, L"\"%s\" /blocked", appExe);

    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0,
                        KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)debugger,
                       (DWORD)((wcslen(debugger) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
        bd_log(L"[Cloud] 已映像劫持: %s", base);
    }
}

/* 无限读取：长期持有句柄并循环读取，阻止文件被修改或删除 */
typedef struct { wchar_t path[MAX_PATH]; } LOCK_ARG;

static DWORD WINAPI lock_file_thread(LPVOID p)
{
    LOCK_ARG* arg = (LOCK_ARG*)p;
    HANDLE h = CreateFileW(arg->path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(arg);
    if (h == INVALID_HANDLE_VALUE) return 0;

    BYTE buf[4096];
    while (1) {
        DWORD r = 0;
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        ReadFile(h, buf, sizeof(buf), &r, NULL);
        Sleep(1000);
    }
    return 0;
}

static void lock_file(const wchar_t* path)
{
    LOCK_ARG* arg = (LOCK_ARG*)malloc(sizeof(LOCK_ARG));
    if (!arg) return;
    wcsncpy(arg->path, path, MAX_PATH - 1);
    arg->path[MAX_PATH - 1] = 0;
    CreateThread(NULL, 0, lock_file_thread, arg, 0, NULL);
}

/* 搜索同名进程，如果病毒正在运行则强制蓝屏 */
static void kill_running_sample(const wchar_t* path)
{
    const wchar_t* base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    BOOL running = FALSE;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, base) == 0) { running = TRUE; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (running) {
        bd_log(L"[Cloud] 检测到病毒进程正在运行，强制蓝屏: %s", base);
        bd_trigger_bsod();
    }
}

static void check_file(const wchar_t* path)
{
    if (!g_bCloudPrt || g_bPaused) return;
    /* 本软件自己的安装目录/缓存目录（含 FileBackup 里的病毒副本）永不检测 */
    if (bd_is_own_path(path)) return;
    /* 启动静默期内不扫描、不记录，避免在用户看不到弹窗时静默拦截文件 */
    if (bd_popup_grace_active()) return;
    if (was_alerted(path)) return;

    unsigned long long size = get_file_size(path);
    if (size == (unsigned long long)-1) return;

    load_wildlist();
    if (g_wildCount == 0) return;

    /* 先按大小筛选，只有大小命中才计算 MD5，避免对全盘文件做哈希 */
    const wchar_t* virus = NULL;
    int match = MATCH_NONE;
    for (int i = 0; i < g_wildCount; i++) {
        if (g_wild[i].size == size) { match = MATCH_SUSPECT; virus = g_wild[i].name; break; }
    }
    if (match == MATCH_NONE) return;

    wchar_t hash[33] = {0};
    BOOL haveHash = bd_file_md5(path, hash, 33);
    if (!haveHash) {
        /* 文件在检测过程中已经消失（被删除/被本软件清除）：无需告警 */
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            mark_alerted(path);
            return;
        }
        bd_log(L"[Cloud] MD5 计算失败: %s", path);
    }
    const wchar_t* matchedName = NULL;
    int level = match_wildlist(size, hash, &matchedName);
    if (level == MATCH_NONE) return;
    if (matchedName) virus = matchedName;

    /* 回收站内的命中文件直接清除，不弹窗、不询问 */
    if (is_recycle_path(path)) {
        SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(path)) {
            bd_log(L"[Cloud] 回收站命中病毒库，已静默删除: %s (level=%d)", path, level);
            bd_record_add(L"云端病毒库", path, L"回收站静默清除");
        } else {
            bd_log(L"[Cloud] 回收站命中但删除失败: %s (err=%lu)", path, GetLastError());
        }
        mark_alerted(path);   /* 避免反复处理同一文件 */
        return;
    }

    /* 策略：
       常用位置（下载/桌面）：大小一致即弹 15 秒疑似窗
       其它位置：只有大小 + MD5 完全一致才弹 3 秒确认窗
                 仅大小一致 → 静默放行，不弹任何提示 */
    BOOL userLoc = is_user_dir(path);
    if (level == MATCH_SUSPECT && !userLoc) {
        bd_log(L"[Cloud] 大小命中但非用户目录，放行: %s (size=%llu)", path, size);
        mark_alerted(path);   /* 避免同一文件反复进入此分支占 CPU */
        return;
    }

    scan_init();
    EnterCriticalSection(&g_scan_cs);
    /* 进入临界区后重新检查，避免重复弹窗 */
    if (was_alerted(path)) { LeaveCriticalSection(&g_scan_cs); return; }
    mark_alerted(path);

    wchar_t text[1200];
    int timeoutSec;
    const wchar_t* title;
    if (level == MATCH_EXACT) {
        swprintf(text, 1200,
                 L"已发现%s病毒！\n\n文件：%s\n大小：%llu 字节\nMD5：%s\n\n请选择处理方式：",
                 virus, path, size, haveHash ? hash : L"计算失败");
        timeoutSec = 3;
        title = L"云端病毒库拦截";
    } else {
        swprintf(text, 1200,
                 L"疑似%s病毒！\n\n文件：%s\n大小：%llu 字节\nMD5：%s\n"
                 L"（文件大小命中病毒库，但哈希不一致）\n\n请选择处理方式：",
                 virus, path, size, haveHash ? hash : L"计算失败");
        timeoutSec = 15;
        title = L"云端病毒库疑似告警";
    }

    /* 超时默认“拦截运行” */
    int r = bd_show_popup(title, text, 5, timeoutSec);
    if (r == BD_POPUP_SUPPRESSED) { LeaveCriticalSection(&g_scan_cs); return; }

    if (r == IDYES) {
        bd_log(L"[Cloud] 用户选择拦截: %s (level=%d)", path, level);
        bd_record_add(L"云端病毒库", path, L"拦截运行");
        image_hijack_block(path);
        lock_file(path);
        kill_running_sample(path);
    } else {
        bd_log(L"[Cloud] 用户同意运行: %s (level=%d)", path, level);
        bd_record_add(L"云端病毒库", path, L"同意运行");
    }
    LeaveCriticalSection(&g_scan_cs);
}

/* ============ 实时捕捉新增/修改文件 ============ */

static void realtime_scan_dir(const wchar_t* dir)
{
    HANDLE hDir = CreateFileW(dir, FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) return;

    /* 64KB 缓冲：递归监视整盘时 8KB 很容易在编译/下载等场景下溢出丢事件 */
    const DWORD bufSize = 64 * 1024;
    BYTE* buf = (BYTE*)malloc(bufSize);
    if (!buf) { CloseHandle(hDir); return; }

    DWORD bytes;
    while (1) {
        /* 暂停/关闭时仍然读取并丢弃事件，避免恢复后积压事件一次性涌入 */
        BOOL ok = ReadDirectoryChangesW(hDir, buf, bufSize, TRUE,
                                        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
                                        FILE_NOTIFY_CHANGE_LAST_WRITE,
                                        &bytes, NULL, NULL);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NOTIFY_ENUM_DIR) {
                bd_log(L"[Cloud] 目录监视缓冲溢出，部分事件被丢弃: %s", dir);
                continue;
            }
            Sleep(500);
            continue;
        }
        if (g_bPaused || !g_bCloudPrt) continue;

        FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buf;
        while (1) {
            if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED ||
                fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                int len = fni->FileNameLength / sizeof(WCHAR);
                if (len > MAX_PATH - 1) len = MAX_PATH - 1;
                wchar_t name[MAX_PATH];
                wcsncpy(name, fni->FileName, len);
                name[len] = 0;
                wchar_t full[MAX_PATH * 2];
                swprintf(full, MAX_PATH * 2, L"%s%s", dir, name);
                if (!wcsstr(full, L"\\BDtemp\\"))
                    check_file(full);
            }
            if (fni->NextEntryOffset == 0) break;
            fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
        }
    }
    free(buf);
    CloseHandle(hDir);
}

/* ============ 全盘慢扫描：每 1 秒扫描 1 个文件 ============ */

/* 断点续扫：每个盘记录最后扫描到的文件，重启/重扫时从该处继续，
   否则以 1 文件/秒的速度永远扫不到靠后的目录。 */
static void cursor_path(wchar_t drive, wchar_t* out, int cap)
{
    swprintf(out, cap, L"%s\\scan_%c.pos", BD_TEMP_DIR, drive);
}

static void load_cursor(wchar_t drive, wchar_t* out, int cap)
{
    out[0] = 0;
    wchar_t p[MAX_PATH];
    cursor_path(drive, p, MAX_PATH);
    FILE* f = _wfopen(p, L"r, ccs=UTF-8");
    if (!f) return;
    if (!fgetws(out, cap, f)) out[0] = 0;
    fclose(f);
    size_t l = wcslen(out);
    while (l > 0 && (out[l-1] == L'\r' || out[l-1] == L'\n')) out[--l] = 0;
}

static void save_cursor(wchar_t drive, const wchar_t* path)
{
    wchar_t p[MAX_PATH];
    cursor_path(drive, p, MAX_PATH);
    FILE* f = _wfopen(p, L"w, ccs=UTF-8");
    if (f) { fwprintf(f, L"%s", path); fclose(f); }
}

static void clear_cursor(wchar_t drive)
{
    wchar_t p[MAX_PATH];
    cursor_path(drive, p, MAX_PATH);
    DeleteFileW(p);
}

static void slow_scan_tree(const wchar_t* dir, const wchar_t* cursor, wchar_t drive)
{
    wchar_t pattern[MAX_PATH * 2];
    swprintf(pattern, MAX_PATH * 2, L"%s%s*", dir, (dir[wcslen(dir) - 1] == L'\\') ? L"" : L"\\");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        wchar_t full[MAX_PATH * 2];
        swprintf(full, MAX_PATH * 2, L"%s%s", dir, (dir[wcslen(dir) - 1] == L'\\') ? L"" : L"\\");
        wcscat(full, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                slow_scan_tree(full, cursor, drive);
        } else {
            if (!g_bCloudPrt) { FindClose(hFind); return; }
            /* 断点之前的文件直接跳过，不占用扫描速度 */
            if (cursor[0] && _wcsicmp(full, cursor) <= 0) continue;
            if (!g_bPaused) {
                check_file(full);
                save_cursor(drive, full);
            }
            /* 控制扫描速度，尽量减少 CPU 占用 */
            Sleep(1000);
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

static DWORD WINAPI slow_scan_thread(LPVOID p)
{
    while (1) {
        if (!g_bCloudPrt || g_bPaused) { Sleep(2000); continue; }
        DWORD mask = GetLogicalDrives();
        for (int i = 0; i < 26; i++) {
            if (!(mask & (1u << i))) continue;
            wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
            if (GetDriveTypeW(root) != DRIVE_FIXED) continue;

            wchar_t cursor[MAX_PATH * 2];
            load_cursor(root[0], cursor, MAX_PATH * 2);
            /* 断点不在本盘（盘符变动/文件残留）时从头开始 */
            if (cursor[0] && _wcsicmp(cursor, root) != 0 &&
                !(towlower(cursor[0]) == towlower(root[0]) && cursor[1] == L':'))
                cursor[0] = 0;

            slow_scan_tree(root, cursor, root[0]);
            clear_cursor(root[0]);   /* 本轮扫完，下一轮从头开始 */
        }
        Sleep(5000);
    }
    return 0;
}

/* ============ 试用倒计时 ============ */

static DWORD WINAPI trial_thread(LPVOID p)
{
    while (1) {
        Sleep(60 * 1000);
        if (!g_bCloudPrt || g_bPaused) continue;
        if (bd_cloud_is_unlocked()) continue;   /* 已提交 3 个样本，永久版 */

        int m = bd_cloud_get_minutes();
        if (m <= 0) {
            bd_cloud_set_minutes(0);
        } else {
            m--;
            bd_cloud_set_minutes(m);
        }

        if (m <= 0) {
            /* 自动关闭功能 */
            WritePrivateProfileStringW(L"Config", L"Cloud", L"0", BD_CONFIG_FILE);
            g_bCloudPrt = FALSE;
            bd_log(L"[Cloud] 试用已到期，已自动关闭云端病毒库比对");
            bd_show_popup(L"试用已到期",
                          L"云端病毒库比对试用已到期。\n\n解决方法：提交三个病毒样本，以获取永久版。",
                          6, 0);
        }
    }
    return 0;
}

void bd_cloud_monitor_start(void)
{
    scan_init();
    bd_ensure_store_dir();

    /* 每个固定磁盘启动一个实时监控线程 */
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(mask & (1u << i))) continue;
        wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
        if (GetDriveTypeW(root) == DRIVE_FIXED) {
            wchar_t* d = (wchar_t*)malloc(sizeof(wchar_t) * 4);
            wcscpy(d, root);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)realtime_scan_dir, d, 0, NULL);
        }
    }

    CreateThread(NULL, 0, slow_scan_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, trial_thread, NULL, 0, NULL);
}
