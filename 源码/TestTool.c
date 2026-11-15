/* BDProtect 防护测试工具 (TestTool, GUI 选择页版)
 *
 * 界面：左侧日志/进度，右侧 5 个测试项按钮。
 * 点击右侧任意一项，只运行该项测试，完成后自动给出结果；
 * 全部 5 项都测过后自动汇总并写出报告。
 *
 * 覆盖范围（不含云端病毒库）：
 *   1. 文件防护：制造批量删除，最多等 50 秒检测是否自动回滚（回滚成功立即结束）
 *   2. 注册表防护：修改 HKLM Run，最多等 50 秒检测是否回滚
 *   3. MBR 防护：改写引导扇区前 4 字节，最多等 50 秒检测是否恢复
 *   4. 进程注入防护：释放注入程序，对系统 dism.exe 注入，检测是否被阻止
 *   5. 网络防护：持续连接百度服务器，询问用户是否看到拦截弹窗
 *      （15 秒内未作答则结果为“未知”）
 *
 * 构建：
 *   gcc -O2 -Wall -municode -mwindows TestTool.c -o TestTool.exe \
 *       -lws2_32 -ladvapi32 -luser32 -lcomctl32 -lshell32 -lole32
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include <stdarg.h>

#define TEST_ROOT      L"C:\\BD_Test_Area"
#define REPORT_FILE    L"C:\\BD_Test_Area\\TestReport.txt"
#define INJECT_RESULT  L"C:\\BD_Test_Area\\inject_result.txt"
#define INJECT_EXE     L"C:\\BD_Test_Area\\bd_inject_test.exe"
#define MBR_BACKUP     L"C:\\BD_Test_Area\\mbr_original.bin"

#define TEST_TIMEOUT_MS  50000     /* 单项自动判定超时：50 秒 */
#define FILE_TOTAL       111       /* 分 3 个目录，每个 ≤ 限流额度 */
#define NET_PROMPT_SEC   15        /* 网络用例询问用户的超时 */

/* ---------------- 控件 ID ---------------- */
#define ID_BTN_TEST0   1001        /* 右侧 5 个测试项按钮：1001..1005 */
#define ID_BTN_CLOSE   1006
#define ID_ALLBAR      1007
#define ID_CURBAR      1008
#define ID_LOGLIST     1009
#define ID_STATUS      1010
#define ID_DETAIL      1011

#define TIMER_TICK     1

/* ---------------- 测试结果 ---------------- */
enum { RES_NONE = 0, RES_PASS, RES_FAIL, RES_UNKNOWN, RES_SKIP };

/* ---------------- 状态机 ---------------- */
enum {
    ST_IDLE = 0,
    ST_FILE_PREP, ST_FILE_COOLDOWN, ST_FILE_WAIT,
    ST_REG_START, ST_REG_WAIT,
    ST_MBR_START, ST_MBR_WAIT,
    ST_INJ_START, ST_INJ_WAIT,
    ST_NET_START, ST_NET_WAIT
};

static HWND g_hwnd, g_hAllBar, g_hCurBar, g_hStatus, g_hDetail, g_hLog, g_hClose;
static HWND g_hTestBtn[5];

static int  g_state = ST_IDLE;
static DWORD g_stateStart = 0;
static DWORD g_nextPoll = 0;
static BOOL g_running = FALSE;
static BOOL g_paused = FALSE;       /* 弹出模态询问时暂停状态机 */
static BOOL g_skipMbr = FALSE;
static int  g_testIndex = 0;
static const int g_totalTests = 5;
static int  g_results[5];
static wchar_t g_resultMsgs[5][256];
static wchar_t g_report[32768];

/* 文件测试 */
static int  g_filesCreated = 0;
/* 注册表测试 */
static wchar_t g_regMarker[64];
/* MBR 测试 */
static BYTE g_mbrOrig[512];
static BOOL g_mbrPatched = FALSE;
/* 注入测试 */
static PROCESS_INFORMATION g_injProc;
static BOOL g_injProcValid = FALSE;
/* 网络测试 */
static PROCESS_INFORMATION g_netProc;
static BOOL g_netProcValid = FALSE;
static wchar_t g_netExePath[MAX_PATH * 2];
/* 弹出询问 */
static HWND g_askWnd = NULL;
static int  g_askResult = -2;
static int  g_askRemain = 0;

static const wchar_t* g_btnLabels[5] = {
    L"1. 文件防护",
    L"2. 注册表防护",
    L"3. MBR 防护",
    L"4. 进程注入防护",
    L"5. 网络防护"
};
static const wchar_t* g_btnSubs[5] = {
    L"批量删除自动回滚",
    L"关键键篡改回滚",
    L"引导扇区恢复",
    L"阻止注入 dism.exe",
    L"拦截外联"
};

/* ==================== 通用工具 ==================== */

static DWORD elapsed_ms(void) { return GetTickCount() - g_stateStart; }

static BOOL process_running(const wchar_t* name)
{
    BOOL found = FALSE;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { found = TRUE; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static BOOL is_elevated(void)
{
    BOOL admin = FALSE;
    PSID grp = NULL;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
        CheckTokenMembership(NULL, grp, &admin);
        FreeSid(grp);
    }
    return admin;
}

static BOOL enable_priv(LPCWSTR name)
{
    HANDLE tok; LUID luid; TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) { CloseHandle(tok); return FALSE; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

static void make_dir(const wchar_t* p) { SHCreateDirectoryExW(NULL, p, NULL); }

static BOOL create_empty(const wchar_t* p)
{
    HANDLE h = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(h);
    return TRUE;
}

static void remove_tree(const wchar_t* dir)
{
    wchar_t search[MAX_PATH * 2];
    swprintf(search, MAX_PATH * 2, L"%s\\*.*", dir);
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            wchar_t p[MAX_PATH * 2];
            swprintf(p, MAX_PATH * 2, L"%s\\%s", dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_tree(p);
            else { SetFileAttributesW(p, FILE_ATTRIBUTE_NORMAL); DeleteFileW(p); }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    SetFileAttributesW(dir, FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(dir);
}

static int count_children(const wchar_t* dir)
{
    wchar_t search[MAX_PATH * 2];
    swprintf(search, MAX_PATH * 2, L"%s\\*", dir);
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    int n = 0;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        n++;
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return n;
}

/* ==================== UI ==================== */

static void log_line(const wchar_t* text)
{
    if (g_hLog) {
        int i = (int)SendMessageW(g_hLog, LB_ADDSTRING, 0, (LPARAM)text);
        SendMessageW(g_hLog, LB_SETTOPINDEX, i, 0);
    }
    size_t have = wcslen(g_report);
    if (have < 32000) {
        wcsncat(g_report, text, 32000 - have);
        wcsncat(g_report, L"\r\n", 32000 - wcslen(g_report));
    }
}

static void log_fmt(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 1024, fmt, ap);
    va_end(ap);
    log_line(buf);
}

static void set_status(const wchar_t* title, const wchar_t* detail)
{
    if (g_hStatus) SetWindowTextW(g_hStatus, title);
    if (g_hDetail) SetWindowTextW(g_hDetail, detail);
}

static void set_all_progress(int permille)
{
    if (permille < 0) permille = 0;
    if (permille > 1000) permille = 1000;
    SendMessageW(g_hAllBar, PBM_SETPOS, (WPARAM)permille, 0);
}

static void set_cur_progress(int permille)
{
    if (permille < 0) permille = 0;
    if (permille > 1000) permille = 1000;
    SendMessageW(g_hCurBar, PBM_SETPOS, (WPARAM)permille, 0);
}

static const wchar_t* result_tag(int r)
{
    switch (r) {
    case RES_PASS:    return L"通过";
    case RES_FAIL:    return L"失败";
    case RES_UNKNOWN: return L"未知";
    case RES_SKIP:    return L"跳过";
    default:          return NULL;
    }
}

/* 刷新右侧按钮文字：未测显示说明，已测追加结果 */
static void update_test_button(int i)
{
    if (!g_hTestBtn[i]) return;
    wchar_t t[256];
    const wchar_t* tag = result_tag(g_results[i]);
    if (tag) swprintf(t, 256, L"%s\n%s —— %s", g_btnLabels[i], g_btnSubs[i], tag);
    else     swprintf(t, 256, L"%s\n%s", g_btnLabels[i], g_btnSubs[i]);
    SetWindowTextW(g_hTestBtn[i], t);
}

static void enable_test_buttons(BOOL enable)
{
    for (int i = 0; i < 5; i++)
        if (g_hTestBtn[i]) EnableWindow(g_hTestBtn[i], enable);
}

/* ==================== 网络询问对话框（15 秒超时 → 未知） ==================== */

#define ID_ASK_YES 2001
#define ID_ASK_NO  2002

static LRESULT CALLBACK AskWndProc(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    static HWND hCount = NULL;
    switch (msg) {
    case WM_CREATE: {
        CreateWindowW(L"STATIC",
            L"请查看屏幕上是否出现了 BDProtect 的「网络防护拦截」窗口。\n\n"
            L"是 = 已弹出（测试通过）\n"
            L"否 = 未弹出（测试失败）\n"
            L"15 秒内不作答 = 结果未知",
            WS_CHILD | WS_VISIBLE, 20, 15, 460, 90, h, NULL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"是，已弹出", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      70, 120, 140, 34, h, (HMENU)ID_ASK_YES, NULL, NULL);
        CreateWindowW(L"BUTTON", L"否，未弹出", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      250, 120, 140, 34, h, (HMENU)ID_ASK_NO, NULL, NULL);
        hCount = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_CENTER,
                               20, 165, 460, 24, h, NULL, NULL, NULL);
        g_askRemain = NET_PROMPT_SEC;
        wchar_t t[64];
        swprintf(t, 64, L"剩余 %d 秒（超时判定为“未知”）", g_askRemain);
        SetWindowTextW(hCount, t);
        SetTimer(h, 1, 1000, NULL);
        return 0;
    }
    case WM_TIMER:
        if (--g_askRemain <= 0) {
            g_askResult = -1;
            DestroyWindow(h);
        } else {
            wchar_t t[64];
            swprintf(t, 64, L"剩余 %d 秒（超时判定为“未知”）", g_askRemain);
            SetWindowTextW(hCount, t);
        }
        return 0;
    case WM_COMMAND:
        g_askResult = (LOWORD(w) == ID_ASK_YES) ? 1 : 0;
        DestroyWindow(h);
        return 0;
    case WM_CLOSE:
        g_askResult = -1;
        DestroyWindow(h);
        return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

/* 返回 1=是 0=否 -1=超时 */
static int ask_network_prompt(void)
{
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = AskWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BDTestAskCls";
    RegisterClassExW(&wc);

    g_askResult = -2;
    int w = 520, hgt = 240;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    g_askWnd = CreateWindowExW(WS_EX_TOPMOST, L"BDTestAskCls", L"网络防护结果确认",
                               WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                               (sw - w) / 2, (sh - hgt) / 2, w, hgt,
                               g_hwnd, NULL, wc.hInstance, NULL);
    if (!g_askWnd) return -1;

    EnableWindow(g_hwnd, FALSE);
    g_paused = TRUE;

    MSG msg;
    while (IsWindow(g_askWnd)) {
        if (GetMessageW(&msg, NULL, 0, 0) <= 0) break;
        if (!IsDialogMessageW(g_askWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    g_paused = FALSE;
    EnableWindow(g_hwnd, TRUE);
    SetForegroundWindow(g_hwnd);
    return (g_askResult == -2) ? -1 : g_askResult;
}

/* ==================== 注册表辅助 ==================== */

static BOOL read_reg_value(const wchar_t* key, const wchar_t* name, wchar_t* out, int cap)
{
    HKEY h = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return FALSE;
    DWORD cb = (DWORD)(cap * sizeof(wchar_t)), type = 0;
    BOOL ok = RegQueryValueExW(h, name, NULL, &type, (LPBYTE)out, &cb) == ERROR_SUCCESS;
    RegCloseKey(h);
    return ok;
}

/* ==================== MBR 辅助 ==================== */

static BOOL read_mbr(BYTE* buf)
{
    HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD bytes = 0;
    BOOL ok = ReadFile(h, buf, 512, &bytes, NULL) && bytes == 512;
    CloseHandle(h);
    return ok;
}

static BOOL write_mbr(const BYTE* buf)
{
    HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    DWORD bytes = 0;
    BOOL ok = WriteFile(h, buf, 512, &bytes, NULL) && bytes == 512;
    CloseHandle(h);
    return ok;
}

static void restore_mbr_if_needed(void)
{
    if (!g_mbrPatched) return;
    BYTE now[512];
    if (read_mbr(now) && memcmp(now, g_mbrOrig, 512) == 0) {
        g_mbrPatched = FALSE;
        return;
    }
    write_mbr(g_mbrOrig);
    g_mbrPatched = FALSE;
}

/* ==================== 测试流程 ==================== */

static void start_test(int idx);
static void stop_helpers(void);

static void write_report(void)
{
    FILE* f = _wfopen(REPORT_FILE, L"w, ccs=UTF-8");
    if (f) { fwprintf(f, L"%s", g_report); fclose(f); }
}

static void update_overall(void)
{
    int done = 0;
    for (int i = 0; i < g_totalTests; i++)
        if (g_results[i] != RES_NONE) done++;
    set_all_progress(done * 1000 / g_totalTests);
}

static void complete_test(int result, const wchar_t* msg)
{
    int idx = g_testIndex;
    if (idx < 0 || idx >= g_totalTests) return;
    g_results[idx] = result;
    wcsncpy(g_resultMsgs[idx], msg, 255);
    g_resultMsgs[idx][255] = 0;

    log_fmt(L"[%s] %s —— %s", result_tag(result), g_btnLabels[idx], msg);

    stop_helpers();
    g_running = FALSE;
    g_state = ST_IDLE;
    set_cur_progress(1000);
    update_test_button(idx);
    update_overall();
    enable_test_buttons(TRUE);
    set_status(L"就绪", L"请在右侧选择要测试的项目");
    write_report();

    int done = 0;
    for (int i = 0; i < g_totalTests; i++)
        if (g_results[i] != RES_NONE) done++;

    if (done >= g_totalTests) {
        int pass = 0, fail = 0, unknown = 0, skipped = 0;
        for (int i = 0; i < g_totalTests; i++) {
            if (g_results[i] == RES_PASS) pass++;
            else if (g_results[i] == RES_FAIL) fail++;
            else if (g_results[i] == RES_SKIP) skipped++;
            else unknown++;
        }
        log_line(L"");
        log_fmt(L"========== 测试汇总 ==========");
        log_fmt(L"通过 %d 项，失败 %d 项，未知 %d 项，跳过 %d 项（共 %d 项）",
                pass, fail, unknown, skipped, g_totalTests);
        write_report();
        MessageBoxW(g_hwnd,
                    fail == 0 && unknown == 0 ? L"全部测试通过。" : L"全部测试已完成，请查看窗口中的结果。",
                    L"BDProtect 防护测试", MB_OK | MB_ICONINFORMATION);
    }
}

/* 每项测试结束时统一收尾：恢复 MBR、停网络线程、结束注入程序 */
static void stop_helpers(void)
{
    if (g_netProcValid) {
        TerminateProcess(g_netProc.hProcess, 0);
        WaitForSingleObject(g_netProc.hProcess, 1000);
        CloseHandle(g_netProc.hThread);
        CloseHandle(g_netProc.hProcess);
        g_netProcValid = FALSE;
    }
    if (g_netExePath[0]) { DeleteFileW(g_netExePath); g_netExePath[0] = 0; }
    if (g_injProcValid) {
        TerminateProcess(g_injProc.hProcess, 0);
        WaitForSingleObject(g_injProc.hProcess, 1000);
        CloseHandle(g_injProc.hThread);
        CloseHandle(g_injProc.hProcess);
        g_injProcValid = FALSE;
    }
    restore_mbr_if_needed();
}

static void start_test(int idx)
{
    if (g_running) return;
    g_testIndex = idx;
    g_running = TRUE;
    g_stateStart = GetTickCount();
    g_nextPoll = 0;
    set_cur_progress(0);
    enable_test_buttons(FALSE);

    wchar_t title[160];
    swprintf(title, 160, L"%s - %s", g_btnLabels[idx], g_btnSubs[idx]);
    set_status(title, L"准备中...");
    log_line(L"");
    log_fmt(L"===== 开始单项测试：%s =====", title);

    switch (idx) {
    case 0: g_state = ST_FILE_PREP; break;
    case 1: g_state = ST_REG_START; break;
    case 2: g_state = ST_MBR_START; break;
    case 3: g_state = ST_INJ_START; break;
    case 4: g_state = ST_NET_START; break;
    default: g_running = FALSE; enable_test_buttons(TRUE); break;
    }
}

/* 文件测试数据目录 */
static void file_test_dir(int d, wchar_t* out, int cap)
{
    swprintf(out, cap, L"%s\\filetest%d\\sub", TEST_ROOT, d);
}

/* ---- 各项状态处理 ---- */

static void tick_file_prep(void)
{
    set_status(L"1. 文件防护 - 批量删除自动回滚", L"正在创建测试文件（准备回滚验证数据）...");
    remove_tree(TEST_ROOT);
    make_dir(TEST_ROOT);
    int created = 0;
    for (int d = 0; d < 3; d++) {
        wchar_t dir[MAX_PATH];
        file_test_dir(d, dir, MAX_PATH);
        make_dir(dir);
        for (int i = 0; i < 37; i++) {
            wchar_t p[MAX_PATH];
            swprintf(p, MAX_PATH, L"%s\\d%02d.txt", dir, i);
            if (create_empty(p)) created++;
        }
    }
    g_filesCreated = created;
    log_fmt(L"已创建 %d / %d 个测试文件（分 3 个目录）。", created, FILE_TOTAL);
    log_line(L"等待 5 秒确保备份完成，然后执行批量删除...");
    g_state = ST_FILE_COOLDOWN;
    g_stateStart = GetTickCount();
}

static void tick_file_cooldown(void)
{
    DWORD e = elapsed_ms();
    wchar_t buf[128];
    swprintf(buf, 128, L"准备中：%lu / 5 秒（等待备份落盘）", (unsigned long)(e / 1000));
    set_status(L"1. 文件防护 - 批量删除自动回滚", buf);
    set_cur_progress((int)(e * 1000 / 5000));
    if (e < 5000) return;

    int deleted = 0;
    for (int d = 0; d < 3; d++) {
        wchar_t dir[MAX_PATH];
        file_test_dir(d, dir, MAX_PATH);
        for (int i = 0; i < 37; i++) {
            wchar_t p[MAX_PATH];
            swprintf(p, MAX_PATH, L"%s\\d%02d.txt", dir, i);
            SetFileAttributesW(p, FILE_ATTRIBUTE_NORMAL);
            if (DeleteFileW(p)) deleted++;
        }
    }
    log_fmt(L"已删除 %d 个文件，最多等待 50 秒检测自动回滚...", deleted);
    g_state = ST_FILE_WAIT;
    g_stateStart = GetTickCount();
    g_nextPoll = 0;
}

static void tick_file_wait(void)
{
    DWORD e = elapsed_ms();
    DWORD now = GetTickCount();
    static int restored = 0;

    if (now >= g_nextPoll) {
        g_nextPoll = now + 500;
        restored = 0;
        for (int d = 0; d < 3; d++) {
            wchar_t dir[MAX_PATH];
            file_test_dir(d, dir, MAX_PATH);
            restored += count_children(dir);
        }
        if (restored >= 105) {
            complete_test(RES_PASS, L"批量删除被拦截，文件已自动回滚");
            return;
        }
    }

    wchar_t buf[160];
    swprintf(buf, 160, L"已恢复 %d / %d 个文件，剩余 %lu 秒",
             restored, FILE_TOTAL, (unsigned long)((TEST_TIMEOUT_MS - e) / 1000 + 1));
    set_status(L"1. 文件防护 - 批量删除自动回滚", buf);
    set_cur_progress((int)(e * 1000 / TEST_TIMEOUT_MS));

    if (e >= TEST_TIMEOUT_MS)
        complete_test(RES_FAIL, restored ? L"回滚不完整：只恢复了部分文件" : L"50 秒内未检测到回滚（未弹窗或用户选择了同意）");
}

static void tick_reg_start(void)
{
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    swprintf(g_regMarker, 64, L"BDTest-%lu", (unsigned long)GetTickCount());

    HKEY h = NULL;
    BOOL ok = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS) {
        ok = RegSetValueExW(h, L"BDTestValue", 0, REG_SZ,
                            (const BYTE*)g_regMarker,
                            (DWORD)((wcslen(g_regMarker) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
        RegCloseKey(h);
    }
    if (!ok) {
        complete_test(RES_SKIP, L"无法写入测试注册表值（需要管理员权限）");
        return;
    }
    log_fmt(L"已写入测试值 HKLM\\...\\Run\\BDTestValue = %s，最多等待 50 秒检测回滚...", g_regMarker);
    g_state = ST_REG_WAIT;
    g_stateStart = GetTickCount();
    g_nextPoll = 0;
}

static void tick_reg_wait(void)
{
    DWORD e = elapsed_ms();
    DWORD now = GetTickCount();
    static BOOL rolledBack = FALSE;

    if (now >= g_nextPoll) {
        g_nextPoll = now + 500;
        wchar_t val[MAX_PATH];
        BOOL exists = read_reg_value(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                     L"BDTestValue", val, MAX_PATH);
        rolledBack = !exists || _wcsicmp(val, g_regMarker) != 0;
        if (rolledBack) {
            complete_test(RES_PASS, L"注册表修改被拦截并已回滚");
            return;
        }
    }

    wchar_t buf[160];
    swprintf(buf, 160, L"等待回滚，剩余 %lu 秒",
             (unsigned long)((TEST_TIMEOUT_MS - e) / 1000 + 1));
    set_status(L"2. 注册表防护 - 关键键篡改回滚", buf);
    set_cur_progress((int)(e * 1000 / TEST_TIMEOUT_MS));

    if (e >= TEST_TIMEOUT_MS) {
        HKEY h = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS) {
            RegDeleteValueW(h, L"BDTestValue");
            RegCloseKey(h);
        }
        complete_test(RES_FAIL, L"50 秒内未检测到注册表回滚");
    }
}

static void tick_mbr_start(void)
{
    if (g_skipMbr) {
        complete_test(RES_SKIP, L"用户选择跳过 MBR 测试");
        return;
    }
    if (!read_mbr(g_mbrOrig)) {
        complete_test(RES_SKIP, L"无法读取 PhysicalDrive0（需要管理员权限）");
        return;
    }
    FILE* f = _wfopen(MBR_BACKUP, L"wb");
    if (f) { fwrite(g_mbrOrig, 1, 512, f); fclose(f); }

    BYTE patched[512];
    memcpy(patched, g_mbrOrig, 512);
    patched[0] = 0xAA; patched[1] = 0xBB; patched[2] = 0xCC; patched[3] = 0xDD;
    if (!write_mbr(patched)) {
        complete_test(RES_SKIP, L"写入 PhysicalDrive0 被系统拒绝");
        return;
    }
    g_mbrPatched = TRUE;
    log_line(L"已改写 MBR 前 4 字节，最多等待 50 秒检测自动恢复...");
    g_state = ST_MBR_WAIT;
    g_stateStart = GetTickCount();
    g_nextPoll = 0;
}

static void tick_mbr_wait(void)
{
    DWORD e = elapsed_ms();
    DWORD now = GetTickCount();
    static BOOL restored = FALSE;

    if (now >= g_nextPoll) {
        g_nextPoll = now + 500;
        BYTE cur[512];
        restored = read_mbr(cur) && memcmp(cur, g_mbrOrig, 512) == 0;
        if (restored) {
            g_mbrPatched = FALSE;
            complete_test(RES_PASS, L"MBR 修改被拦截并已恢复");
            return;
        }
    }

    wchar_t buf[128];
    swprintf(buf, 128, L"等待 MBR 恢复，剩余 %lu 秒",
             (unsigned long)((TEST_TIMEOUT_MS - e) / 1000 + 1));
    set_status(L"3. MBR 防护 - 引导扇区恢复", buf);
    set_cur_progress((int)(e * 1000 / TEST_TIMEOUT_MS));

    if (e >= TEST_TIMEOUT_MS) {
        restore_mbr_if_needed();
        complete_test(RES_FAIL, L"50 秒内未检测到 MBR 恢复（已由测试工具强制恢复）");
    }
}

/* ---- 注入测试：释放一个独立程序，对 dism.exe 注入 ---- */

static void tick_inj_start(void)
{
    DeleteFileW(INJECT_RESULT);
    DeleteFileW(INJECT_EXE);

    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    if (!CopyFileW(self, INJECT_EXE, FALSE)) {
        complete_test(RES_SKIP, L"无法释放注入测试程序");
        return;
    }

    wchar_t cmd[MAX_PATH * 2];
    swprintf(cmd, MAX_PATH * 2, L"\"%s\" --inject-dism \"%s\"", INJECT_EXE, INJECT_RESULT);

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    memset(&g_injProc, 0, sizeof(g_injProc));
    BOOL ok = CreateProcessW(INJECT_EXE, cmd, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &g_injProc);
    g_injProcValid = ok;
    if (!ok) {
        complete_test(RES_SKIP, L"无法启动注入测试程序");
        return;
    }
    log_line(L"已释放注入测试程序，目标为系统 dism.exe；最多等待 50 秒检测拦截结果...");
    g_state = ST_INJ_WAIT;
    g_stateStart = GetTickCount();
    g_nextPoll = 0;
}

static void tick_inj_wait(void)
{
    DWORD e = elapsed_ms();
    DWORD now = GetTickCount();
    static wchar_t result[128];
    static BOOL haveResult = FALSE;

    if (now >= g_nextPoll) {
        g_nextPoll = now + 500;
        FILE* f = _wfopen(INJECT_RESULT, L"r");
        if (f) {
            char buf[256] = {0};
            size_t n = fread(buf, 1, 255, f);
            fclose(f);
            buf[n] = 0;
            if (strstr(buf, "SUSPENDED"))         { wcscpy(result, L"注入线程被挂起，注入被阻止"); haveResult = TRUE; }
            else if (strstr(buf, "CREATE_FAILED")) { wcscpy(result, L"系统/防护拒绝了远程线程创建，注入被阻止"); haveResult = TRUE; }
            else if (strstr(buf, "INJECTED"))      { wcscpy(result, L"注入线程正常运行，未被拦截"); haveResult = TRUE; }
            else if (strstr(buf, "OPEN_FAILED"))   { wcscpy(result, L"无法打开目标进程，无法判定"); haveResult = TRUE; }
            else if (strstr(buf, "NO_TARGET"))     { wcscpy(result, L"未能启动 dism.exe 目标进程，无法判定"); haveResult = TRUE; }
            else if (strstr(buf, "THREAD_EXITED")) { wcscpy(result, L"注入线程已退出，无法判定"); haveResult = TRUE; }
        }
        if (haveResult) {
            BOOL pass = (wcsstr(result, L"阻止") != NULL);
            BOOL unknown = (wcsstr(result, L"无法判定") != NULL);
            DeleteFileW(INJECT_EXE);
            complete_test(unknown ? RES_UNKNOWN : (pass ? RES_PASS : RES_FAIL), result);
            return;
        }
    }

    wchar_t buf[128];
    swprintf(buf, 128, L"等待注入拦截结果，剩余 %lu 秒",
             (unsigned long)((TEST_TIMEOUT_MS - e) / 1000 + 1));
    set_status(L"4. 进程注入防护 - 阻止注入 dism.exe", buf);
    set_cur_progress((int)(e * 1000 / TEST_TIMEOUT_MS));

    if (e >= TEST_TIMEOUT_MS) {
        BOOL childAlive = FALSE;
        if (g_injProcValid) {
            childAlive = WaitForSingleObject(g_injProc.hProcess, 0) == WAIT_TIMEOUT;
            TerminateProcess(g_injProc.hProcess, 0);
            WaitForSingleObject(g_injProc.hProcess, 1000);
            CloseHandle(g_injProc.hThread);
            CloseHandle(g_injProc.hProcess);
            g_injProcValid = FALSE;
        }
        DeleteFileW(INJECT_EXE);
        if (childAlive)
            complete_test(RES_FAIL, L"注入程序仍在运行且未产生拦截结果");
        else
            complete_test(RES_PASS, L"注入程序异常退出，未能完成注入");
    }
}

/* ---- 网络测试 ---- */

/* 子进程：持续连接百度，用于触发网络防护弹窗。
   必须用独立进程：本工具自己一旦被用户加进联网信任列表，以后就再也不会弹窗，
   测试会永远得到“未弹出”。每次运行换一个随机文件名，保证是陌生程序。 */
static int net_child_main(int seconds)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    DWORD start = GetTickCount();
    while ((int)((GetTickCount() - start) / 1000) < seconds) {
        if (!res) {
            if (getaddrinfo("www.baidu.com", "80", &hints, &res) != 0) { Sleep(500); continue; }
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            u_long nb = 1;
            ioctlsocket(s, FIONBIO, &nb);
            connect(s, res->ai_addr, (int)res->ai_addrlen);
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            struct timeval tv;
            tv.tv_sec = 3;
            tv.tv_usec = 0;
            if (select(0, NULL, &wf, NULL, &tv) > 0 && FD_ISSET(s, &wf)) {
                int err = 0, len = sizeof(err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
                if (err == 0) {
                    Sleep(2500);   /* 保持连接，确保网络防护能扫描到 ESTABLISHED */
                    closesocket(s);
                    Sleep(200);
                    continue;
                }
            }
            closesocket(s);
        }
        Sleep(300);
    }
    if (res) freeaddrinfo(res);
    WSACleanup();
    return 0;
}

static void tick_net_start(void)
{
    make_dir(TEST_ROOT);

    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    swprintf(g_netExePath, MAX_PATH * 2, L"%s\\net_test_%lu.exe", TEST_ROOT,
             (unsigned long)GetTickCount());
    if (!CopyFileW(self, g_netExePath, FALSE)) {
        g_netExePath[0] = 0;
        complete_test(RES_SKIP, L"无法释放网络测试程序");
        return;
    }

    wchar_t cmd[MAX_PATH * 4];
    swprintf(cmd, MAX_PATH * 4, L"\"%s\" --net-connect 60", g_netExePath);

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    memset(&g_netProc, 0, sizeof(g_netProc));
    g_netProcValid = CreateProcessW(g_netExePath, cmd, NULL, NULL, FALSE,
                                    CREATE_NO_WINDOW, NULL, NULL, &si, &g_netProc) != 0;
    if (!g_netProcValid) {
        DeleteFileW(g_netExePath);
        g_netExePath[0] = 0;
        complete_test(RES_SKIP, L"无法启动网络测试程序");
        return;
    }

    log_line(L"已释放独立测试程序并持续连接 www.baidu.com:80，等待网络防护弹窗...");
    g_state = ST_NET_WAIT;
    g_stateStart = GetTickCount();
}

static void tick_net_wait(void)
{
    DWORD e = elapsed_ms();
    if (e < 4000) {
        wchar_t buf[160];
        swprintf(buf, 160, L"正在连接 www.baidu.com，剩余 %lu 秒",
                 (unsigned long)((4000 - e) / 1000 + 1));
        set_status(L"5. 网络防护 - 拦截外联", buf);
        set_cur_progress((int)(e * 1000 / 4000));
        return;
    }

    set_status(L"5. 网络防护 - 拦截外联", L"等待用户确认是否看到拦截弹窗...");
    int ans = ask_network_prompt();

    if (ans == 1)       complete_test(RES_PASS, L"网络防护弹窗已弹出");
    else if (ans == 0)  complete_test(RES_FAIL, L"未出现网络防护弹窗");
    else                complete_test(RES_UNKNOWN, L"15 秒内未确认，结果未知");
}

/* 定时器总调度 */
static void tick(void)
{
    if (g_paused || !g_running) return;

    switch (g_state) {
    case ST_FILE_PREP:     tick_file_prep(); break;
    case ST_FILE_COOLDOWN: tick_file_cooldown(); break;
    case ST_FILE_WAIT:     tick_file_wait(); break;
    case ST_REG_START:     tick_reg_start(); break;
    case ST_REG_WAIT:      tick_reg_wait(); break;
    case ST_MBR_START:     tick_mbr_start(); break;
    case ST_MBR_WAIT:      tick_mbr_wait(); break;
    case ST_INJ_START:     tick_inj_start(); break;
    case ST_INJ_WAIT:      tick_inj_wait(); break;
    case ST_NET_START:     tick_net_start(); break;
    case ST_NET_WAIT:      tick_net_wait(); break;
    default: break;
    }
}

/* ==================== 注入子程序（--inject-dism） ==================== */

static void write_inject_result(const char* text)
{
    FILE* f = _wfopen(INJECT_RESULT, L"w");
    if (f) { fwrite(text, 1, strlen(text), f); fclose(f); }
}

static ULONGLONG ft_diff_ms(const FILETIME* a, const FILETIME* b)
{
    ULARGE_INTEGER x, y;
    x.LowPart = a->dwLowDateTime; x.HighPart = a->dwHighDateTime;
    y.LowPart = b->dwLowDateTime; y.HighPart = b->dwHighDateTime;
    return (x.QuadPart - y.QuadPart) / 10000ULL;
}

/* 以“挂起”方式启动系统 dism.exe 作为注入目标。
   dism /Get-Packages 在执行环境不合适时几十毫秒就会退出（实测 0.08 秒），
   进程一退注入线程也跟着消失，防护程序 2.5 秒一次的扫描根本来不及看到。
   挂起创建后主线程不会运行，进程能稳定存活；注入线程仍可远程创建，
   判定完成后 TerminateProcess 收掉即可。 */
static int inject_child_main(const wchar_t* resultPath)
{
    enable_priv(SE_DEBUG_NAME);

    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    wchar_t dism[MAX_PATH];
    swprintf(dism, MAX_PATH, L"%s\\Dism.exe", sys);
    wchar_t cmd[MAX_PATH * 2];
    swprintf(cmd, MAX_PATH * 2, L"\"%s\" /online /Get-Packages", dism);

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(dism, cmd, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        char buf[64];
        sprintf(buf, "RESULT=NO_TARGET\r\nERR=%lu\r\n", GetLastError());
        write_inject_result(buf);
        return 0;
    }
    DWORD dismPid = pi.dwProcessId;

    char result[128] = {0};
    HANDLE hProc = NULL;
    void* mem = NULL;
    HANDLE hThread = NULL;

    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                        PROCESS_VM_WRITE | PROCESS_VM_READ |
                        PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
                        FALSE, dismPid);
    if (!hProc) {
        sprintf(result, "RESULT=OPEN_FAILED\r\nERR=%lu\r\n", GetLastError());
        goto cleanup;
    }

    mem = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
    if (!mem) {
        sprintf(result, "RESULT=CREATE_FAILED\r\nERR=%lu\r\n", GetLastError());
        goto cleanup;
    }

    {
        BYTE jmp_self[2] = { 0xEB, 0xFE };   /* jmp $：死循环，便于判定线程是否被挂起 */
        SIZE_T written = 0;
        WriteProcessMemory(hProc, mem, jmp_self, sizeof(jmp_self), &written);
    }

    hThread = CreateRemoteThread(hProc, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (!hThread) {
        sprintf(result, "RESULT=CREATE_FAILED\r\nERR=%lu\r\n", GetLastError());
        goto cleanup;
    }

    {
        /* 每秒采样一次线程 CPU。死循环线程若未被拦截会吃满 1 个核；
           被防护挂起后 CPU 增量归零 → 判定为已拦截。 */
        FILETIME c, e, prevK, prevU, curK, curU;
        GetThreadTimes(hThread, &c, &e, &prevK, &prevU);
        BOOL threadAlive = TRUE;

        for (int sec = 0; sec < 15; sec++) {
            Sleep(1000);
            if (WaitForSingleObject(hThread, 0) != WAIT_TIMEOUT) { threadAlive = FALSE; break; }
            GetThreadTimes(hThread, &c, &e, &curK, &curU);
            ULONGLONG busy = ft_diff_ms(&curK, &prevK) + ft_diff_ms(&curU, &prevU);
            prevK = curK;
            prevU = curU;
            if (busy < 100) {   /* 1 秒内几乎不消耗 CPU：被挂起 */
                sprintf(result, "RESULT=SUSPENDED\r\nCPU=%llu\r\n", (unsigned long long)busy);
                break;
            }
        }
        if (!result[0]) {
            if (threadAlive) strcpy(result, "RESULT=INJECTED\r\n");
            else             strcpy(result, "RESULT=THREAD_EXITED\r\n");
        }
    }

cleanup:
    if (hThread) { SuspendThread(hThread); CloseHandle(hThread); }
    if (hProc) CloseHandle(hProc);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 1000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (!result[0]) strcpy(result, "RESULT=THREAD_EXITED\r\n");
    write_inject_result(result);
    (void)resultPath;
    return 0;
}

/* ==================== 主窗口 ==================== */

static void on_test_button(int i)
{
    if (g_running) return;

    if (i == 2) {   /* MBR 需要用户确认 */
        g_skipMbr = (MessageBoxW(g_hwnd,
            L"MBR 防护测试会临时改写物理磁盘 0 的引导扇区前 4 字节。\n\n"
            L"建议只在虚拟机/测试机上执行。工具会自动恢复，\n"
            L"但仍有极低概率造成引导异常。\n\n"
            L"选择“否”将跳过该项。",
            L"MBR 测试确认", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES);
    } else {
        g_skipMbr = FALSE;
    }
    start_test(i);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        HWND hTitle = CreateWindowW(L"STATIC", L"BDProtect 防护测试 —— 点击右侧任意一项单独测试",
                                    WS_CHILD | WS_VISIBLE, 15, 10, 690, 26, hwnd, NULL, NULL, NULL);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)font, TRUE);

        g_hStatus = CreateWindowW(L"STATIC", L"就绪，请在右侧选择要测试的项目",
                                  WS_CHILD | WS_VISIBLE, 15, 40, 690, 22,
                                  hwnd, (HMENU)ID_STATUS, NULL, NULL);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)font, TRUE);

        HWND hAllText = CreateWindowW(L"STATIC", L"总进度", WS_CHILD | WS_VISIBLE,
                                      15, 70, 60, 20, hwnd, NULL, NULL, NULL);
        SendMessageW(hAllText, WM_SETFONT, (WPARAM)font, TRUE);
        g_hAllBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
                                    WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                    80, 68, 625, 22, hwnd, (HMENU)ID_ALLBAR, NULL, NULL);

        HWND hCurText = CreateWindowW(L"STATIC", L"当前测试", WS_CHILD | WS_VISIBLE,
                                      15, 100, 60, 20, hwnd, NULL, NULL, NULL);
        SendMessageW(hCurText, WM_SETFONT, (WPARAM)font, TRUE);
        g_hCurBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
                                    WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                    80, 98, 625, 22, hwnd, (HMENU)ID_CURBAR, NULL, NULL);

        g_hDetail = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                  15, 128, 690, 22, hwnd, (HMENU)ID_DETAIL, NULL, NULL);
        SendMessageW(g_hDetail, WM_SETFONT, (WPARAM)font, TRUE);

        g_hLog = CreateWindowW(L"LISTBOX", NULL,
                               WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | LBS_NOINTEGRALHEIGHT,
                               15, 158, 460, 400, hwnd, (HMENU)ID_LOGLIST, NULL, NULL);
        SendMessageW(g_hLog, WM_SETFONT, (WPARAM)font, TRUE);

        for (int i = 0; i < 5; i++) {
            g_hTestBtn[i] = CreateWindowW(L"BUTTON", L"", WS_CHILD | WS_VISIBLE |
                                          BS_PUSHBUTTON | BS_MULTILINE,
                                          490, 158 + i * 76, 215, 64,
                                          hwnd, (HMENU)(INT_PTR)(ID_BTN_TEST0 + i), NULL, NULL);
            SendMessageW(g_hTestBtn[i], WM_SETFONT, (WPARAM)font, TRUE);
            update_test_button(i);
        }

        g_hClose = CreateWindowW(L"BUTTON", L"关闭", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 595, 580, 110, 34, hwnd, (HMENU)ID_BTN_CLOSE, NULL, NULL);
        SendMessageW(g_hClose, WM_SETFONT, (WPARAM)font, TRUE);

        SetTimer(hwnd, TIMER_TICK, 100, NULL);

        log_line(L"========== BDProtect 防护测试 ==========");
        log_fmt(L"管理员权限：%s", is_elevated() ? L"是" : L"否");
        log_fmt(L"BDProtect.exe：%s", process_running(L"BDProtect.exe") ? L"正在运行" : L"未运行");
        log_fmt(L"BDMain.exe：%s", process_running(L"BDMain.exe") ? L"正在运行" : L"未运行");
        log_line(L"提示：测试期间 BDProtect 会弹窗，请【不要手动点击】，等它超时按默认值处理；");
        log_line(L"      只有网络测试需要你手动确认（15 秒内作答）。");
        return 0;
    }

    case WM_TIMER:
        if (w == TIMER_TICK) tick();
        return 0;

    case WM_COMMAND:
        if (LOWORD(w) >= ID_BTN_TEST0 && LOWORD(w) < ID_BTN_TEST0 + 5) {
            on_test_button(LOWORD(w) - ID_BTN_TEST0);
        } else if (LOWORD(w) == ID_BTN_CLOSE) {
            SendMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        return 0;

    case WM_CLOSE:
        if (g_running) {
            if (MessageBoxW(hwnd, L"测试尚未完成，确定要退出吗？", L"确认退出",
                            MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
        }
        stop_helpers();
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, TIMER_TICK);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE prev, LPWSTR cmdLine, int show)
{
    /* 注入子程序模式 */
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        if (argc >= 2 && wcscmp(argv[1], L"--inject-dism") == 0) {
            int r = inject_child_main(argc >= 3 ? argv[2] : INJECT_RESULT);
            LocalFree(argv);
            return r;
        }
        if (argc >= 2 && wcscmp(argv[1], L"--net-connect") == 0) {
            int secs = argc >= 3 ? _wtoi(argv[2]) : 30;
            int r = net_child_main(secs > 0 ? secs : 30);
            LocalFree(argv);
            return r;
        }
        LocalFree(argv);
    }

    if (!is_elevated()) {
        MessageBoxW(NULL, L"请以管理员身份运行本测试工具。", L"BDProtect 防护测试",
                    MB_OK | MB_ICONERROR);
        return 1;
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    if (!process_running(L"BDProtect.exe")) {
        MessageBoxW(NULL, L"BDProtect.exe 没有在运行。\n请先启动防护程序再测试。",
                    L"BDProtect 防护测试", MB_OK | MB_ICONERROR);
        return 1;
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BDTestToolCls";
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);

    int w = 730, h = 670;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    HWND hwnd = CreateWindowExW(0, L"BDTestToolCls", L"BDProtect 防护测试",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                (sw - w) / 2, (sh - h) / 2, w, h,
                                NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
