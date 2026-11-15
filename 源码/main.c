#include "bd_common.h"
#include "bd_paths.h"
#include <tlhelp32.h>

BOOL g_bPaused = FALSE, g_bFilePrt = TRUE, g_bRegPrt = TRUE, g_bMbrPrt = TRUE, g_bNetPrt = TRUE;
BOOL g_bInjectPrt = TRUE, g_bCloudPrt = FALSE;
HICON g_hIconNormal, g_hIconGray;

static HWND g_hwnd = NULL;
static BOOL g_bExiting = FALSE;
static BOOL g_bShuttingDown = FALSE;
static BOOL g_bPausedBeforeShutdown = FALSE;

#define ID_TRAY_TOGGLE 1001
#define WM_TRAYICON (WM_USER + 1)
#define WM_APP_EXIT_REQUEST (WM_APP + 31)

DWORD WINAPI config_watch_thread(LPVOID p) {
    while(1) {
        Sleep(1000);
        if (g_bShuttingDown) return 0;   /* 关机流程中不再响应配置 */
        g_bFilePrt   = GetPrivateProfileIntW(L"Config", L"File",   1, BD_CONFIG_FILE);
        g_bRegPrt    = GetPrivateProfileIntW(L"Config", L"Reg",    1, BD_CONFIG_FILE);
        g_bMbrPrt    = GetPrivateProfileIntW(L"Config", L"Mbr",    1, BD_CONFIG_FILE);
        g_bNetPrt    = GetPrivateProfileIntW(L"Config", L"Net",    1, BD_CONFIG_FILE);
        g_bInjectPrt = GetPrivateProfileIntW(L"Config", L"Inject", 1, BD_CONFIG_FILE);
        g_bCloudPrt  = GetPrivateProfileIntW(L"Config", L"Cloud",  0, BD_CONFIG_FILE);
    }
    return 0;
}

/* 检查是否已经有另一个 BDProtect 实例在运行。
   仅靠全局互斥量不够：当后台进程以管理员权限运行、而新实例以普通权限启动时，
   CreateMutex 会返回 ERROR_ACCESS_DENIED，旧代码会误以为自己是第一个实例，
   于是出现多个托盘图标。这里再加一层进程枚举作为兜底。 */
static BOOL AnotherInstanceRunning(void)
{
    DWORD self = GetCurrentProcessId();
    BOOL found = FALSE;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID != self && _wcsicmp(pe.szExeFile, L"BDProtect.exe") == 0) {
                found = TRUE;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

/* 等待“请求退出”事件：仅用于卸载/升级时安全退出。
   普通用户无法通过托盘完全退出，只能暂停防护。 */
DWORD WINAPI exit_request_thread(LPVOID p) {
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, L"Global\\BDProtect_ExitRequest");
    if (!hEvent) return 0;
    WaitForSingleObject(hEvent, INFINITE);
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_EXIT_REQUEST, 0, 0);
    return 0;
}

/* 卸载/更新前会留下 stop.flag 标志文件。识别到标志后立刻安全退出，
   这样卸载程序和更新程序就不需要强杀关键进程（强杀会蓝屏）。 */
DWORD WINAPI stop_flag_thread(LPVOID p) {
    while (!g_bExiting) {
        if (GetFileAttributesW(BD_STOP_FLAG) != INVALID_FILE_ATTRIBUTES) {
            bd_log(L"[Exit] 检测到 stop.flag，安全退出");
            if (g_hwnd) PostMessageW(g_hwnd, WM_APP_EXIT_REQUEST, 0, 0);
            return 0;
        }
        Sleep(500);
    }
    return 0;
}

static void DoGracefulExit(HWND hwnd) {
    if (g_bExiting) return;
    g_bExiting = TRUE;
    /* 关键进程在终止前必须清除标记，否则系统会蓝屏 */
    bd_cleanup_critical();
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.hWnd = hwnd; nid.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    PostQuitMessage(0);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    static NOTIFYICONDATAW nid;
    switch(msg) {
        case WM_CREATE:
            g_hwnd = hwnd;
            g_hIconNormal = LoadIconW(NULL, IDI_SHIELD);
            g_hIconGray = LoadIconW(NULL, IDI_APPLICATION);
            nid.cbSize = sizeof(nid); nid.hWnd = hwnd; nid.uID = 1;
            nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP; nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = g_hIconNormal; wcscpy(nid.szTip, L"BDProtect 运行中");
            Shell_NotifyIconW(NIM_ADD, &nid);

            CreateThread(NULL, 0, config_watch_thread, NULL, 0, NULL);
            CreateThread(NULL, 0, exit_request_thread, NULL, 0, NULL);
            CreateThread(NULL, 0, stop_flag_thread, NULL, 0, NULL);
            return 0;

        case WM_TRAYICON:
            if(l == WM_RBUTTONUP) {
                POINT pt; GetCursorPos(&pt); HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_TRAY_TOGGLE, g_bPaused ? L"恢复病毒防护" : L"暂停病毒防护");
                SetForegroundWindow(hwnd);
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD|TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
                if(cmd == ID_TRAY_TOGGLE) {
                    g_bPaused = !g_bPaused;
                    nid.hIcon = g_bPaused ? g_hIconGray : g_hIconNormal;
                    wcscpy(nid.szTip, g_bPaused ? L"BDProtect 已暂停" : L"BDProtect 运行中");
                    Shell_NotifyIconW(NIM_MODIFY, &nid);
                }
            }
            return 0;

        case WM_APP_EXIT_REQUEST:
            DoGracefulExit(hwnd);
            return 0;

        /* 关机/重启/注销：必须先撤销“关键进程”标记再退出，
           否则系统终止本进程时会直接蓝屏，表现为关机变死机。 */
        case WM_QUERYENDSESSION:
            g_bShuttingDown = TRUE;
            g_bPausedBeforeShutdown = g_bPaused;
            g_bPaused = TRUE;          /* 停止一切拦截动作 */
            bd_cleanup_critical();
            return TRUE;

        case WM_ENDSESSION:
            if (w) {
                g_bShuttingDown = TRUE;
                g_bPaused = TRUE;
                bd_cleanup_critical();
            } else {
                /* 关机/注销被取消：恢复原来的暂停状态和关键进程标记，
                   否则防护会一直停着。 */
                g_bShuttingDown = FALSE;
                g_bPaused = g_bPausedBeforeShutdown;
                bd_start_self_guard();
            }
            return 0;

        case WM_DESTROY:
            bd_cleanup_critical();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE h, HINSTANCE p, LPWSTR cmd, int show) {
    SetConsoleOutputCP(GetACP());   /* 强制使用 ANSI 代码页 */

    /* 被映像劫持的“病毒样本”启动时会走到这里 */
    if (cmd && wcsstr(cmd, L"/blocked")) {
        MessageBoxW(NULL, L"因为疑似病毒而无法运行。", L"BDProtect 拦截", MB_OK | MB_ICONWARNING | MB_TOPMOST);
        return 0;
    }

    /* 卸载/更新过程中不要重新拉起自己 */
    if (GetFileAttributesW(BD_STOP_FLAG) != INVALID_FILE_ATTRIBUTES) return 0;

    // 互斥锁保护 (必须用这个句柄，不能丢弃)
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\BDProtect_Mutex");
    DWORD mutexErr = GetLastError();
    /* ERROR_ACCESS_DENIED 说明互斥量已被更高权限的实例占用，同样视为“已在运行” */
    if (hMutex == NULL || mutexErr == ERROR_ALREADY_EXISTS || mutexErr == ERROR_ACCESS_DENIED ||
        AnotherInstanceRunning()) {
        if (cmd == NULL || wcsstr(cmd, L"-silent") == NULL) {
            MessageBoxW(NULL, L"BDProtect 病毒防护程序已经在后台运行！\n\n请查看右下角系统托盘。", L"提示", MB_ICONINFORMATION | MB_TOPMOST);
        }
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    bd_paths_init();              /* 读取缓存目录记录；缓存目录消失时回退默认 */
    CreateDirectoryW(BD_TEMP_DIR, NULL);
    bd_log(L"[Path] install=%s cache=%s", g_bdInstallDir, g_bdCacheDir);
    CreateDirectoryW(BD_FILE_BAK_DIR, NULL);
    bd_ensure_store_dir();
    bd_ensure_state_dir();        /* 迁移配置并收紧 config.ini / stop.flag 目录权限 */
    bd_enable_core_privileges();
    bd_install_crash_guard();     /* 崩溃时先清除关键进程标记，避免整机蓝屏 */
    bd_ui_init();

    WNDCLASSEXW wc = {0}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = WndProc;
    wc.hInstance = h; wc.lpszClassName = L"BDCls"; RegisterClassExW(&wc);

    /* 必须是顶层窗口（不能是 HWND_MESSAGE），否则收不到 WM_QUERYENDSESSION，
       关机时会被系统直接终止关键进程，导致蓝屏/死机。窗口保持隐藏。 */
    HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, L"BDCls", L"BDProtect",
                                WS_POPUP, -32000, -32000, 1, 1, NULL, NULL, h, NULL);
    (void)hwnd;

    bd_file_monitor_start();
    bd_reg_monitor_start();
    bd_mbr_monitor_start();
    bd_net_monitor_start();
    bd_inject_monitor_start();
    bd_cloud_monitor_start();

    /* 加入系统级关键进程：被任务管理器或其它程序强行终止时系统直接蓝屏 */
    bd_start_self_guard();

    MSG msg; while(GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }

    bd_cleanup_critical();
    if (hMutex) CloseHandle(hMutex);
    return 0;
}
