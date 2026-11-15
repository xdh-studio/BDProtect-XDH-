#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")

#define ID_PROGRESS 1001
#define ID_STATUS   1002
#define ID_ED_INSTALL      2001
#define ID_BTN_BROWSE_INST 2002
#define ID_ED_CACHE        2003
#define ID_BTN_BROWSE_CACHE 2004
#define ID_BTN_OK    2005
#define ID_BTN_CANCEL 2006
#define GUARD_TASK  L"BDProtect_System_Guard"

/* 默认安装/缓存位置（默认仍是 C:\Program Files\BDApp 和 C:\BDtemp，均可在安装时更改） */
#define INSTALL_DEFAULT L"C:\\Program Files\\BDApp"
#define CACHE_DEFAULT   L"C:\\BDtemp"
/* 缓存位置记录文件名：放在安装目录内 */
#define CACHE_PATH_NAME   L"BDCachePath.txt"
/* 卸载信息注册表键：InstallLocation 记录上次的安装位置，更新模式据此恢复 */
#define UNINSTALL_REG_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\XDHProtectCenter"

/* 标志类文件必须长期保留，安装/更新时绝不覆盖或删除 */
#define STORE_DIR   L"C:\\ProgramData\\Microsoft\\Windows\\Caches\\BDProtectData"
#define RESTRICTED  STORE_DIR L"\\Restricted.txt"
#define USERUP      STORE_DIR L"\\UserUp.txt"

static BOOL g_UpdateMode = FALSE;

/* 安装/缓存目录（运行时可改；更新模式会先从记录文件恢复上次的安装位置） */
static wchar_t g_InstallDir[MAX_PATH] = INSTALL_DEFAULT;
static wchar_t g_CacheDir[MAX_PATH]   = CACHE_DEFAULT;
static BOOL g_PathChosen = FALSE;

// 文件资源映射表：只安装本软件自身的文件
// 病毒库与工具箱程序一律联网获取，不随安装包分发
struct FileMap {
    int id;
    const wchar_t* filename;
} files[] = {
    {102, L"BDMain.exe"}, {103, L"BDProtect.exe"}, {112, L"Uninstall.exe"},
    {117, L"main.ico"}, {119, L"BDProtectVersion.txt"}, {120, L"IPconfig.ini"},
    {121, L"libwinpthread-1.dll"}
};

HWND hWndProgress;
HWND hWndStatus;

void UpdateProgress(int percent, const wchar_t* statusText) {
    SendMessageW(hWndProgress, PBM_SETPOS, percent, 0);
    if (statusText) {
        SetWindowTextW(hWndStatus, statusText);
    }
}

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return fRet;
}

BOOL ProcessRunning(const wchar_t* name) {
    BOOL found = FALSE;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, name) == 0) { found = TRUE; break; }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return found;
}

void TerminateProcessByName(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) { TerminateProcess(h, 0); CloseHandle(h); }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

/* 最后手段：远程清除关键进程标记后再结束进程，避免蓝屏。
   只有在 stop.flag / 退出事件都没能停止后台进程（例如旧版本无响应）时才会用到。 */
typedef NTSTATUS (NTAPI *NtSetInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG);

void TerminateCriticalProcessByName(const wchar_t* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtSetInformationProcess_t setInfo = NULL;
    if (ntdll) setInfo = (NtSetInformationProcess_t)GetProcAddress(ntdll, "NtSetInformationProcess");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                HANDLE h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
                                       FALSE, pe.th32ProcessID);
                if (!h) h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) {
                    BOOL cleared = FALSE;
                    if (setInfo) {
                        ULONG zero = 0; /* ProcessBreakOnTermination = 29 */
                        NTSTATUS st = setInfo(h, 29, &zero, sizeof(zero));
                        cleared = (st >= 0); /* 只有成功清除关键标记才允许强杀，避免蓝屏 */
                    }
                    if (cleared) TerminateProcess(h, 0);
                    CloseHandle(h);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

/* 运行状态目录：仅管理员可写，普通用户无法通过写 stop.flag/config.ini 关闭防护 */
#define BD_STATE_DIR L"C:\\ProgramData\\BDProtect"
#define BD_STOP_FLAG BD_STATE_DIR L"\\stop.flag"

void EnsureStateDir() {
    SHCreateDirectoryExW(NULL, BD_STATE_DIR, NULL);

    /* 收紧 ACL：只有 SYSTEM 和 Administrators 能写，普通用户仅可读。
       否则任何人都能改写 config.ini 或放置 stop.flag 来关闭防护。 */
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
}

/* 创建 stop 标志文件：后台防护进程和控制中心识别到后会自行安全退出 */
void CreateStopFlag() {
    EnsureStateDir();
    HANDLE h = CreateFileW(BD_STOP_FLAG, GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, "1", 1, &w, NULL);
        CloseHandle(h);
    }
}

void DeleteStopFlag() {
    DeleteFileW(BD_STOP_FLAG);
}

/* 让关键进程（BDProtect）先清除标记再退出，避免蓝屏 */
void StopProtection() {
    /* 1. 先留下 stop 标志文件（新版程序会自行退出） */
    CreateStopFlag();

    /* 2. 同时向旧版本发送退出事件（旧版本不识别 stop.flag） */
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, L"Global\\BDProtect_ExitRequest");
    if (hEvent) {
        SetEvent(hEvent);
        for (int i = 0; i < 150 && ProcessRunning(L"BDProtect.exe"); i++) Sleep(100);
        CloseHandle(hEvent);
    }

    /* 旧版本没有版本文件，也不是关键进程，可以直接结束 */
    wchar_t verFile[MAX_PATH];
    swprintf(verFile, MAX_PATH, L"%s\\BDProtectVersion.txt", g_InstallDir);
    if (ProcessRunning(L"BDProtect.exe") &&
        GetFileAttributesW(verFile) == INVALID_FILE_ATTRIBUTES) {
        TerminateProcessByName(L"BDProtect.exe");
        Sleep(500);
    }

    /* 最后手段：15 秒内仍未退出，远程清除关键进程标记后再结束，避免蓝屏 */
    if (ProcessRunning(L"BDProtect.exe")) {
        TerminateCriticalProcessByName(L"BDProtect.exe");
        for (int i = 0; i < 20 && ProcessRunning(L"BDProtect.exe"); i++) Sleep(100);
    }

    /* 控制中心是非关键进程，可安全结束；先等它自行退出 */
    for (int i = 0; i < 30 && ProcessRunning(L"BDMain.exe"); i++) Sleep(100);
    if (ProcessRunning(L"BDMain.exe")) {
        TerminateProcessByName(L"BDMain.exe");
        Sleep(300);
    }

    /* 3. 已确认停止后删除标志，避免新启动的程序立刻又退出 */
    if (!ProcessRunning(L"BDProtect.exe") && !ProcessRunning(L"BDMain.exe"))
        DeleteStopFlag();
}

void ExtractFile(HMODULE hMod, int resId, const wchar_t* destPath) {
    HRSRC hRes = FindResourceW(hMod, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hRes) return;
    HGLOBAL hMem = LoadResource(hMod, hRes);
    DWORD size = SizeofResource(hMod, hRes);
    void* pData = LockResource(hMem);

    HANDLE hFile = CreateFileW(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, pData, size, &written, NULL);
        CloseHandle(hFile);
    }
}

void WriteTextIfMissing(const wchar_t* path, const char* text) {
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, text, (DWORD)strlen(text), &w, NULL);
        CloseHandle(h);
    }
}

void CreateShortcut(const wchar_t* targetExe, const wchar_t* shortcutPath, const wchar_t* iconPath, const wchar_t* workingDir) {
    IShellLinkW* psl;
    CoInitialize(NULL);
    if (SUCCEEDED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void**)&psl))) {
        IPersistFile* ppf;
        psl->lpVtbl->SetPath(psl, targetExe);
        psl->lpVtbl->SetIconLocation(psl, iconPath, 0);
        if (workingDir) psl->lpVtbl->SetWorkingDirectory(psl, workingDir);

        if (SUCCEEDED(psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void**)&ppf))) {
            ppf->lpVtbl->Save(ppf, shortcutPath, TRUE);
            ppf->lpVtbl->Release(ppf);
        }
        psl->lpVtbl->Release(psl);
    }
    CoUninitialize();
}

/* ============ 安装/缓存路径 ============ */

static void NormalizePath(wchar_t* p) {
    size_t n = wcslen(p);
    while (n > 3 && p[n-1] == L'\\') p[--n] = 0;
}

static void WritePathFile(const wchar_t* pathFile, const wchar_t* value) {
    FILE* f = _wfopen(pathFile, L"w, ccs=UTF-8");
    if (!f) return;
    fwprintf(f, L"%s\n", value);
    fclose(f);
}

static BOOL ReadPathFile(const wchar_t* pathFile, wchar_t* out, int cap) {
    FILE* f = _wfopen(pathFile, L"r, ccs=UTF-8");
    if (!f) return FALSE;
    if (!fgetws(out, cap, f)) { fclose(f); return FALSE; }
    fclose(f);
    size_t l = wcslen(out);
    while (l > 0 && (out[l-1] == L'\r' || out[l-1] == L'\n')) out[--l] = 0;
    if (l == 0) return FALSE;
    NormalizePath(out);
    return TRUE;
}

/* 更新模式：从注册表 InstallLocation 恢复上次安装位置 */
static void LoadSavedInstallPath(void) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, UNINSTALL_REG_KEY, 0,
                      KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH];
        DWORD type = 0, cb = sizeof(buf);
        if (RegQueryValueExW(hKey, L"InstallLocation", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS &&
            type == REG_SZ && cb > sizeof(wchar_t)) {
            NormalizePath(buf);
            if (GetFileAttributesW(buf) != INVALID_FILE_ATTRIBUTES) {
                wcsncpy(g_InstallDir, buf, MAX_PATH - 1);
                g_InstallDir[MAX_PATH - 1] = 0;
            }
        }
        RegCloseKey(hKey);
    }
}

/* 更新模式：沿用安装目录内已记录的缓存位置，避免升级后被打回 C:\BDtemp */
static void LoadSavedCachePath(void) {
    wchar_t cacheFile[MAX_PATH], buf[MAX_PATH];
    swprintf(cacheFile, MAX_PATH, L"%s\\%s", g_InstallDir, CACHE_PATH_NAME);
    if (ReadPathFile(cacheFile, buf, MAX_PATH) &&
        GetFileAttributesW(buf) != INVALID_FILE_ATTRIBUTES) {
        wcsncpy(g_CacheDir, buf, MAX_PATH - 1);
        g_CacheDir[MAX_PATH - 1] = 0;
    }
}

static void PersistPaths(void) {
    /* 缓存位置记录在安装目录内，程序启动时读取；
       安装位置本身由卸载注册表 InstallLocation 记录 */
    wchar_t cacheFile[MAX_PATH];
    swprintf(cacheFile, MAX_PATH, L"%s\\%s", g_InstallDir, CACHE_PATH_NAME);
    WritePathFile(cacheFile, g_CacheDir);

    /* 注册表备份：安装目录内文件被误删时，程序仍能找回用户的缓存位置 */
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XDH\\BDProtect", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY,
                        NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"CacheDir", 0, REG_SZ,
                       (const BYTE*)g_CacheDir,
                       (DWORD)((wcslen(g_CacheDir) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

/* 校验用户输入的目录路径：
   返回 NULL 表示合法；否则返回具体错误说明（静态缓冲）。
   合法要求：绝对路径（X:\...）、不是盘符根目录、盘符存在、
   不含非法字符、能创建、能写入。 */
static const wchar_t* ValidateDirPath(const wchar_t* dir)
{
    static wchar_t err[512];

    size_t n = wcslen(dir);
    if (n == 0)
        return L"路径不能为空。";
    if (n < 4)
        return L"路径不完整：必须形如 D:\\BDtemp。";
    if (n >= MAX_PATH - 32)
        return L"路径太长。";
    if (!((dir[0] >= L'A' && dir[0] <= L'Z') || (dir[0] >= L'a' && dir[0] <= L'z')) || dir[1] != L':' || dir[2] != L'\\')
        return L"必须是带盘符的绝对路径，例如 D:\\BDtemp。";

    wchar_t root[4] = { dir[0], L':', L'\\', 0 };
    if (GetDriveTypeW(root) == DRIVE_NO_ROOT_DIR) {
        swprintf(err, 512, L"磁盘 %s 不存在或未就绪。", root);
        return err;
    }

    for (const wchar_t* p = dir; *p; p++) {
        if (*p == L'<' || *p == L'>' || *p == L'"' || *p == L'|' || *p == L'?' || *p == L'*')
            return L"路径中含有非法字符（< > \" | ? *）。";
    }

    /* 不能直接装到盘符根，也不能是系统目录 */
    if (n == 3)
        return L"不能直接安装到磁盘根目录，请在其下指定一个文件夹，例如 D:\\BDApp。";
    if (_wcsnicmp(dir, L"C:\\Windows", 10) == 0)
        return L"不能安装到系统目录 C:\\Windows 下。";

    /* 试着创建并写入探针文件，确认真的可用 */
    int rc = SHCreateDirectoryExW(NULL, dir, NULL);
    if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS) {
        swprintf(err, 512, L"无法创建目录 %s（错误码 %d）。\n请检查路径是否写错，或换一个位置。", dir, rc);
        return err;
    }
    wchar_t probe[MAX_PATH];
    swprintf(probe, MAX_PATH, L"%s\\.bd_install_probe", dir);
    HANDLE h = CreateFileW(probe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        swprintf(err, 512, L"目录 %s 不可写入（错误码 %lu）。\n请换一个位置。", dir, GetLastError());
        return err;
    }
    CloseHandle(h);
    DeleteFileW(probe);
    return NULL;
}

/* 浏览文件夹，成功返回 TRUE 并把选中路径写入 out */
static BOOL BrowseFolder(HWND hwnd, const wchar_t* title, wchar_t* out, int cap) {
    BROWSEINFOW bi = {0};
    bi.hwndOwner = hwnd;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return FALSE;
    BOOL ok = SHGetPathFromIDListW(pidl, out);
    CoTaskMemFree(pidl);
    if (ok) NormalizePath(out);
    return ok;
}

/* 路径选择窗口过程 */
static LRESULT CALLBACK PathWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindowW(L"STATIC", L"安装位置（程序文件）：",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                15, 15, 300, 16, hwnd, NULL, NULL, NULL);
            CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_InstallDir,
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                15, 34, 330, 24, hwnd, (HMENU)ID_ED_INSTALL, NULL, NULL);
            CreateWindowW(L"BUTTON", L"浏览…",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                352, 34, 60, 24, hwnd, (HMENU)ID_BTN_BROWSE_INST, NULL, NULL);

            CreateWindowW(L"STATIC", L"缓存位置（病毒库/日志/备份，建议剩余空间较大的盘）：",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                15, 72, 380, 16, hwnd, NULL, NULL, NULL);
            CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_CacheDir,
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                15, 91, 330, 24, hwnd, (HMENU)ID_ED_CACHE, NULL, NULL);
            CreateWindowW(L"BUTTON", L"浏览…",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                352, 91, 60, 24, hwnd, (HMENU)ID_BTN_BROWSE_CACHE, NULL, NULL);

            CreateWindowW(L"BUTTON", L"开始安装",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,
                240, 135, 90, 28, hwnd, (HMENU)ID_BTN_OK, NULL, NULL);
            CreateWindowW(L"BUTTON", L"取消",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                342, 135, 70, 28, hwnd, (HMENU)ID_BTN_CANCEL, NULL, NULL);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            wchar_t buf[MAX_PATH];
            if (id == ID_BTN_BROWSE_INST) {
                buf[0] = 0;
                GetWindowTextW(GetDlgItem(hwnd, ID_ED_INSTALL), buf, MAX_PATH);
                if (BrowseFolder(hwnd, L"请选择安装位置", buf, MAX_PATH))
                    SetWindowTextW(GetDlgItem(hwnd, ID_ED_INSTALL), buf);
                return 0;
            }
            if (id == ID_BTN_BROWSE_CACHE) {
                buf[0] = 0;
                GetWindowTextW(GetDlgItem(hwnd, ID_ED_CACHE), buf, MAX_PATH);
                if (BrowseFolder(hwnd, L"请选择缓存位置", buf, MAX_PATH))
                    SetWindowTextW(GetDlgItem(hwnd, ID_ED_CACHE), buf);
                return 0;
            }
            if (id == ID_BTN_OK) {
                wchar_t inst[MAX_PATH], cache[MAX_PATH];
                GetWindowTextW(GetDlgItem(hwnd, ID_ED_INSTALL), inst, MAX_PATH);
                GetWindowTextW(GetDlgItem(hwnd, ID_ED_CACHE), cache, MAX_PATH);
                NormalizePath(inst);
                NormalizePath(cache);
                SetWindowTextW(GetDlgItem(hwnd, ID_ED_INSTALL), inst);
                SetWindowTextW(GetDlgItem(hwnd, ID_ED_CACHE), cache);

                const wchar_t* e1 = ValidateDirPath(inst);
                if (e1) {
                    MessageBoxW(hwnd, e1, L"安装位置无效", MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(hwnd, ID_ED_INSTALL));
                    return 0;
                }
                const wchar_t* e2 = ValidateDirPath(cache);
                if (e2) {
                    MessageBoxW(hwnd, e2, L"缓存位置无效", MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(hwnd, ID_ED_CACHE));
                    return 0;
                }
                /* 安装目录与缓存目录不能互相嵌套，避免互相删除 */
                if (_wcsnicmp(cache, inst, wcslen(inst)) == 0 ||
                    _wcsnicmp(inst, cache, wcslen(cache)) == 0) {
                    MessageBoxW(hwnd, L"安装位置和缓存位置不能相同或互相包含，请分开指定。",
                                L"路径冲突", MB_OK | MB_ICONWARNING);
                    return 0;
                }
                wcsncpy(g_InstallDir, inst, MAX_PATH - 1); g_InstallDir[MAX_PATH - 1] = 0;
                wcsncpy(g_CacheDir, cache, MAX_PATH - 1);  g_CacheDir[MAX_PATH - 1] = 0;
                g_PathChosen = TRUE;
                DestroyWindow(hwnd);
                return 0;
            }
            if (id == ID_BTN_CANCEL) {
                DestroyWindow(hwnd);
                return 0;
            }
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* 弹出安装/缓存位置选择窗口；用户点“开始安装”返回 TRUE */
static BOOL AskInstallPaths(HINSTANCE hInst, int show) {
    const wchar_t CLASS[] = L"PathSelectClass";
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = PathWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    RegisterClassW(&wc);

    int width = 435, height = 210;
    int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;
    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, CLASS, L"选择安装位置与缓存位置",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y, width, height, NULL, NULL, hInst, NULL);
    if (!hwnd) return FALSE;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return g_PathChosen;
}

void RegisterUninstall() {
    HKEY hKey;
    const wchar_t* keyPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\XDHProtectCenter";

    LONG res = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE,
                               KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL);

    if (res == ERROR_SUCCESS) {
        const wchar_t* displayName  = L"XDH防护控制中心";
        const wchar_t* publisher    = L"XDH Team";
        const wchar_t* displayVer   = L"1.0.4.0";
        wchar_t uninstallStr[MAX_PATH + 16], displayIcon[MAX_PATH], installLoc[MAX_PATH];
        swprintf(uninstallStr, MAX_PATH + 16, L"\"%s\\Uninstall.exe\"", g_InstallDir);
        swprintf(displayIcon, MAX_PATH, L"%s\\main.ico", g_InstallDir);
        wcsncpy(installLoc, g_InstallDir, MAX_PATH - 1); installLoc[MAX_PATH - 1] = 0;
        DWORD estimatedSize         = 10240;
        DWORD noModify              = 1;
        DWORD noRepair              = 1;

        RegSetValueExW(hKey, L"DisplayName", 0, REG_SZ, (const BYTE*)displayName, (DWORD)((wcslen(displayName)+1)*sizeof(wchar_t)));
        RegSetValueExW(hKey, L"Publisher", 0, REG_SZ, (const BYTE*)publisher, (DWORD)((wcslen(publisher)+1)*sizeof(wchar_t)));
        RegSetValueExW(hKey, L"DisplayVersion", 0, REG_SZ, (const BYTE*)displayVer, (DWORD)((wcslen(displayVer)+1)*sizeof(wchar_t)));
        RegSetValueExW(hKey, L"UninstallString", 0, REG_SZ, (const BYTE*)uninstallStr, (DWORD)((wcslen(uninstallStr)+1)*sizeof(wchar_t)));
        RegSetValueExW(hKey, L"DisplayIcon", 0, REG_SZ, (const BYTE*)displayIcon, (DWORD)((wcslen(displayIcon)+1)*sizeof(wchar_t)));
        RegSetValueExW(hKey, L"InstallLocation", 0, REG_SZ, (const BYTE*)installLoc, (DWORD)((wcslen(installLoc)+1)*sizeof(wchar_t)));

        RegSetValueExW(hKey, L"EstimatedSize", 0, REG_DWORD, (const BYTE*)&estimatedSize, sizeof(DWORD));
        RegSetValueExW(hKey, L"NoModify", 0, REG_DWORD, (const BYTE*)&noModify, sizeof(DWORD));
        RegSetValueExW(hKey, L"NoRepair", 0, REG_DWORD, (const BYTE*)&noRepair, sizeof(DWORD));

        RegCloseKey(hKey);
    }
}

/* 清空安装目录（更新前），但绝不触碰标志文件目录 */
void ClearInstallDir() {
    wchar_t search[MAX_PATH];
    swprintf(search, MAX_PATH, L"%s\\*.*", g_InstallDir);
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        /* 在线更新的数据和用户配置必须保留 */
        if (_wcsicmp(fd.cFileName, L"Wildlist.txt") == 0 ||
            _wcsicmp(fd.cFileName, L"WildlistVersion.txt") == 0 ||
            _wcsicmp(fd.cFileName, L"IPconfig.ini") == 0)
            continue;

        wchar_t full[MAX_PATH];
        swprintf(full, MAX_PATH, L"%s\\%s", g_InstallDir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        SetFileAttributesW(full, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(full);
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

void CreateGuardTask() {
    wchar_t cmd[2048];
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    /* 删除旧版本遗留的第二个任务，保证系统里只有一个 */
    wcscpy(cmd, L"schtasks /delete /tn \"BDAppProtect\" /f");
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    /* 路径含空格，/tr 需要再包一层引号，否则任务无法启动 */
    swprintf(cmd, 2048,
             L"schtasks /create /tn \"%s\" /tr \"\\\"%s\\BDProtect.exe\\\"\" /sc onlogon /rl highest /f",
             GUARD_TASK, g_InstallDir);
    si.cb = sizeof(si);
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    Sleep(300);
}

DWORD WINAPI InstallThread(LPVOID lpParam) {
    HMODULE hMod = GetModuleHandle(NULL);
    wchar_t destPath[MAX_PATH];

    UpdateProgress(3, g_UpdateMode ? L"正在停止旧版本程序..." : L"正在创建安装目录...");
    /* 安装/更新前都先停止旧进程：先留下 stop.flag，让程序自行安全退出 */
    if (g_UpdateMode || ProcessRunning(L"BDProtect.exe") || ProcessRunning(L"BDMain.exe")) {
        StopProtection();
    }
    if (ProcessRunning(L"BDProtect.exe")) {
        DeleteStopFlag();
        MessageBoxW(NULL,
                    L"后台防护进程未能安全退出，安装/更新已取消。\n请重启电脑后重新运行。",
                    L"操作失败", MB_OK | MB_ICONERROR);
        PostQuitMessage(0);
        return 0;
    }
    EnsureStateDir();
    ClearInstallDir();
    SHCreateDirectoryExW(NULL, g_InstallDir, NULL);
    Sleep(150);
    /* 记录安装/缓存位置，程序启动时会读取 */
    SHCreateDirectoryExW(NULL, g_CacheDir, NULL);
    PersistPaths();

    // 释放文件
    int numFiles = sizeof(files) / sizeof(files[0]);
    for (int i = 0; i < numFiles; i++) {
        swprintf(destPath, MAX_PATH, L"%s\\%s", g_InstallDir, files[i].filename);

        BOOL write = TRUE;
        /* 服务器地址由用户/运维维护，已存在时保留，避免升级后被覆盖 */
        if (files[i].id == 120 &&
            GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES) {
            write = FALSE;
        }
        if (write) ExtractFile(hMod, files[i].id, destPath);

        wchar_t msg[256];
        swprintf(msg, 256, g_UpdateMode ? L"正在更新: %s" : L"正在释放: %s", files[i].filename);

        int currentProgress = 5 + (int)((float)(i + 1) / numFiles * 60);
        UpdateProgress(currentProgress, msg);
        Sleep(40);
    }

    /* 校验核心文件是否真的释放成功，避免“装完根本运行不起来” */
    {
        wchar_t mainExe[MAX_PATH];
        swprintf(mainExe, MAX_PATH, L"%s\\BDMain.exe", g_InstallDir);
        if (GetFileAttributesW(mainExe) == INVALID_FILE_ATTRIBUTES) {
            DeleteStopFlag();
            MessageBoxW(NULL,
                        L"核心程序文件释放失败，安装未完成。\n\n请确认安装目录可写、路径正确，然后重新安装。",
                        L"安装失败", MB_OK | MB_ICONERROR);
            PostQuitMessage(0);
            return 0;
        }
    }

    /* 标志类文件：只在不存在时创建，永不覆盖 */
    UpdateProgress(68, L"正在初始化授权与试用状态...");
    SHCreateDirectoryExW(NULL, STORE_DIR, NULL);
    WriteTextIfMissing(RESTRICTED, "90\n");
    WriteTextIfMissing(USERUP, "0\n");
    Sleep(100);

    UpdateProgress(72, g_UpdateMode ? L"正在更新桌面快捷方式..." : L"正在创建桌面快捷方式...");
    wchar_t desktopPath[MAX_PATH], lnkPath[MAX_PATH], targetExe[MAX_PATH], iconPath[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath);
    swprintf(lnkPath, MAX_PATH, L"%s\\XDH防护控制中心.lnk", desktopPath);
    swprintf(targetExe, MAX_PATH, L"%s\\BDMain.exe", g_InstallDir);
    swprintf(iconPath, MAX_PATH, L"%s\\main.ico", g_InstallDir);
    CreateShortcut(targetExe, lnkPath, iconPath, g_InstallDir);
    Sleep(200);

    UpdateProgress(80, L"正在注册卸载信息...");
    RegisterUninstall();
    Sleep(200);

    UpdateProgress(90, L"正在配置开机启动计划任务...");
    CreateGuardTask();

    UpdateProgress(100, g_UpdateMode ? L"更新完成，正在启动..." : L"安装完成，正在启动...");

    /* 启动前确保标志已清除，否则新程序会立即退出 */
    DeleteStopFlag();
    ShellExecuteW(NULL, L"open", targetExe, NULL, g_InstallDir, SW_SHOWNORMAL);

    PostQuitMessage(0);
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            hWndStatus = CreateWindowW(L"STATIC", g_UpdateMode ? L"正在初始化更新..." : L"正在初始化安装...",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                15, 15, 320, 20, hwnd, (HMENU)ID_STATUS, NULL, NULL);

            hWndProgress = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                15, 40, 320, 25, hwnd, (HMENU)ID_PROGRESS, NULL, NULL);

            SendMessageW(hWndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
            SendMessageW(hWndProgress, PBM_SETPOS, 0, 0);

            CreateThread(NULL, 0, InstallThread, hwnd, 0, NULL);
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show) {
    SetConsoleOutputCP(GetACP());   /* 强制使用 ANSI 代码页 */

    // 1. 检查提权
    if (!IsElevated()) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        ShellExecuteW(NULL, L"runas", path, cmd, NULL, SW_SHOWNORMAL);
        return 0;
    }

    // 已有旧版本，或由自动升级程序带 /UPDATE 调用，则进入无弹窗更新模式
    g_UpdateMode = (wcsstr(cmd, L"/UPDATE") != NULL);

    // 恢复上次安装位置（若存在），用于判断是否为更新
    LoadSavedInstallPath();

    if (!g_UpdateMode) {
        wchar_t oldMain[MAX_PATH];
        swprintf(oldMain, MAX_PATH, L"%s\\BDMain.exe", g_InstallDir);
        g_UpdateMode = (GetFileAttributesW(oldMain) != INVALID_FILE_ATTRIBUTES);
    }

    if (!g_UpdateMode) {
        // 2. 弹出“制作人声明”弹窗
        MessageBoxW(NULL, L"软件由 @徐小小的电子制作 制作", L"制作人声明", MB_OK | MB_ICONINFORMATION);

        // 3. 弹出“软件介绍”弹窗，带确定和取消
        int introResult = MessageBoxW(NULL, L"此软件可无需网络对系统实施保护", L"软件介绍", MB_OKCANCEL | MB_ICONQUESTION);
        if (introResult != IDOK) {
            return 0;
        }

        // 4. 弹出安装/缓存位置选择窗口（默认 C:\Program Files\BDApp 与 C:\BDtemp）
        if (!AskInstallPaths(hInst, show)) {
            return 0;   /* 用户取消 */
        }
    } else {
        // 更新模式：沿用已记录的缓存位置，不要把用户选的 D 盘打回 C 盘
        LoadSavedCachePath();
    }

    // 4. 初始化通用控件库
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    // 5. 注册并创建进度条窗口
    const wchar_t CLASS[] = L"InstallerClass";
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    RegisterClassW(&wc);

    int width = 370, height = 120;
    int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, CLASS, g_UpdateMode ? L"更新程序" : L"安装程序",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y, width, height, NULL, NULL, hInst, NULL);

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
