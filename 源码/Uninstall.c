#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h> // 用于获取桌面路径

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

#define ID_BTN_UNINSTALL 1001

// 检查当前是否拥有管理员权限
BOOL IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    return isAdmin;
}

BOOL IsProcessRunning(const wchar_t* procName);
void StopMainCenter();

/* 最后手段：远程清除关键进程标记后再结束，避免蓝屏 */
typedef NTSTATUS (NTAPI *NtSetInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG);

void TerminateCriticalProcessByName(const wchar_t* procName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtSetInformationProcess_t setInfo = NULL;
    if (ntdll) setInfo = (NtSetInformationProcess_t)GetProcAddress(ntdll, "NtSetInformationProcess");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName) == 0) {
                HANDLE h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
                                       FALSE, pe.th32ProcessID);
                if (!h) h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) {
                    BOOL cleared = FALSE;
                    if (setInfo) {
                        ULONG zero = 0;
                        NTSTATUS st = setInfo(h, 29, &zero, sizeof(zero));
                        cleared = (st >= 0); /* 成功清除关键标记后才允许强杀，避免蓝屏 */
                    }
                    if (cleared) TerminateProcess(h, 0);
                    CloseHandle(h);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

// 卸载/更新前留下 stop 标志文件，后台防护进程与控制中心识别后自行安全退出
#define BD_STATE_DIR L"C:\\ProgramData\\BDProtect"
#define BD_STOP_FLAG BD_STATE_DIR L"\\stop.flag"

void CreateStopFlag() {
    CreateDirectoryW(BD_STATE_DIR, NULL);
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

// 通知后台防护进程安全退出（清除关键进程标记，避免蓝屏）
void RequestProtectionExit() {
    // 1. 先留下 stop 标志文件：新版程序会自行退出
    CreateStopFlag();

    // 2. 兼容旧版本：发送退出事件
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, L"Global\\BDProtect_ExitRequest");
    if (hEvent) {
        SetEvent(hEvent);
        // 最多等待 15 秒，让所有实例自行退出
        for (int i = 0; i < 150 && IsProcessRunning(L"BDProtect.exe"); i++) Sleep(100);
        CloseHandle(hEvent);
    }

    // 旧版本程序不是关键进程，也不监听停止标志/事件，可直接结束
    if (IsProcessRunning(L"BDProtect.exe") &&
        GetFileAttributesW(L"C:\\Program Files\\BDApp\\BDProtectVersion.txt") == INVALID_FILE_ATTRIBUTES) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"BDProtect.exe") == 0) {
                        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }

    // 15 秒后仍未退出：远程清除关键标记再结束，避免蓝屏并保证卸载成功
    if (IsProcessRunning(L"BDProtect.exe")) {
        TerminateCriticalProcessByName(L"BDProtect.exe");
        for (int i = 0; i < 20 && IsProcessRunning(L"BDProtect.exe"); i++) Sleep(100);
    }

    // 控制中心识别 stop.flag 后也会自行退出
    for (int i = 0; i < 50 && IsProcessRunning(L"BDMain.exe"); i++) Sleep(100);
    StopMainCenter();

    // 3. 进程都退出后删除标志，避免下次启动立刻退出
    if (!IsProcessRunning(L"BDProtect.exe") && !IsProcessRunning(L"BDMain.exe"))
        DeleteStopFlag();
}

// 结束主控中心（非关键进程，可安全结束）
void StopMainCenter() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"BDMain.exe") == 0) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) { TerminateProcess(h, 0); CloseHandle(h); }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

// 检查进程是否在运行
BOOL IsProcessRunning(const wchar_t* procName) {
    BOOL found = FALSE;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, procName) == 0) {
                    found = TRUE; break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return found;
}

// 递归删除整个文件夹
void DeleteDirectory(const wchar_t* dirPath) {
    wchar_t search[MAX_PATH];
    swprintf(search, MAX_PATH, L"%s\\*.*", dirPath);
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            wchar_t filePath[MAX_PATH];
            swprintf(filePath, MAX_PATH, L"%s\\%s", dirPath, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                DeleteDirectory(filePath);
            } else {
                SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(filePath);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    SetFileAttributesW(dirPath, FILE_ATTRIBUTE_NORMAL);   /* 只读目录会导致删除失败 */
    RemoveDirectoryW(dirPath);
}

// 读取安装目录内记录的缓存位置（BDCachePath.txt）
static BOOL ReadCacheDirRecord(const wchar_t* cacheFile, wchar_t* out, int cap) {
    FILE* f = _wfopen(cacheFile, L"r, ccs=UTF-8");
    if (!f) return FALSE;
    if (!fgetws(out, cap, f)) { fclose(f); return FALSE; }
    fclose(f);

    size_t l = wcslen(out);
    while (l > 0 && (out[l-1] == L'\r' || out[l-1] == L'\n' || out[l-1] == L' ' || out[l-1] == L'\t'))
        out[--l] = 0;
    // 去掉 BOM（记录文件曾经以不同编码写过）
    if (out[0] == 0xFEFF) memmove(out, out + 1, wcslen(out) * sizeof(wchar_t));
    // 去掉末尾反斜杠
    l = wcslen(out);
    while (l > 3 && out[l-1] == L'\\') out[--l] = 0;
    return l >= 4 && out[1] == L':';
}

// 读取注册表里的缓存位置备份
static BOOL ReadCacheDirRegistry(wchar_t* out, int cap) {
    DWORD cb = (DWORD)(cap * sizeof(wchar_t));
    DWORD type = 0;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XDH\\BDProtect", L"CacheDir",
                     RRF_RT_REG_SZ, &type, out, &cb) != ERROR_SUCCESS)
        return FALSE;
    size_t l = wcslen(out);
    while (l > 3 && out[l-1] == L'\\') out[--l] = 0;
    return l >= 4 && out[1] == L':';
}

// 缓存位置可能同时记录在安装目录文件、注册表里；逐个都删，避免残留
void CleanCacheDirectories() {
    wchar_t self[MAX_PATH] = {0}, cacheFile[MAX_PATH] = {0};
    wchar_t paths[4][MAX_PATH];
    int n = 0;

    GetModuleFileNameW(NULL, self, MAX_PATH);
    wchar_t* slash = wcsrchr(self, L'\\');
    if (slash) {
        /* 早期版本的安装程序格式串写错，会在安装目录的上一级留下一个
           “<安装目录名>BDCachePath.txt”的垃圾文件，这里顺手清掉 */
        wchar_t base[MAX_PATH];
        wcsncpy(base, slash + 1, MAX_PATH - 1);
        base[MAX_PATH - 1] = 0;
        *slash = 0;
        swprintf(cacheFile, MAX_PATH, L"%s\\%s%s", self, base, L"BDCachePath.txt");
        DeleteFileW(cacheFile);

        swprintf(cacheFile, MAX_PATH, L"%s\\BDCachePath.txt", self);
        if (ReadCacheDirRecord(cacheFile, paths[n], MAX_PATH)) n++;
    }
    if (ReadCacheDirRegistry(paths[n], MAX_PATH)) n++;
    // 兼容旧版本以及“记录文件丢失”的情况
    if (n < 4) wcscpy(paths[n++], L"C:\\BDtemp");

    for (int i = 0; i < n; i++) {
        if (!paths[i][0]) continue;
        BOOL dup = FALSE;
        for (int j = 0; j < i; j++)
            if (_wcsicmp(paths[i], paths[j]) == 0) { dup = TRUE; break; }
        if (dup) continue;

        // 安全阀：绝不删除盘符根目录或系统目录
        size_t len = wcslen(paths[i]);
        if (len <= 3 || _wcsicmp(paths[i], L"C:\\Windows") == 0 ||
            _wcsicmp(paths[i], L"C:\\Program Files") == 0 ||
            _wcsicmp(paths[i], L"C:\\Program Files (x86)") == 0) {
            continue;
        }
        if (GetFileAttributesW(paths[i]) == INVALID_FILE_ATTRIBUTES) continue;

        DeleteDirectory(paths[i]);
        if (GetFileAttributesW(paths[i]) != INVALID_FILE_ATTRIBUTES) {
            Sleep(300);        /* 可能还有句柄未释放，再试一次 */
            DeleteDirectory(paths[i]);
        }
    }

    // 删除注册表备份，避免重装后又被指回已删除的目录
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\XDH\\BDProtect");
}

// 核心：清空当前程序所在目录的所有文件
void CleanCurrentDirectory() {
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    
    wchar_t* slash = wcsrchr(selfPath, L'\\');
    if (!slash) return;
    *slash = 0; 
    
    if (wcslen(selfPath) <= 3 || 
        _wcsicmp(selfPath, L"C:\\Windows") == 0 || 
        _wcsicmp(selfPath, L"C:\\Windows\\System32") == 0 ||
        _wcsicmp(selfPath, L"C:\\Program Files") == 0 ||
        _wcsicmp(selfPath, L"C:\\Program Files (x86)") == 0 ||
        wcsstr(selfPath, L"\\Windows\\System32") != NULL) {
        MessageBoxW(NULL, L"检测到卸载程序位于受保护的系统目录中！\n为了防止误删系统文件，已停止清理当前目录。", L"安全拦截", MB_ICONERROR);
        return;
    }

    wchar_t search[MAX_PATH];
    swprintf(search, MAX_PATH, L"%s\\*.*", selfPath);
    
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            if (_wcsicmp(fd.cFileName, L"Uninstall.exe") == 0) continue; // 跳过自己
            
            wchar_t filePath[MAX_PATH];
            swprintf(filePath, MAX_PATH, L"%s\\%s", selfPath, fd.cFileName);
            
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                DeleteDirectory(filePath);
            } else {
                SetFileAttributesW(filePath, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(filePath);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

// 【新增】清理控制面板/设置中的卸载条目
void RemoveUninstallRegistry() {
    HKEY hKey;
    const wchar_t* keyPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    // 兼容 64 位系统视图
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegDeleteKeyW(hKey, L"XDHProtectCenter");
        RegCloseKey(hKey);
    }
    // 兼容 32 位系统视图 (保险起见)
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_ALL_ACCESS | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
        RegDeleteKeyW(hKey, L"XDHProtectCenter");
        RegCloseKey(hKey);
    }
}

// 【新增】清理桌面快捷方式
void RemoveDesktopShortcuts() {
    wchar_t desktopPath[MAX_PATH];
    wchar_t lnkPath[MAX_PATH];
    
    // 公共桌面路径
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, desktopPath))) {
        swprintf(lnkPath, MAX_PATH, L"%s\\XDH防护控制中心.lnk", desktopPath);
        DeleteFileW(lnkPath);
    }
    // 当前用户桌面路径
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath))) {
        swprintf(lnkPath, MAX_PATH, L"%s\\XDH防护控制中心.lnk", desktopPath);
        DeleteFileW(lnkPath);
    }
}

// 清理映像劫持
void CleanIFEO() {
    HKEY hKey;
    const wchar_t* ifeoPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeoPath, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t subKeyName[256];
        DWORD index = 0;
        DWORD size = 256;
        while (RegEnumKeyExW(hKey, index, subKeyName, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSub;
            if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hSub) == ERROR_SUCCESS) {
                wchar_t debugger[256];
                DWORD dwSize = sizeof(debugger);
                if (RegQueryValueExW(hSub, L"Debugger", NULL, NULL, (LPBYTE)debugger, &dwSize) == ERROR_SUCCESS) {
                    if (wcsstr(debugger, L"svchost.exe") != NULL ||
                        wcsstr(debugger, L"BDProtect.exe") != NULL) {
                        RegCloseKey(hSub);
                        RegDeleteKeyW(hKey, subKeyName);
                        index = 0; size = 256; 
                        continue;
                    }
                }
                RegCloseKey(hSub);
            }
            index++; size = 256;
        }
        RegCloseKey(hKey);
    }
}

// 清理防火墙规则
void CleanFirewall() {
    WinExec("cmd /c \"for /f \\\"tokens=2 delims=:\\\" %a in ('netsh advfirewall firewall show rule name=all ^| findstr /i \\\"BD_Block_\\\"') do netsh advfirewall firewall delete rule name=%a\"", SW_HIDE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindowW(L"STATIC", L"卸载程序", WS_CHILD|WS_VISIBLE|SS_CENTER, 20, 20, 340, 30, hwnd, NULL, NULL, NULL);
            CreateWindowW(L"STATIC", L"卸载程序会自动安全停止后台防护进程。",
                          WS_CHILD|WS_VISIBLE|SS_CENTER, 20, 60, 340, 80, hwnd, NULL, NULL, NULL);
            CreateWindowW(L"BUTTON", L"一键卸载", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 130, 150, 120, 40, hwnd, (HMENU)ID_BTN_UNINSTALL, NULL, NULL);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(w) == ID_BTN_UNINSTALL) {
                int confirm = MessageBoxW(hwnd, L"确定要彻底卸载 XDH防护系统 并清除所在目录的所有文件吗？", L"确认卸载", MB_YESNO | MB_ICONWARNING);
                if (confirm == IDYES) {
                    // 0. 安全停止后台防护进程（不能强杀：关键进程会导致蓝屏）
                    RequestProtectionExit();
                    if (IsProcessRunning(L"BDProtect.exe")) {
                        DeleteStopFlag(); /* 卸载取消：恢复正常保护状态 */
                        MessageBoxW(hwnd, L"后台防护进程未能安全退出，卸载已取消。\n请重启电脑后重试。", L"无法卸载", MB_ICONERROR);
                        return 0;
                    }
                    StopMainCenter();

                    // 1. 删除注册表中的“安装的应用”条目
                    RemoveUninstallRegistry();
                    
                    // 2. 删除桌面快捷方式
                    RemoveDesktopShortcuts();
                    
                    // 3. 删除计划任务 (匹配安装程序设置的任务名 BDAppProtect)
                    WinExec("schtasks /delete /tn \"BDAppProtect\" /f", SW_HIDE);
                    // 兼容清理一下老版本可能产生的任务
                    WinExec("schtasks /delete /tn \"BDProtect_System_Guard\" /f", SW_HIDE);
                    
                    // 4. 清理防火墙规则
                    CleanFirewall();
                    
                    // 5. 解除映像劫持
                    CleanIFEO();
                    
                    // 6. 清理缓存目录（记录文件 + 注册表备份 + 默认位置，全部清掉）
                    CleanCacheDirectories();
                    DeleteDirectory(BD_STATE_DIR);
                    /* 注意：C:\ProgramData\Microsoft\Windows\Caches\BDProtectData
                       里是 Restricted.txt / UserUp.txt 等标志文件，按设计
                       卸载和更新都不得删除，重装后试用状态/解锁状态仍要保留。 */
                    
                    // 7. 清空当前程序所在目录
                    CleanCurrentDirectory();
                    
                    // 8. 借助系统 cmd 延时删除自己
                    wchar_t selfPath[MAX_PATH];
                    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
                    wchar_t cmd[1024];
                    swprintf(cmd, 1024, L"cmd.exe /c ping 127.0.0.1 -n 2 > nul & del /f /q \"%s\"", selfPath);
                    
                    STARTUPINFO si = { sizeof(si) }; 
                    si.dwFlags = STARTF_USESHOWWINDOW; 
                    si.wShowWindow = SW_HIDE;
                    PROCESS_INFORMATION pi;
                    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                    
                    MessageBoxW(hwnd, L"感谢使用，再见！", L"卸载成功", MB_ICONINFORMATION);
                    PostQuitMessage(0);
                }
            }
            return 0;
        }
        case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE h, HINSTANCE p, LPWSTR cmdLine, int show) {
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
                MessageBoxW(NULL, L"请求管理员权限被拒绝，无法执行卸载程序。", L"权限不足", MB_ICONERROR);
                return 0;
            }
        }
    }

    WNDCLASSEXW wc = {0}; 
    wc.cbSize = sizeof(wc); 
    wc.lpfnWndProc = WndProc;
    wc.hInstance = h; 
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1); 
    wc.lpszClassName = L"UninstallCls";
    wc.hIcon = LoadIconW(NULL, IDI_WARNING);
    RegisterClassExW(&wc);
    
    HWND hwnd = CreateWindowExW(0, L"UninstallCls", L"XDH防护系统卸载程序", 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 260, NULL, NULL, h, NULL);
    
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hwnd, NULL, (screenW - 400)/2, (screenH - 260)/2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(hwnd, show);
    MSG msg; while(GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}