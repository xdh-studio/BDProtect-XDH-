#include "bd_common.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <netfw.h>

#define WHITE_FILE bd_cache_path(L"net_white.txt")
#define BLACK_FILE bd_cache_path(L"net_black.txt")

/* 本软件自身和系统核心进程永远不拦截，避免出现“杀毒软件拦自己”的问题 */
static BOOL is_trusted_net_process(const wchar_t* path)
{
    if (bd_is_own_app_path(path)) return TRUE;

    const wchar_t* base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    static const wchar_t* trusted[] = {
        L"System", L"Idle", L"csrss.exe", L"smss.exe", L"wininit.exe",
        L"winlogon.exe", L"services.exe", L"lsass.exe", L"svchost.exe",
        L"dllhost.exe", L"taskhostw.exe", L"RuntimeBroker.exe", L"explorer.exe"
    };
    for (int i = 0; i < (int)(sizeof(trusted) / sizeof(trusted[0])); i++)
        if (_wcsicmp(base, trusted[i]) == 0) return TRUE;
    return FALSE;
}

static BOOL check_list(const wchar_t* file, const wchar_t* path) {
    FILE* f = _wfopen(file, L"r, ccs=UTF-8"); if (!f) return FALSE;
    wchar_t line[MAX_PATH]; BOOL ok = FALSE;
    while (fgetws(line, MAX_PATH, f)) {
        /* 行尾的 \r\n 直接去掉（UCRT 的 wcstok 需要上下文参数，改用简单裁剪） */
        size_t n = wcslen(line);
        while (n > 0 && (line[n-1] == L'\r' || line[n-1] == L'\n')) line[--n] = 0;
        if (n > 0 && _wcsicmp(line, path) == 0) { ok = TRUE; break; }
    }
    fclose(f); return ok;
}

static void add_list(const wchar_t* file, const wchar_t* path) {
    FILE* f = _wfopen(file, L"a, ccs=UTF-8");
    if (f) { fwprintf(f, L"%s\n", path); fclose(f); }
}

static void image_hijack(const wchar_t* path) {
    wchar_t* exeName = wcsrchr(path, L'\\');
    if (!exeName) return;
    exeName++; 
    
    wchar_t regPath[512];
    swprintf(regPath, 512, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", exeName);
    
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        const wchar_t* dummy = L"svchost.exe"; 
        RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)dummy, (wcslen(dummy)+1)*sizeof(wchar_t));
        RegCloseKey(hKey);
        bd_log(L"[Net] 已执行映像劫持: %s", exeName);
    }
}

static void kill_tcp_conn(DWORD pid) {
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        PMIB_TCPTABLE_OWNER_PID table = malloc(size);
        if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                if (table->table[i].dwOwningPid == pid) {
                    MIB_TCPROW tcpRow;
                    tcpRow.dwState = MIB_TCP_STATE_DELETE_TCB;
                    tcpRow.dwLocalAddr = table->table[i].dwLocalAddr;
                    tcpRow.dwLocalPort = table->table[i].dwLocalPort;
                    tcpRow.dwRemoteAddr = table->table[i].dwRemoteAddr;
                    tcpRow.dwRemotePort = table->table[i].dwRemotePort;
                    SetTcpEntry(&tcpRow);
                }
            }
        }
        free(table);
    }
}

static DWORD WINAPI net_thread(LPVOID p) {
    DWORD alerted[512] = {0};
    while(1) {
        if (g_bPaused || !g_bNetPrt) { Sleep(1000); continue; }
        DWORD size = 0;
        if(GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
            PMIB_TCPTABLE_OWNER_PID table = malloc(size);
            if(GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for(DWORD i=0; i<table->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID row = table->table[i];
                    
                    // 修复：将 MIB_TCP_STATE_ESTABLISHED 替换为 MinGW 支持的 MIB_TCP_STATE_ESTAB
                    if(row.dwState == MIB_TCP_STATE_ESTAB && row.dwRemotePort != 0 && row.dwOwningPid > 4) {
                        
                        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.dwOwningPid);
                        if(h) {
                            WCHAR path[MAX_PATH]; DWORD s = MAX_PATH;
                            if(QueryFullProcessImageNameW(h, 0, path, &s) &&
                               !is_trusted_net_process(path)) {
                                if (check_list(BLACK_FILE, path)) {
                                    kill_tcp_conn(row.dwOwningPid);
                                } else if (!check_list(WHITE_FILE, path)) {
                                    BOOL a = FALSE; for(int j=0; j<512; j++) if(alerted[j]==row.dwOwningPid) { a=TRUE; break; }
                                    if(!a) {
                                        for(int j=0; j<512; j++) if(alerted[j]==0) { alerted[j]=row.dwOwningPid; break; }

                                        int r = bd_show_popup(L"网络防护拦截", path, 3, 0);
                                        /* 启动静默期内不记录、不放行、也不拦截；
                                           撤销已登记状态，静默期结束后该进程会再次提示 */
                                        if (r == BD_POPUP_SUPPRESSED) {
                                            for (int j = 0; j < 512; j++)
                                                if (alerted[j] == row.dwOwningPid) alerted[j] = 0;
                                            CloseHandle(h);
                                            continue;
                                        }
                                        bd_record_add(L"网络防护", path,
                                                      r == IDYES ? L"同意联网" : (r == IDIGNORE ? L"禁用程序" : L"禁止联网"));

                                        if(r == IDYES) {
                                            add_list(WHITE_FILE, path);
                                        } else if (r == IDNO) {
                                            add_list(BLACK_FILE, path);
                                            kill_tcp_conn(row.dwOwningPid);
                                        } else if (r == IDIGNORE) {
                                            add_list(BLACK_FILE, path);
                                            kill_tcp_conn(row.dwOwningPid);
                                            image_hijack(path);
                                        }
                                    }
                                }
                            }
                            CloseHandle(h);
                        }
                    }
                }
            }
            free(table);
        }
        Sleep(1500);
    }
    return 0;
}

void bd_net_monitor_start(void) { CreateThread(NULL, 0, net_thread, NULL, 0, NULL); }