#include "bd_common.h"
#include <tlhelp32.h>

/* 进程注入防护（用户态启发式）
 *
 * 思路：持续检查关键系统进程中的线程起始地址。
 * 正常线程的起始地址一定落在该进程已加载的某个模块（exe/dll）映像范围内；
 * 由 CreateRemoteThread / 内存注入产生的线程，其起始地址通常落在“无主”内存，
 * 不在任何模块范围内。发现后立即终止该线程并提示。
 */

typedef NTSTATUS (NTAPI *NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static const wchar_t* g_protected_procs[] = {
    L"winlogon.exe",
    L"lsass.exe",
    L"services.exe",
    L"smss.exe",
    L"svchost.exe",
    L"dism.exe"
};
#define PROTECTED_COUNT (int)(sizeof(g_protected_procs)/sizeof(g_protected_procs[0]))

typedef struct {
    ULONG_PTR base;
    ULONG_PTR size;
} MOD_RANGE;

#define MAX_MODS 512
static NtQueryInformationThread_t g_NtQIT = NULL;

static BOOL is_protected_proc(const wchar_t* name)
{
    for (int i = 0; i < PROTECTED_COUNT; i++)
        if (_wcsicmp(name, g_protected_procs[i]) == 0) return TRUE;
    return FALSE;
}

static int load_module_ranges(DWORD pid, MOD_RANGE* ranges, int cap)
{
    int n = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (n >= cap) break;
            ranges[n].base = (ULONG_PTR)me.modBaseAddr;
            ranges[n].size = me.modBaseSize;
            n++;
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return n;
}

static BOOL in_any_module(ULONG_PTR addr, const MOD_RANGE* ranges, int n)
{
    for (int i = 0; i < n; i++) {
        if (addr >= ranges[i].base && addr < ranges[i].base + ranges[i].size)
            return TRUE;
    }
    return FALSE;
}

typedef struct {
    DWORD pid;
    wchar_t name[64];
} SUSPECT;

static BOOL already_alerted(SUSPECT* list, int n, DWORD pid)
{
    for (int i = 0; i < n; i++) if (list[i].pid == pid) return TRUE;
    return FALSE;
}

static void scan_process(DWORD pid, const wchar_t* procName, SUSPECT* alerted, int* alertedCount)
{
    MOD_RANGE ranges[MAX_MODS];
    int modCount = load_module_ranges(pid, ranges, MAX_MODS);
    if (modCount <= 0) return;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return; }

    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            /* ThreadQuerySetWin32StartAddress 需要 THREAD_QUERY_INFORMATION；
               在 Win10/11 上只用 THREAD_QUERY_LIMITED_INFORMATION 会返回
               STATUS_ACCESS_DENIED(0xC0000022)，等于所有线程都查不到起始地址，
               注入防护会完全失效。所以先要完整查询权限，失败再退回受限权限
               （PPL 保护进程只能用受限权限，此时查不到就跳过）。 */
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                                        FALSE, te.th32ThreadID);
            if (!hThread)
                hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME,
                                     FALSE, te.th32ThreadID);
            if (!hThread) continue;

            ULONG_PTR start = 0;
            ULONG retLen = 0;
            NTSTATUS st = 0;
            if (g_NtQIT) st = g_NtQIT(hThread, 9 /*ThreadQuerySetWin32StartAddress*/,
                                      &start, sizeof(start), &retLen);

            if (st == 0 && start > 0x10000 && !in_any_module(start, ranges, modCount)) {
                /* 起始地址不在任何已加载模块内。再用 VirtualQueryEx 复核：
                   MEM_IMAGE / MEM_MAPPED 属于未枚举到的模块或共享映射，不算注入；
                   只处理“私有且可执行”的内存，进一步要求 RWX，避免误伤 JIT 线程。 */
                MEMORY_BASIC_INFORMATION mbi;
                BOOL injected = FALSE;
                if (VirtualQueryEx(hProc, (LPCVOID)start, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                        (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                        injected = TRUE;
                }
                if (!injected) { CloseHandle(hThread); continue; }

                /* 挂起而不是终止：TerminateThread 会遗留锁，可能让 lsass/winlogon
                   等关键进程死锁甚至蓝屏；挂起可达到同样拦截效果且可逆。 */
                BOOL newly = !already_alerted(alerted, *alertedCount, pid);
                SuspendThread(hThread);

                if (newly && *alertedCount < 64) {
                    alerted[*alertedCount].pid = pid;
                    wcsncpy(alerted[*alertedCount].name, procName, 63);
                    alerted[*alertedCount].name[63] = 0;
                    (*alertedCount)++;

                    bd_log(L"[Inject] 已拦截对 %s (PID %lu) 的线程注入，起始地址 0x%p",
                           procName, (unsigned long)pid, (void*)start);
                    bd_record_add(L"进程注入防护", procName, L"已拦截");

                    wchar_t text[512];
                    swprintf(text, 512,
                             L"已拦截一次进程注入攻击！\n\n目标进程：%s\n攻击线程已被挂起，系统安全。",
                             procName);
                    bd_show_popup(L"进程注入防护", text, 4, 3);
                }
            }
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    CloseHandle(hProc);
}

static DWORD WINAPI inject_thread(LPVOID p)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) g_NtQIT = (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");

    SUSPECT alerted[64];
    int alertedCount = 0;

    while (1) {
        if (g_bPaused || !g_bInjectPrt) { Sleep(1000); continue; }
        if (!g_NtQIT) {
            HMODULE nt = GetModuleHandleW(L"ntdll.dll");
            if (nt) g_NtQIT = (NtQueryInformationThread_t)GetProcAddress(nt, "NtQueryInformationThread");
        }

        /* 每轮重新扫描；已告警的 PID 在 60 秒后允许再次告警 */
        if (alertedCount >= 64) alertedCount = 0;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (is_protected_proc(pe.szExeFile)) {
                        scan_process(pe.th32ProcessID, pe.szExeFile, alerted, &alertedCount);
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        Sleep(2500);
    }
    return 0;
}

void bd_inject_monitor_start(void)
{
    CreateThread(NULL, 0, inject_thread, NULL, 0, NULL);
}
