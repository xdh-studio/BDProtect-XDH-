#include "bd_common.h"

typedef VOID (WINAPI *RtlSetProcessIsCritical_t)(BOOLEAN, PBOOLEAN, BOOLEAN);
static RtlSetProcessIsCritical_t g_setCritical = NULL;

/* 关键进程自身崩溃同样会导致蓝屏。崩溃时先清除关键标记再退出，
   避免一次普通的内存错误把整台机器拖下水。 */
static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
{
    DWORD code = 0;
    if (ep && ep->ExceptionRecord) code = ep->ExceptionRecord->ExceptionCode;
    OutputDebugStringW(L"[BDProtect] unhandled exception, clearing critical flag\n");
    bd_log(L"[Protect] 未处理异常 0x%08lx，清除关键进程标记后退出", (unsigned long)code);
    bd_cleanup_critical();
    return EXCEPTION_EXECUTE_HANDLER;
}

void bd_install_crash_guard(void)
{
    SetUnhandledExceptionFilter(CrashFilter);
}

void bd_cleanup_critical(void)
{
    if (!g_setCritical) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            g_setCritical = (RtlSetProcessIsCritical_t)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
    }
    if (g_setCritical)
        g_setCritical(FALSE, NULL, FALSE);
}

void bd_start_self_guard(void)
{
    // 启用核心特权，防止被轻易提权或操纵
    bd_enable_core_privileges();
    
    // 提升为关键进程，任何外部程序杀此进程都会导致系统直接蓝屏
    if (!g_setCritical) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            g_setCritical = (RtlSetProcessIsCritical_t)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
    }
    
    if (g_setCritical) {
        g_setCritical(TRUE, NULL, FALSE);
        bd_log(L"[Protect] 已设为关键进程 (Critical Process)");
    }
}