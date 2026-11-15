#include "bd_common.h"

static BOOL mbr_read(BYTE *buf) {
    HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD bytes = 0;
    BOOL ok = ReadFile(h, buf, 512, &bytes, NULL);
    CloseHandle(h);
    return ok && bytes == 512;
}

static DWORD WINAPI mbr_watch_thread(LPVOID param) {
    BYTE baseline[512];
    BYTE current[512];

    if (!mbr_read(baseline)) {
        bd_log(L"[MBR] 警告：无法读取物理磁盘，请确认是否以管理员身份运行。");
        return 0;
    }
    
    bd_log(L"[MBR] 已成功挂载 MBR 监控");
    FILE *f = _wfopen(BD_MBR_BAK, L"wb");
    if (f) { fwrite(baseline, 1, 512, f); fclose(f); }

    while (1) {
        if (g_bPaused || !g_bMbrPrt) { Sleep(1000); continue; }
        Sleep(2000);
        
        if (!mbr_read(current)) continue;

        if (memcmp(baseline, current, 512) != 0) {
            bd_log(L"[MBR] 检测到 MBR 被修改，等待用户选择...");

            /* 先询问，再按用户选择处理。超时（IDOK）只恢复，不蓝屏；
               只有用户明确点“覆写并急停”才触发蓝屏。 */
            int decision = bd_show_popup(L"MBR 防护告警",
                                         L"主引导记录被修改！\n请选择处理方式：\n"
                                         L"[同意] 放行并更新基线\n"
                                         L"[覆写并急停] 恢复原 MBR 并蓝屏\n"
                                         L"（15 秒无操作将自动恢复原 MBR，不蓝屏）",
                                         2, 15);
            /* 启动静默期：不做任何处理，下一轮检测到变化会重新提示 */
            if (decision == BD_POPUP_SUPPRESSED) continue;

            if (decision == IDYES) {
                bd_log(L"[MBR] 用户同意了 MBR 修改，更新基线");
                bd_record_add(L"MBR防护", L"PhysicalDrive0 主引导记录", L"同意");
                memcpy(baseline, current, 512);
            } else {
                bd_log(L"[MBR] 正在恢复原 MBR...");
                HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                BOOL restored = FALSE;
                if (h != INVALID_HANDLE_VALUE) {
                    SetFilePointer(h, 0, NULL, FILE_BEGIN);
                    DWORD bytes = 0;
                    restored = WriteFile(h, baseline, 512, &bytes, NULL) && bytes == 512;
                    CloseHandle(h);
                }
                bd_log(L"[MBR] 回写%s", restored ? L"完成" : L"失败");

                if (decision == IDNO) {
                    bd_record_add(L"MBR防护", L"PhysicalDrive0 主引导记录", L"恢复并急停");
                    bd_trigger_bsod();
                } else {
                    bd_record_add(L"MBR防护", L"PhysicalDrive0 主引导记录", L"已恢复");
                }
            }
        }
    }
    return 0;
}

void bd_mbr_monitor_start(void) {
    CreateThread(NULL, 0, mbr_watch_thread, NULL, 0, NULL);
}