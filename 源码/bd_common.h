#ifndef BD_COMMON_H
#define BD_COMMON_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <shellapi.h>
#include "bd_paths.h"

/* 缓存目录下的文件/目录路径：由 bd_paths 按当前缓存位置（默认 C:\BDtemp，
   安装时可改）生成。返回线程本地缓冲，勿在同一表达式中多次使用，
   使用前必须先调用 bd_paths_init()。 */
#define BD_TEMP_DIR      bd_cache_root()
#define BD_FILES_SNAP    bd_cache_path(L"files.snap")
#define BD_MBR_BAK       bd_cache_path(L"mbr.bak")
#define BD_LOG_FILE      bd_cache_path(L"bd.log")
#define BD_RECORDS_FILE  bd_cache_path(L"records.log")
#define BD_FILE_BAK_DIR  bd_cache_path(L"FileBackup")
#define BD_WHITELIST     bd_cache_path(L"net_whitelist.txt")
#define BD_TOOL_CACHE    bd_cache_path(L"PracticalToolbox.txt")

/* 运行状态目录：配置和“退出”标志文件放在这里，并收紧 ACL，
   只允许 SYSTEM / Administrators 写入。这样普通进程无法通过
   写 stop.flag 或改 config.ini 来关闭防护。 */
#define BD_STATE_DIR     L"C:\\ProgramData\\BDProtect"
#define BD_STOP_FLAG     BD_STATE_DIR L"\\stop.flag"
#define BD_CONFIG_FILE   BD_STATE_DIR L"\\config.ini"

/* 旧的配置位置：升级时迁移一次，之后不再使用 */
#define BD_OLD_CONFIG_FILE bd_cache_path(L"config.ini")

/* 用于保存“标志类文件”的深层目录。
   这些文件在卸载和更新时都不能被删除或修改。 */
#define BD_STORE_DIR     L"C:\\ProgramData\\Microsoft\\Windows\\Caches\\BDProtectData"
#define BD_RESTRICTED    BD_STORE_DIR L"\\Restricted.txt"
#define BD_USERUP        BD_STORE_DIR L"\\UserUp.txt"

/* 文件阈值 */
#define FILE_DELETE_THRESHOLD   10
#define FILE_MODIFY_THRESHOLD   5
#define FILE_RECHECK_INTERVAL_MS 15000

/* 文件保护抑制期（用户点击“继续”后） */
#define FILE_SUSPEND_MS          (5 * 60 * 1000)

/* 弹窗超时 */
#define FILE_DIALOG_TIMEOUT_MS   15000

/* 启动静默期内弹窗被抑制时的返回值：调用方应“不做任何动作” */
#define BD_POPUP_SUPPRESSED      (-99)

/* 云端病毒库试用：初始 90 分钟，提交 3 个样本后永久解锁 */
#define BD_TRIAL_MINUTES         90
#define BD_UNLOCK_SAMPLES        3

/* 后台防护进程启动后的静默期：这段时间内不弹任何防护弹窗 */
#define BD_STARTUP_GRACE_MS      30000

extern HANDLE g_hFileSuspendEvent;
extern BOOL g_bPaused;
extern BOOL g_bFilePrt, g_bRegPrt, g_bMbrPrt, g_bNetPrt, g_bInjectPrt, g_bCloudPrt;

void bd_log(const wchar_t* fmt, ...);
BOOL bd_enable_privilege(LPCWSTR name);
void bd_enable_core_privileges(void);
void bd_force_reboot(void);
void bd_trigger_bsod(void);
void bd_cleanup_critical(void);
void bd_start_self_guard(void);
void bd_install_crash_guard(void);
void bd_ui_init(void);
BOOL bd_popup_grace_active(void);

/* 路径辅助 */
void bd_get_app_dir(wchar_t* out, int cap);
void bd_get_app_file(const wchar_t* name, wchar_t* out, int cap);
void bd_ensure_store_dir(void);
void bd_ensure_state_dir(void);
void bd_harden_dir(const wchar_t* dir);
BOOL bd_is_own_app_path(const wchar_t* path);
/* 安装目录或缓存目录（含旧默认 C:\BDtemp）→ 扫描/防护一律放行 */
BOOL bd_is_own_path(const wchar_t* path);

/* 文件哈希（MD5，32 位小写十六进制）。失败返回 FALSE，out 置空。 */
BOOL bd_file_md5(const wchar_t* path, wchar_t* out, int cap);
BOOL bd_is_hex32(const wchar_t* s);

/* UI 弹窗 (返回 IDYES/IDNO/IDCANCEL/IDOK)
   type: 1 文件/注册表 2 MBR 3 网络 4 静默提示(3秒) 5 病毒拦截 6 单按钮提示 */
int bd_show_popup(const wchar_t* title, const wchar_t* text, int type, int timeoutSec);

/* 拦截记录 */
void bd_record_add(const wchar_t* type, const wchar_t* target, const wchar_t* choice);

/* 云端病毒库试用状态 */
int  bd_cloud_get_minutes(void);
void bd_cloud_set_minutes(int minutes);
int  bd_cloud_get_userup(void);
void bd_cloud_inc_userup(void);
BOOL bd_cloud_is_unlocked(void);
BOOL bd_cloud_expired(void);

/* 监控模块 */
void bd_file_monitor_start(void);
void bd_reg_monitor_start(void);
void bd_mbr_monitor_start(void);
void bd_net_monitor_start(void);
void bd_inject_monitor_start(void);
void bd_cloud_monitor_start(void);

#endif
