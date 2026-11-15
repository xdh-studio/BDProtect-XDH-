#include "bd_common.h"
#include <shlobj.h> // 需要用于创建多级目录

HANDLE g_hFileSuspendEvent = NULL;
static CRITICAL_SECTION g_file_cs;
static BOOL g_is_alerting = FALSE;
static DWORD g_last_event_time = 0;

#define MAX_TRACKED 2000
static wchar_t g_tracked_paths[MAX_TRACKED][MAX_PATH];
/* 每条路径记住了哪些动作已经统计过：同一路径的“修改”重复上报只算一次，
   但“先新增、后删除”属于两种不同动作，必须分别计数——否则新建的文件
   被同一批操作删除时永远统计不到删除，等于漏掉最关键的破坏行为。 */
static BYTE g_tracked_actions[MAX_TRACKED];
#define ACT_MOD 1
#define ACT_ADD 2
#define ACT_DEL 4
static int g_tracked_count = 0;

static int sys_del = 0, sys_mod = 0, sys_add = 0;
static int high_del = 0, high_mod = 0, high_add = 0;
static int norm_del = 0, norm_mod = 0, norm_add = 0;
static DWORD g_window_start = 0;

#define RISK_NORMAL 0
#define RISK_HIGH   1
#define RISK_SYSTEM 2

/* 触发阈值。原则：不降低安全性 ——
   删除原文件是勒索/破坏的必经步骤，删除阈值保持原样；
   安装、更新、编译、解压通常只会大量“修改/新增”文件，
   因此修改与新增的阈值明显放宽。
   任何真正的勒索行为要么删除原文件（按老阈值照样拦截），
   要么在大量目录里改写/新增（总量仍会超过下面的阈值）。 */
#define SYS_DEL_LIMIT   20
#define HIGH_DEL_LIMIT  30
#define NORM_DEL_LIMIT  80
#define SYS_MOD_LIMIT   60
#define HIGH_MOD_LIMIT  90
#define NORM_MOD_LIMIT  240
#define SYS_ADD_LIMIT   200
#define HIGH_ADD_LIMIT  300
#define NORM_ADD_LIMIT  800

/* 同一个目录内最多统计这么多次“新增”，其余忽略：
   单个安装包/游戏更新在一个目录里铺几千个文件也不再触发 */
#define ADD_PER_DIR_CAP 40
#define ADD_DIR_SLOTS   128
/* 事件连续不断时每 5 分钟把累计量减半（按速率判断，而不是一次性清零）。
   减半而不是清零：持续不断的批量动作仍会累积到阈值，只是不会随着时间
   无限累加，避免长时间正常使用被算成“批量破坏”。 */
#define WINDOW_MAX_MS   (5 * 60 * 1000)

typedef struct { wchar_t dir[MAX_PATH]; int cnt; } ADD_DIR_ENTRY;
static ADD_DIR_ENTRY g_adddirs[ADD_DIR_SLOTS];
static int g_adddir_count = 0;

static void reset_event_counters(void)
{
    sys_del = sys_mod = sys_add = 0;
    high_del = high_mod = high_add = 0;
    norm_del = norm_mod = norm_add = 0;
    g_adddir_count = 0;
    g_window_start = 0;
    g_tracked_count = 0;
}

/* 触发告警时用：只清计数，保留被改动路径清单——
   回滚要靠这份清单，先清掉就等于“知道出事了但什么都不恢复”。 */
static void reset_counters_keep_tracking(void)
{
    sys_del = sys_mod = sys_add = 0;
    high_del = high_mod = high_add = 0;
    norm_del = norm_mod = norm_add = 0;
    g_adddir_count = 0;
    g_window_start = 0;
}

/* 窗口超时：计数减半。删除计数也减半，但阈值本来就是按“短时间批量删除”
   设计的，持续删除仍会很快重新超限，安全性不受影响。 */
static void decay_event_counters(void)
{
    sys_del /= 2; sys_mod /= 2; sys_add /= 2;
    high_del /= 2; high_mod /= 2; high_add /= 2;
    norm_del /= 2; norm_mod /= 2; norm_add /= 2;
    g_adddir_count = 0;      /* 目录限流额度同步刷新 */
}

/* “新增”事件按“应用/目录”限流：返回 FALSE 表示该事件不计入统计。
   分组键取路径前 3 级（如 C:\Program Files\App、D:\Users\me\Desktop），
   这样一次安装/解压/更新在同一个应用目录里铺再多文件也只算一份。 */
static BOOL add_event_allowed(const wchar_t* full)
{
    wchar_t dir[MAX_PATH];
    wcsncpy(dir, full, MAX_PATH - 1);
    dir[MAX_PATH - 1] = 0;

    int seps = 0;
    for (size_t i = 0; dir[i]; i++) {
        if (dir[i] == L'\\') {
            seps++;
            if (seps >= 3) { dir[i] = 0; break; }   /* 保留到第 3 个分隔符之前 */
        }
    }
    if (seps < 3) {
        wchar_t* slash = wcsrchr(dir, L'\\');
        if (slash) *slash = 0;                      /* 层级不足时按父目录分组 */
    }
    CharLowerW(dir);

    for (int i = 0; i < g_adddir_count; i++) {
        if (_wcsicmp(g_adddirs[i].dir, dir) == 0) {
            if (g_adddirs[i].cnt >= ADD_PER_DIR_CAP) return FALSE;
            g_adddirs[i].cnt++;
            return TRUE;
        }
    }
    if (g_adddir_count < ADD_DIR_SLOTS) {
        wcsncpy(g_adddirs[g_adddir_count].dir, dir, MAX_PATH - 1);
        g_adddirs[g_adddir_count].dir[MAX_PATH - 1] = 0;
        g_adddirs[g_adddir_count].cnt = 1;
        g_adddir_count++;
    }
    return TRUE;
}

#define BACKUP_MAX_FILE_SIZE  (64ULL * 1024 * 1024)
#define BACKUP_MAX_FILES      3000
#define BACKUP_MAX_TOTAL      (1024ULL * 1024 * 1024)
static int g_backupCount = 0;
static unsigned long long g_backupBytes = 0;

static BOOL is_directory_path(const wchar_t* path)
{
    DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL should_ignore(const wchar_t* path)
{
    /* 本软件自己的安装目录与缓存目录（含 FileBackup 里的病毒副本）一律放行 */
    if (bd_is_own_path(path)) return TRUE;
    if (wcsstr(path, L"\\BDtemp\\") != NULL) return TRUE;

    wchar_t lower[MAX_PATH * 2];
    wcsncpy(lower, path, MAX_PATH * 2 - 1);
    lower[MAX_PATH * 2 - 1] = 0;
    CharLowerW(lower);

    static const wchar_t* noisy_dirs[] = {
        L"\\appdata\\",
        L"\\programdata\\",
        L"\\windows\\temp\\",
        L"\\windows\\winsxs\\",
        L"\\windows\\installer\\",
        L"\\windows\\softwaredistribution\\",
        L"\\windows\\system32\\config\\",
        L"\\windows\\prefetch\\",
        L"\\windows\\servicing\\",
        L"\\windows\\logs\\",
        L"\\windows\\minidump\\",
        L"\\windows\\livekernelreports\\",
        L"\\windows\\systemtemp\\",
        L"\\windows\\system32\\catroot",
        L"\\windows\\system32\\logfiles\\",
        L"\\windows\\assembly\\",
        L"\\windows\\fontcache\\",
        L"\\temp\\",
        L"\\cache\\",
        L"\\caches\\",
        L"\\crashpad\\",
        L"\\$recycle.bin\\",
        L"\\system volume information\\",
        L"\\node_modules\\",
        L"\\.git\\",
        L"\\steamapps\\",
        L"\\.vscode\\extensions\\"
    };
    for (int i = 0; i < (int)(sizeof(noisy_dirs) / sizeof(noisy_dirs[0])); i++)
        if (wcsstr(lower, noisy_dirs[i]) != NULL) return TRUE;

    static const wchar_t* noisy_ext[] = {
        L".tmp", L".temp", L".log", L".etl", L".dmp", L".chk", L".swp", L".lock",
        L".crdownload", L".part", L".download", L".~bf",
        L".pf", L".pf_bak", L".db-wal", L".db-shm", L".journal", L".bak"
    };
    size_t len = wcslen(lower);
    for (int i = 0; i < (int)(sizeof(noisy_ext) / sizeof(noisy_ext[0])); i++) {
        size_t el = wcslen(noisy_ext[i]);
        if (len > el && wcscmp(lower + len - el, noisy_ext[i]) == 0) return TRUE;
    }
    if (wcsstr(lower, L"~$") != NULL) return TRUE;
    return FALSE;
}

static int get_file_risk(const wchar_t* path)
{
    wchar_t lower[MAX_PATH * 2];
    wcsncpy(lower, path, MAX_PATH * 2 - 1);
    lower[MAX_PATH * 2 - 1] = 0;
    CharLowerW(lower);

    if (wcsstr(lower, L"c:\\windows\\") ||
        wcsstr(lower, L"c:\\program files") ||
        wcsstr(lower, L"\\start menu\\") ||
        wcsstr(lower, L"\\startup\\")) {
        return RISK_SYSTEM;
    }

    const wchar_t* ext = wcsrchr(lower, L'.');
    if (ext) {
        static const wchar_t* high_ext[] = {
            L".exe", L".dll", L".sys", L".bat", L".vbs", L".cmd", L".com", L".scr",
            L".ps1", L".msi", L".reg", L".drv", L".ocx"
        };
        for (int i = 0; i < (int)(sizeof(high_ext) / sizeof(high_ext[0])); i++)
            if (_wcsicmp(ext, high_ext[i]) == 0) return RISK_HIGH;
    }
    return RISK_NORMAL;
}

/* 记录“该路径的该类动作已经统计过”。返回 TRUE 表示重复，本次应跳过。 */
static BOOL mark_path_action(const wchar_t* full_path, BYTE act) {
    for (int i = 0; i < g_tracked_count; i++) {
        if (_wcsicmp(g_tracked_paths[i], full_path) == 0) {
            BOOL seen = (g_tracked_actions[i] & act) != 0;
            g_tracked_actions[i] |= act;
            return seen;
        }
    }
    if (g_tracked_count < MAX_TRACKED) {
        wcsncpy(g_tracked_paths[g_tracked_count], full_path, MAX_PATH - 1);
        g_tracked_paths[g_tracked_count][MAX_PATH - 1] = 0;
        g_tracked_actions[g_tracked_count] = act;
        g_tracked_count++;
    }
    return FALSE;
}

/* 将原文件路径转换为备份路径，并创建多级目录 */
static void get_bak_path(const wchar_t* orig, wchar_t* bak, int cap) {
    swprintf(bak, cap, L"%s\\%s", BD_FILE_BAK_DIR, orig);
    size_t base = wcslen(BD_FILE_BAK_DIR) + 1;
    for (size_t i = base; bak[i]; i++) {
        if (bak[i] == L':') bak[i] = L'_';
    }

    wchar_t dir[MAX_PATH * 2];
    wcsncpy(dir, bak, MAX_PATH * 2 - 1);
    dir[MAX_PATH * 2 - 1] = 0;
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) *slash = 0;
    SHCreateDirectoryExW(NULL, dir, NULL);
}

/* 首次见到某个文件时保存一份快照：以后它再被修改/删除时就有据可回滚 */
static BOOL ensure_backup(const wchar_t* path)
{
    wchar_t bak[MAX_PATH * 2];
    get_bak_path(path, bak, MAX_PATH * 2);
    if (GetFileAttributesW(bak) != INVALID_FILE_ATTRIBUTES) return TRUE;

    DWORD attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) return FALSE;

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return FALSE;
    unsigned long long size = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (size > BACKUP_MAX_FILE_SIZE || g_backupBytes + size > BACKUP_MAX_TOTAL) return FALSE;

    if (CopyFileW(path, bak, FALSE)) {
        g_backupBytes += size;
        return TRUE;
    }
    return FALSE;
}

/* 递归备份常用目录（限制深度和文件数量，避免占用太多空间） */
static void backup_tree(const wchar_t* dir, int depth)
{
    if (depth > 3 || g_backupCount >= BACKUP_MAX_FILES) return;

    wchar_t search[MAX_PATH * 2];
    swprintf(search, MAX_PATH * 2, L"%s\\*", dir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (g_backupCount >= BACKUP_MAX_FILES) break;

        wchar_t full[MAX_PATH * 2];
        swprintf(full, MAX_PATH * 2, L"%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (_wcsicmp(fd.cFileName, L"AppData") == 0) continue;
            if (_wcsicmp(fd.cFileName, L"node_modules") == 0) continue;
            if (_wcsicmp(fd.cFileName, L".git") == 0) continue;
            backup_tree(full, depth + 1);
        } else {
            if (should_ignore(full)) continue;
            unsigned long long size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (size > BACKUP_MAX_FILE_SIZE) continue;
            if (ensure_backup(full)) g_backupCount++;
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

static void backup_initial_files(void) {
    bd_log(L"[File] 正在建立初始备份...");
    wchar_t userProfile[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH)) {
        static const wchar_t* dirs[] = { L"\\Desktop", L"\\Documents", L"\\Downloads" };
        for (int i = 0; i < 3; i++) {
            wchar_t path[MAX_PATH];
            swprintf(path, MAX_PATH, L"%s%s", userProfile, dirs[i]);
            backup_tree(path, 0);
        }
    }
    bd_log(L"[File] 初始备份完成，共 %d 个文件。", g_backupCount);
}

static BOOL restore_one(const wchar_t* orig)
{
    wchar_t bak[MAX_PATH * 2];
    get_bak_path(orig, bak, MAX_PATH * 2);
    if (GetFileAttributesW(bak) == INVALID_FILE_ATTRIBUTES) return FALSE;

    /* 目标文件可能还在且为只读；先清属性再覆盖 */
    SetFileAttributesW(orig, FILE_ATTRIBUTE_NORMAL);

    /* 原文件所在目录可能被删除，先补建目录 */
    wchar_t dir[MAX_PATH];
    wcsncpy(dir, orig, MAX_PATH - 1);
    dir[MAX_PATH - 1] = 0;
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) { *slash = 0; SHCreateDirectoryExW(NULL, dir, NULL); }

    if (CopyFileW(bak, orig, FALSE)) {
        bd_log(L"[File] 已回滚: %s", orig);
        return TRUE;
    }
    bd_log(L"[File] 回滚失败: %s", orig);
    return FALSE;
}

static DWORD WINAPI monitor_dir(LPVOID param) {
    wchar_t* dir = (wchar_t*)param;
    HANDLE hDir = CreateFileW(dir, FILE_LIST_DIRECTORY, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) { free(dir); return 0; }

    /* 64KB 缓冲：递归监视整盘时 8KB 极易溢出，溢出后事件会被静默丢弃 */
    const DWORD bufSize = 64 * 1024;
    BYTE* buf = (BYTE*)malloc(bufSize);
    if (!buf) { free(dir); CloseHandle(hDir); return 0; }

    DWORD bytes;
    while (1) {
        /* 暂停时仍读取并丢弃事件，避免恢复后积压事件造成误报（如误判批量删除） */
        BOOL ok = ReadDirectoryChangesW(hDir, buf, bufSize, TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes, NULL, NULL);
        if (!ok) {
            if (GetLastError() == ERROR_NOTIFY_ENUM_DIR)
                bd_log(L"[File] 目录监视缓冲溢出，部分事件被丢弃: %s", dir);
            Sleep(500);
            continue;
        }

        if (g_bPaused || !g_bFilePrt) {
            /* 丢弃暂停期间的事件，同时清空统计，避免恢复后累计触发 */
            EnterCriticalSection(&g_file_cs);
            reset_event_counters();
            g_last_event_time = 0;
            LeaveCriticalSection(&g_file_cs);
            continue;
        }

        {
            if (g_is_alerting) continue;
            FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buf;
            BOOL trigger = FALSE;

            EnterCriticalSection(&g_file_cs);
            DWORD now = GetTickCount();
            /* 空闲 20 秒清零；连续忙碌也最多累计 5 分钟，按速率判断 */
            if (g_last_event_time != 0 && (now - g_last_event_time > 20000)) {
                reset_event_counters();
            } else if (g_window_start != 0 && (now - g_window_start > WINDOW_MAX_MS)) {
                decay_event_counters();
                g_window_start = now;
            }
            if (g_window_start == 0) g_window_start = now;
            g_last_event_time = now;

            while (1) {
                int len = fni->FileNameLength / sizeof(WCHAR);
                wchar_t name[MAX_PATH];
                if (len > MAX_PATH - 1) len = MAX_PATH - 1;
                wcsncpy(name, fni->FileName, len); name[len] = 0;
                wchar_t full[MAX_PATH*2]; swprintf(full, MAX_PATH*2, L"%s%s", dir, name);

                BOOL is_dir = is_directory_path(full);
                if (!is_dir && !should_ignore(full)) {
                    BYTE act = 0;
                    if (fni->Action == FILE_ACTION_MODIFIED) act = ACT_MOD;
                    else if (fni->Action == FILE_ACTION_RENAMED_NEW_NAME) act = ACT_MOD;
                    else if (fni->Action == FILE_ACTION_ADDED) act = ACT_ADD;
                    else if (fni->Action == FILE_ACTION_REMOVED) act = ACT_DEL;

                    if (act) {
                        /* 同一路径的同一种动作只统计一次；不同动作分别统计，
                           这样“新建后删除”里的删除依然会被计算。 */
                        if (mark_path_action(full, act)) {
                            /* 重复上报，忽略 */
                        } else {
                            int risk = get_file_risk(full);
                            BOOL changed = FALSE;

                            if (act == ACT_MOD) {
                                /* 改名也计入“修改”且不限流：勒索软件加密文件的
                                   典型动作就是原地改名（追加 .enc 等）。 */
                                if (risk == RISK_SYSTEM) sys_mod++;
                                else if (risk == RISK_HIGH) high_mod++;
                                else norm_mod++;
                                changed = TRUE;
                            }
                            else if (act == ACT_ADD) {
                                /* 纯新增按“应用/目录”限流，安装包/解压不会把计数刷爆 */
                                if (add_event_allowed(full)) {
                                    if (risk == RISK_SYSTEM) sys_add++;
                                    else if (risk == RISK_HIGH) high_add++;
                                    else norm_add++;
                                    changed = TRUE;
                                }
                            }
                            else if (act == ACT_DEL) {
                                if (risk == RISK_SYSTEM) sys_del++;
                                else if (risk == RISK_HIGH) high_del++;
                                else norm_del++;
                                changed = TRUE;
                            }

                            if (changed) {
                                /* 首次见到该文件时留一份快照，后续再被改动/删除就能回滚 */
                                ensure_backup(full);
                            }
                        }
                    }
                }
                if (fni->NextEntryOffset == 0) break;
                fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
            }

            if (sys_del > SYS_DEL_LIMIT || high_del > HIGH_DEL_LIMIT || norm_del > NORM_DEL_LIMIT ||
                sys_mod > SYS_MOD_LIMIT || high_mod > HIGH_MOD_LIMIT || norm_mod > NORM_MOD_LIMIT ||
                sys_add > SYS_ADD_LIMIT || high_add > HIGH_ADD_LIMIT || norm_add > NORM_ADD_LIMIT) {
                trigger = TRUE;
            }
            LeaveCriticalSection(&g_file_cs);

            if (trigger) {
                Sleep(3000);
                EnterCriticalSection(&g_file_cs);
                if (!g_is_alerting) {
                    g_is_alerting = TRUE;

                    int s_d = sys_del, s_m = sys_mod, s_a = sys_add;
                    int h_d = high_del, h_m = high_mod, h_a = high_add;
                    int n_d = norm_del, n_m = norm_mod, n_a = norm_add;

                    reset_counters_keep_tracking();
                    LeaveCriticalSection(&g_file_cs);

                    wchar_t text[1024] = L"文件防护：捕获到异常批量变动！\n\n";
                    if (s_d > SYS_DEL_LIMIT || s_m > SYS_MOD_LIMIT || s_a > SYS_ADD_LIMIT) {
                        wchar_t line[256]; swprintf(line, 256, L"【系统核心】 删除:%d 修改:%d 新增:%d\n", s_d, s_m, s_a);
                        wcscat(text, line);
                    }
                    if (h_d > HIGH_DEL_LIMIT || h_m > HIGH_MOD_LIMIT || h_a > HIGH_ADD_LIMIT) {
                        wchar_t line[256]; swprintf(line, 256, L"【高危可执行】 删除:%d 修改:%d 新增:%d\n", h_d, h_m, h_a);
                        wcscat(text, line);
                    }
                    if (n_d > NORM_DEL_LIMIT || n_m > NORM_MOD_LIMIT || n_a > NORM_ADD_LIMIT) {
                        wchar_t line[256]; swprintf(line, 256, L"【普通文档类】 删除:%d 修改:%d 新增:%d\n", n_d, n_m, n_a);
                        wcscat(text, line);
                    }
                    wcscat(text, L"\n请选择处理方式（回滚会尽量恢复所有被改动的文件）：");

                    int r = bd_show_popup(L"文件防护告警", text, 1, 15);
                    if (r == BD_POPUP_SUPPRESSED) {
                        /* 启动静默期：不记录、不回滚，后续事件会重新触发 */
                        g_tracked_count = 0;
                        g_is_alerting = FALSE;
                        continue;
                    }

                    bd_record_add(L"文件防护",
                                  g_tracked_count > 0 ? g_tracked_paths[0] : L"批量文件变动",
                                  r == IDYES ? L"同意" : (r == IDCANCEL ? L"急停" : L"回滚"));

                    if (r == IDYES) {
                        bd_log(L"[File] 用户信任本次修改");
                        /* 信任的话，把被修改的文件重新备份，覆盖旧的备份 */
                        for (int i = 0; i < g_tracked_count; i++) {
                            wchar_t bak_path[MAX_PATH*2];
                            get_bak_path(g_tracked_paths[i], bak_path, MAX_PATH*2);
                            CopyFileW(g_tracked_paths[i], bak_path, FALSE);
                        }
                    }
                    else if (r == IDNO) {
                        bd_log(L"[File] 执行回滚操作...");
                        int restored = 0, failed = 0;
                        for (int i = 0; i < g_tracked_count; i++) {
                            if (restore_one(g_tracked_paths[i])) restored++;
                            else failed++;
                        }
                        bd_log(L"[File] 回滚完成：成功 %d，失败 %d", restored, failed);

                        if (restored == 0 && g_tracked_count > 0) {
                            bd_show_popup(L"回滚结果",
                                          L"这些文件在此前没有备份，无法恢复。\n"
                                          L"新版会在文件第一次出现时自动备份，之后的修改即可回滚。",
                                          6, 0);
                        }
                    }
                    else if (r == IDCANCEL) {
                        bd_trigger_bsod();
                    }

                    g_tracked_count = 0; // 清空追踪
                    EnterCriticalSection(&g_file_cs);
                    g_is_alerting = FALSE;
                    LeaveCriticalSection(&g_file_cs);
                } else {
                    LeaveCriticalSection(&g_file_cs);
                }
            }
        }
    }
    return 0;
}

void bd_file_monitor_start(void) {
    InitializeCriticalSection(&g_file_cs);
    g_hFileSuspendEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

    /* 启动时备份桌面/文档/下载，保证常见文件都可回滚 */
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)backup_initial_files, NULL, 0, NULL);

    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if ((mask & (1 << i)) != 0) {
            wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
            if (GetDriveTypeW(root) == DRIVE_FIXED) {
                wchar_t* d = malloc(sizeof(wchar_t) * 4);
                wcscpy(d, root);
                CreateThread(NULL, 0, monitor_dir, d, 0, NULL);
            }
        }
    }
}
