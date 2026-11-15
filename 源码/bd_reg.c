#include "bd_common.h"
#include <shlobj.h>

/* 注册表防护：对关键键做“值级快照”，修改后可精确回滚。
   快照同时落盘到 缓存目录\RegBackup\N.snap，控制中心的拦截记录
   在用户事后改选“回滚”时也能直接使用。 */

#define REG_SNAP_DIR   bd_cache_path(L"RegBackup")
#define MAX_REGVALS    256
#define REG_SNAP_MAGIC 0x52474B53  /* 'S''K''G''R' */

typedef struct {
    HKEY root;
    LPCWSTR subkey;
    const wchar_t* display;   /* 写进拦截记录的完整名称 */
    int index;
} REG_WATCH_ITEM;

static REG_WATCH_ITEM g_reg_items[] = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0 },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 1 },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 2 }
};
#define REG_ITEM_COUNT (int)(sizeof(g_reg_items) / sizeof(g_reg_items[0]))

typedef struct {
    wchar_t name[256];
    DWORD type;
    DWORD size;
    BYTE* data;
} REG_VAL;

static void free_vals(REG_VAL* vals, int n)
{
    for (int i = 0; i < n; i++) {
        if (vals[i].data) { free(vals[i].data); vals[i].data = NULL; }
    }
}

/* 读取一个键下所有值（含二进制数据） */
static int read_values(HKEY hKey, REG_VAL* vals, int cap)
{
    int n = 0;
    for (DWORD i = 0; n < cap; i++) {
        wchar_t name[256];
        DWORD nameLen = 256;
        DWORD type = 0, dataSize = 0;
        LONG r = RegEnumValueW(hKey, i, name, &nameLen, NULL, &type, NULL, &dataSize);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) break;

        BYTE* data = (BYTE*)malloc(dataSize ? dataSize : 1);
        if (!data) break;
        nameLen = 256;
        r = RegEnumValueW(hKey, i, name, &nameLen, NULL, &type, data, &dataSize);
        if (r != ERROR_SUCCESS) { free(data); if (r == ERROR_NO_MORE_ITEMS) break; continue; }

        wcsncpy(vals[n].name, name, 255);
        vals[n].name[255] = 0;
        vals[n].type = type;
        vals[n].size = dataSize;
        vals[n].data = data;
        n++;
    }
    return n;
}

static DWORD vals_checksum(const REG_VAL* vals, int n)
{
    DWORD h = 2166136261u;
    for (int i = 0; i < n; i++) {
        h ^= vals[i].type; h *= 16777619u;
        h ^= vals[i].size; h *= 16777619u;
        for (const wchar_t* p = vals[i].name; *p; p++) { h ^= (DWORD)*p; h *= 16777619u; }
        for (DWORD j = 0; j < vals[i].size; j++) { h ^= vals[i].data[j]; h *= 16777619u; }
    }
    return h;
}

static void ensure_snap_dir(void)
{
    SHCreateDirectoryExW(NULL, REG_SNAP_DIR, NULL);
}

/* 快照文件格式：magic/count + [type, nameChars, dataSize, name, data]... */
static BOOL save_snapshot(int idx, const REG_VAL* vals, int n)
{
    ensure_snap_dir();
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%s\\%d.snap", REG_SNAP_DIR, idx);

    FILE* f = _wfopen(path, L"wb");
    if (!f) return FALSE;

    DWORD magic = REG_SNAP_MAGIC, count = (DWORD)n;
    fwrite(&magic, sizeof(DWORD), 1, f);
    fwrite(&count, sizeof(DWORD), 1, f);
    for (int i = 0; i < n; i++) {
        DWORD type = vals[i].type, nameChars = (DWORD)wcslen(vals[i].name), dataSize = vals[i].size;
        fwrite(&type, sizeof(DWORD), 1, f);
        fwrite(&nameChars, sizeof(DWORD), 1, f);
        fwrite(&dataSize, sizeof(DWORD), 1, f);
        fwrite(vals[i].name, sizeof(wchar_t), nameChars, f);
        if (dataSize) fwrite(vals[i].data, 1, dataSize, f);
    }
    fclose(f);
    return TRUE;
}

static int load_snapshot(int idx, REG_VAL* vals, int cap)
{
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"%s\\%d.snap", REG_SNAP_DIR, idx);
    FILE* f = _wfopen(path, L"rb");
    if (!f) return 0;

    DWORD magic = 0, count = 0;
    if (fread(&magic, sizeof(DWORD), 1, f) != 1 || magic != REG_SNAP_MAGIC ||
        fread(&count, sizeof(DWORD), 1, f) != 1 || count > (DWORD)cap) {
        fclose(f); return 0;
    }

    int n = 0;
    for (DWORD i = 0; i < count; i++) {
        DWORD type = 0, nameChars = 0, dataSize = 0;
        if (fread(&type, sizeof(DWORD), 1, f) != 1 ||
            fread(&nameChars, sizeof(DWORD), 1, f) != 1 ||
            fread(&dataSize, sizeof(DWORD), 1, f) != 1) break;
        if (nameChars > 255 || dataSize > 1024 * 1024) break;

        REG_VAL* v = &vals[n];
        if (fread(v->name, sizeof(wchar_t), nameChars, f) != nameChars) break;
        v->name[nameChars] = 0;
        v->type = type;
        v->size = dataSize;
        v->data = (BYTE*)malloc(dataSize ? dataSize : 1);
        if (!v->data) break;
        if (dataSize && fread(v->data, 1, dataSize, f) != dataSize) { free(v->data); v->data = NULL; break; }
        n++;
    }
    fclose(f);
    return n;
}

static int find_val(const REG_VAL* vals, int n, const wchar_t* name)
{
    for (int i = 0; i < n; i++)
        if (_wcsicmp(vals[i].name, name) == 0) return i;
    return -1;
}

/* 把键恢复成快照状态：多余的值删除，快照里的值写回 */
static void apply_snapshot(HKEY hKey, const REG_VAL* base, int n)
{
    /* 先删掉快照中没有的值 */
    for (DWORD i = 0; ; i++) {
        wchar_t name[256];
        DWORD nameLen = 256;
        LONG r = RegEnumValueW(hKey, i, name, &nameLen, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) break;
        if (find_val(base, n, name) < 0) {
            if (RegDeleteValueW(hKey, name) == ERROR_SUCCESS) i--; /* 删除后索引前移 */
        }
    }

    for (int i = 0; i < n; i++) {
        RegSetValueExW(hKey, base[i].name, 0, base[i].type, base[i].data, base[i].size);
    }
}

static void write_index_file(void)
{
    ensure_snap_dir();
    FILE* f = _wfopen(bd_cache_path(L"RegBackup\\index.txt"), L"w, ccs=UTF-8");
    if (!f) return;
    for (int i = 0; i < REG_ITEM_COUNT; i++)
        fwprintf(f, L"%d\t%s\n", g_reg_items[i].index, g_reg_items[i].display);
    fclose(f);
}

static DWORD WINAPI reg_watch_thread(LPVOID param)
{
    REG_WATCH_ITEM* item = (REG_WATCH_ITEM*)param;
    HKEY hKey = NULL;
    DWORD access = KEY_READ | KEY_ALL_ACCESS | KEY_WOW64_64KEY;
    if (RegOpenKeyExW(item->root, item->subkey, 0, access, &hKey) != ERROR_SUCCESS) return 0;

    REG_VAL* baseline = (REG_VAL*)calloc(MAX_REGVALS, sizeof(REG_VAL));
    if (!baseline) { RegCloseKey(hKey); return 0; }
    int baseCount = read_values(hKey, baseline, MAX_REGVALS);
    save_snapshot(item->index, baseline, baseCount);

    wchar_t reloadFlag[MAX_PATH];
    swprintf(reloadFlag, MAX_PATH, L"%s\\reload_%d.flag", REG_SNAP_DIR, item->index);

    DWORD last_checksum = vals_checksum(baseline, baseCount);

    while (1) {
        if (g_bPaused || !g_bRegPrt) { Sleep(1000); continue; }
        Sleep(1500);

        /* 控制中心事后执行了回滚：重新加载快照作为基线，避免再次误报 */
        if (GetFileAttributesW(reloadFlag) != INVALID_FILE_ATTRIBUTES) {
            DeleteFileW(reloadFlag);
            free_vals(baseline, baseCount);
            memset(baseline, 0, sizeof(REG_VAL) * MAX_REGVALS);
            baseCount = load_snapshot(item->index, baseline, MAX_REGVALS);
            last_checksum = vals_checksum(baseline, baseCount);
        }

        RegCloseKey(hKey);
        if (RegOpenKeyExW(item->root, item->subkey, 0, access, &hKey) != ERROR_SUCCESS) continue;

        REG_VAL* current = (REG_VAL*)calloc(MAX_REGVALS, sizeof(REG_VAL));
        if (!current) continue;
        int curCount = read_values(hKey, current, MAX_REGVALS);
        DWORD current_checksum = vals_checksum(current, curCount);

        if (current_checksum != last_checksum) {
            int r = bd_show_popup(L"注册表防护告警",
                                  L"关键注册表被修改！\n请选择处理方式（回滚会恢复为修改前的状态）：",
                                  1, 15);
            if (r == BD_POPUP_SUPPRESSED) {
                /* 启动静默期：不改动基线，静默期结束后会再次告警 */
                free_vals(current, curCount);
                free(current);
                continue;
            }

            bd_record_add(L"注册表防护", item->display,
                          r == IDYES ? L"同意" : (r == IDCANCEL ? L"急停" : L"回滚"));

            if (r == IDYES) {
                /* 信任修改：当前状态成为新基线（转移数据所有权，避免重复释放） */
                free_vals(baseline, baseCount);
                memset(baseline, 0, sizeof(REG_VAL) * MAX_REGVALS);
                for (int i = 0; i < curCount; i++) {
                    baseline[i] = current[i];
                    current[i].data = NULL;
                }
                baseCount = curCount;
                last_checksum = current_checksum;
                save_snapshot(item->index, baseline, baseCount);
                bd_log(L"[Reg] 用户信任修改，更新备份: %s", item->subkey);
            } else {
                apply_snapshot(hKey, baseline, baseCount);
                last_checksum = vals_checksum(baseline, baseCount);
                bd_log(L"[Reg] 已回滚到修改前状态: %s", item->subkey);

                if (r == IDCANCEL) bd_trigger_bsod();
            }
            free_vals(current, curCount);
            free(current);
        } else {
            free_vals(current, curCount);
            free(current);
        }
    }
    /* 不会走到这里 */
    RegCloseKey(hKey);
    return 0;
}

void bd_reg_monitor_start(void)
{
    ensure_snap_dir();
    write_index_file();
    for (int i = 0; i < REG_ITEM_COUNT; i++)
        CreateThread(NULL, 0, reg_watch_thread, &g_reg_items[i], 0, NULL);
}
