#include "bd_paths.h"
#include <shlobj.h>
#include <stdio.h>

wchar_t g_bdInstallDir[MAX_PATH] = BD_INSTALL_DEFAULT;
wchar_t g_bdCacheDir[MAX_PATH]   = BD_CACHE_DEFAULT;

/* 去掉末尾反斜杠（保留盘符根如 C:\），避免路径比较不一致 */
static void normalize_path(wchar_t* p)
{
    size_t n = wcslen(p);
    while (n > 3 && p[n-1] == L'\\') p[--n] = 0;
}

static void write_path_file(const wchar_t* pathFile, const wchar_t* value)
{
    FILE* f = _wfopen(pathFile, L"w, ccs=UTF-8");
    if (!f) return;
    fwprintf(f, L"%s\n", value);
    fclose(f);
}

static BOOL read_path_file(const wchar_t* pathFile, wchar_t* out, int cap)
{
    FILE* f = _wfopen(pathFile, L"r, ccs=UTF-8");
    if (!f) return FALSE;
    if (!fgetws(out, cap, f)) { fclose(f); return FALSE; }
    fclose(f);
    size_t l = wcslen(out);
    while (l > 0 && (out[l-1] == L'\r' || out[l-1] == L'\n')) out[--l] = 0;
    if (l == 0) return FALSE;
    normalize_path(out);
    return TRUE;
}

const wchar_t* bd_cache_root(void)
{
    return g_bdCacheDir;
}

const wchar_t* bd_cache_path(const wchar_t* name)
{
    static __thread wchar_t buf[MAX_PATH];
    swprintf(buf, MAX_PATH, L"%s\\%s", g_bdCacheDir, name ? name : L"");
    return buf;
}

/* 从注册表读取缓存位置（安装目录内文件缺失时的备份来源） */
static BOOL read_cache_from_registry(wchar_t* out, int cap)
{
    DWORD cb = (DWORD)(cap * sizeof(wchar_t));
    DWORD type = 0;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, BD_PATHS_REG_KEY, BD_PATHS_REG_VALUE,
                     RRF_RT_REG_SZ, &type, out, &cb) != ERROR_SUCCESS)
        return FALSE;
    if (wcslen(out) < 4) return FALSE;
    normalize_path(out);
    return TRUE;
}

static void write_cache_to_registry(const wchar_t* value)
{
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, BD_PATHS_REG_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY,
                        NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, BD_PATHS_REG_VALUE, 0, REG_SZ,
                       (const BYTE*)value,
                       (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

void bd_paths_init(void)
{
    /* 安装目录 = 程序自身所在目录 */
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (slash) {
        *slash = 0;
        wcsncpy(g_bdInstallDir, exe, MAX_PATH - 1);
        g_bdInstallDir[MAX_PATH - 1] = 0;
    }

    /* 缓存目录：优先安装目录内的记录文件，其次注册表备份 */
    wchar_t buf[MAX_PATH];
    wchar_t cacheFile[MAX_PATH];
    swprintf(cacheFile, MAX_PATH, L"%s\\%s", g_bdInstallDir, BD_CACHE_PATH_NAME);
    if (read_path_file(cacheFile, buf, MAX_PATH) ||
        read_cache_from_registry(buf, MAX_PATH)) {
        wcsncpy(g_bdCacheDir, buf, MAX_PATH - 1);
        g_bdCacheDir[MAX_PATH - 1] = 0;
    }

    /* 缓存目录已消失 → 回退到默认 */
    bd_fallback_cache_if_missing();
}

void bd_fallback_cache_if_missing(void)
{
    if (GetFileAttributesW(g_bdCacheDir) == INVALID_FILE_ATTRIBUTES) {
        SHCreateDirectoryExW(NULL, BD_CACHE_DEFAULT, NULL);
        wcsncpy(g_bdCacheDir, BD_CACHE_DEFAULT, MAX_PATH - 1);
        g_bdCacheDir[MAX_PATH - 1] = 0;

        /* 把新的缓存位置写回安装目录与注册表，供下次启动使用 */
        wchar_t cacheFile[MAX_PATH];
        swprintf(cacheFile, MAX_PATH, L"%s\\%s", g_bdInstallDir, BD_CACHE_PATH_NAME);
        write_path_file(cacheFile, g_bdCacheDir);
        write_cache_to_registry(g_bdCacheDir);
    }
}

void bd_set_install_dir(const wchar_t* dir)
{
    wcsncpy(g_bdInstallDir, dir, MAX_PATH - 1);
    g_bdInstallDir[MAX_PATH - 1] = 0;
    normalize_path(g_bdInstallDir);
}

void bd_set_cache_dir(const wchar_t* dir)
{
    wcsncpy(g_bdCacheDir, dir, MAX_PATH - 1);
    g_bdCacheDir[MAX_PATH - 1] = 0;
    normalize_path(g_bdCacheDir);

    /* 保证目录存在，再写记录文件与注册表备份 */
    SHCreateDirectoryExW(NULL, g_bdCacheDir, NULL);
    wchar_t cacheFile[MAX_PATH];
    swprintf(cacheFile, MAX_PATH, L"%s\\%s", g_bdInstallDir, BD_CACHE_PATH_NAME);
    write_path_file(cacheFile, g_bdCacheDir);
    write_cache_to_registry(g_bdCacheDir);
}
