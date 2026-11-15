#include "bd_common.h"
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>
#include <wincrypt.h>

/* ============ 路径辅助 ============ */

void bd_get_app_dir(wchar_t* out, int cap)
{
    if (cap <= 0) return;
    GetModuleFileNameW(NULL, out, cap);
    wchar_t* slash = wcsrchr(out, L'\\');
    if (slash) *slash = 0;
}

void bd_get_app_file(const wchar_t* name, wchar_t* out, int cap)
{
    wchar_t dir[MAX_PATH];
    bd_get_app_dir(dir, MAX_PATH);
    swprintf(out, cap, L"%s\\%s", dir, name);
}

void bd_ensure_store_dir(void)
{
    /* SHCreateDirectoryExW 会自动创建所有缺失的父目录 */
    SHCreateDirectoryExW(NULL, BD_STORE_DIR, NULL);
}

/* 收紧目录权限：SYSTEM/Administrators 完全控制，普通用户只读。
   用于保存配置和 stop.flag 的目录，防止普通进程篡改后关闭防护。 */
void bd_harden_dir(const wchar_t* dir)
{
    if (!dir || !*dir) return;

    PSECURITY_DESCRIPTOR sd = NULL;
    /* D:P           受保护的 DACL
       (A;OICI;FA;;;SY)  SYSTEM 完全控制
       (A;OICI;FA;;;BA)  Administrators 完全控制
       (A;OICI;FR;;;BU)  Users 只读
       (A;OICI;FR;;;WD)  Everyone 只读（保证非域环境可读）  */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)(A;OICI;FR;;;WD)",
            SDDL_REVISION_1, &sd, NULL))
        return;

    PACL dacl = NULL;
    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    if (GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) && daclPresent) {
        SetNamedSecurityInfoW((LPWSTR)dir, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                              NULL, NULL, dacl, NULL);
    }
    LocalFree(sd);
}

void bd_ensure_state_dir(void)
{
    SHCreateDirectoryExW(NULL, BD_STATE_DIR, NULL);
    bd_harden_dir(BD_STATE_DIR);

    /* 从旧位置迁移配置（仅当新位置还没有配置时） */
    if (GetFileAttributesW(BD_CONFIG_FILE) == INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesW(BD_OLD_CONFIG_FILE) != INVALID_FILE_ATTRIBUTES) {
        CopyFileW(BD_OLD_CONFIG_FILE, BD_CONFIG_FILE, FALSE);
    }
}

/* ============ 文件哈希（MD5） ============ */

BOOL bd_is_hex32(const wchar_t* s)
{
    if (!s || wcslen(s) != 32) return FALSE;
    for (int i = 0; i < 32; i++) {
        wchar_t c = s[i];
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')))
            return FALSE;
    }
    return TRUE;
}

/* ---- 自带 MD5 实现 ----
   不再依赖 CryptoAPI：部分系统上 CryptAcquireContext/CryptCreateHash
   会失败（FIPS 策略、增强型密钥提供程序、精简版系统、服务被禁用等），
   导致哈希永远算不出来。自带实现没有任何外部依赖。 */
typedef struct {
    unsigned int state[4];
    unsigned long long count;
    unsigned char buf[64];
} MD5_CTX;

static unsigned int md5_rotl(unsigned int x, int c)
{
    return (x << c) | (x >> (32 - c));
}

static void md5_transform(unsigned int state[4], const unsigned char block[64])
{
    static const unsigned int K[64] = {
        0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,
        0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
        0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,
        0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
        0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,
        0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
        0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,
        0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
        0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,
        0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
        0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,
        0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
        0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,
        0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
        0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,
        0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
    };
    static const int S[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3];
    for (int i = 0; i < 64; i++) {
        unsigned int f;
        int g;
        if (i < 16)      { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;          g = (3 * i + 5) & 15; }
        else             { f = c ^ (b | ~d);       g = (7 * i) & 15; }
        unsigned int w = (unsigned int)block[g*4]
                       | ((unsigned int)block[g*4+1] << 8)
                       | ((unsigned int)block[g*4+2] << 16)
                       | ((unsigned int)block[g*4+3] << 24);
        unsigned int tmp = d;
        d = c;
        c = b;
        b = b + md5_rotl(a + f + K[i] + w, S[i]);
        a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5_init(MD5_CTX* ctx)
{
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xefcdab89u;
    ctx->state[2] = 0x98badcfeu;
    ctx->state[3] = 0x10325476u;
    ctx->count = 0;
}

static void md5_update(MD5_CTX* ctx, const unsigned char* data, size_t len)
{
    size_t used = (size_t)(ctx->count & 63);
    ctx->count += len;

    if (used) {
        size_t need = 64 - used;
        if (len < need) {
            memcpy(ctx->buf + used, data, len);
            return;
        }
        memcpy(ctx->buf + used, data, need);
        md5_transform(ctx->state, ctx->buf);
        data += need;
        len -= need;
    }
    while (len >= 64) {
        md5_transform(ctx->state, data);
        data += 64;
        len -= 64;
    }
    if (len) memcpy(ctx->buf, data, len);
}

static void md5_final(MD5_CTX* ctx, unsigned char digest[16])
{
    unsigned long long bits = ctx->count * 8;
    size_t used = (size_t)(ctx->count & 63);

    ctx->buf[used++] = 0x80;
    if (used > 56) {
        memset(ctx->buf + used, 0, 64 - used);
        md5_transform(ctx->state, ctx->buf);
        used = 0;
    }
    memset(ctx->buf + used, 0, 56 - used);
    for (int i = 0; i < 8; i++)
        ctx->buf[56 + i] = (unsigned char)(bits >> (8 * i));
    md5_transform(ctx->state, ctx->buf);

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            digest[i*4 + j] = (unsigned char)(ctx->state[i] >> (8 * j));
}

/* 打开文件用于读取：普通打开失败时，启用备份权限再试一次
   （有些系统文件/被其他进程占用的文件只允许这样做） */
static HANDLE open_for_read(const wchar_t* path, DWORD* err1, DWORD* err2)
{
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    HANDLE h = CreateFileW(path, GENERIC_READ, share, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h != INVALID_HANDLE_VALUE) return h;

    *err1 = GetLastError();

    /* 超长路径：加 \\?\ 前缀再试 */
    wchar_t longPath[MAX_PATH * 2] = {0};
    BOOL haveLong = FALSE;
    if (wcslen(path) >= MAX_PATH - 12 && path[1] == L':') {
        swprintf(longPath, MAX_PATH * 2, L"\\\\?\\%s", path);
        haveLong = TRUE;
        h = CreateFileW(longPath, GENERIC_READ, share, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
    }

    /* 被占用 / 权限不足：申请 SeBackupPrivilege 后用备份语义打开 */
    bd_enable_privilege(SE_BACKUP_NAME);
    DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS;
    h = CreateFileW(path, GENERIC_READ, share, NULL, OPEN_EXISTING, flags, NULL);
    if (h == INVALID_HANDLE_VALUE && haveLong)
        h = CreateFileW(longPath, GENERIC_READ, share, NULL, OPEN_EXISTING, flags, NULL);
    *err2 = GetLastError();
    return h;
}

/* 计算失败时最多尝试的次数。文件刚被写入/杀毒软件占用时，
   稍等再算往往就成功了，所以重试而不是立刻报失败。 */
#define MD5_MAX_ATTEMPTS 3
#define MD5_RETRY_DELAY  150   /* 毫秒 */

BOOL bd_file_md5(const wchar_t* path, wchar_t* out, int cap)
{
    if (out && cap > 0) out[0] = 0;
    if (!path || !out || cap < 33) return FALSE;

    DWORD lastErr1 = 0, lastErr2 = 0, lastReadErr = 0;
    unsigned long long lastBytes = 0;
    BOOL openFailed = FALSE;

    for (int attempt = 1; attempt <= MD5_MAX_ATTEMPTS; attempt++) {
        DWORD err1 = 0, err2 = 0;
        HANDLE h = open_for_read(path, &err1, &err2);
        if (h == INVALID_HANDLE_VALUE) {
            lastErr1 = err1; lastErr2 = err2; openFailed = TRUE;
        } else {
            openFailed = FALSE;
            MD5_CTX ctx;
            md5_init(&ctx);

            BYTE buf[65536];
            DWORD read = 0;
            BOOL ok = TRUE;
            DWORD rerr = 0;
            for (;;) {
                if (!ReadFile(h, buf, sizeof(buf), &read, NULL)) { rerr = GetLastError(); ok = FALSE; break; }
                if (read == 0) break;
                md5_update(&ctx, buf, read);
            }
            CloseHandle(h);

            if (ok) {
                unsigned char digest[16];
                md5_final(&ctx, digest);
                for (int i = 0; i < 16; i++)
                    swprintf(out + i * 2, cap - i * 2, L"%02x", digest[i]);
                out[32] = 0;
                if (attempt > 1)
                    bd_log(L"[MD5] 第 %d 次尝试成功: %s", attempt, path);
                return TRUE;
            }
            lastReadErr = rerr;
            lastBytes = ctx.count;
        }

        /* 文件在两次尝试之间被删除：没有重试的必要 */
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) break;
        if (attempt < MD5_MAX_ATTEMPTS) Sleep(MD5_RETRY_DELAY);
    }

    /* 三次都失败才记录失败日志，调用方据此提示“计算失败” */
    if (openFailed)
        bd_log(L"[MD5] 计算失败(%d 次): 打不开文件: %s (err=%lu, 重试 err=%lu)",
               MD5_MAX_ATTEMPTS, path, lastErr1, lastErr2);
    else
        bd_log(L"[MD5] 计算失败(%d 次): 读取失败: %s (已读 %llu 字节, err=%lu)",
               MD5_MAX_ATTEMPTS, path, lastBytes, lastReadErr);
    return FALSE;
}

/* 判断路径是否属于本软件自身（安装目录下的程序），
   网络防护/文件防护都不应该拦截自己 */
BOOL bd_is_own_app_path(const wchar_t* path)
{
    if (!path || !path[0]) return FALSE;
    wchar_t dir[MAX_PATH];
    bd_get_app_dir(dir, MAX_PATH);
    size_t n = wcslen(dir);
    if (n == 0) return FALSE;
    if (_wcsnicmp(path, dir, n) != 0) return FALSE;
    return (path[n] == L'\\' || path[n] == 0);
}

/* 判断路径是否属于本软件自己的目录（安装目录或缓存目录）。
   病毒库扫描、文件防护都必须放行：
   缓存目录里有我们自己备份的“病毒文件副本”（FileBackup），
   以及日志、快照、病毒库等数据，检测它们只会制造误报弹窗。 */
BOOL bd_is_own_path(const wchar_t* path)
{
    if (!path || !path[0]) return FALSE;
    if (bd_is_own_app_path(path)) return TRUE;

    const wchar_t* dirs[2];
    int n = 0;
    dirs[n++] = g_bdCacheDir;
    if (_wcsicmp(g_bdCacheDir, BD_CACHE_DEFAULT) != 0)
        dirs[n++] = BD_CACHE_DEFAULT;   /* 旧的默认缓存位置也一并放行 */

    for (int i = 0; i < n; i++) {
        size_t len = wcslen(dirs[i]);
        if (len >= 3 && _wcsnicmp(path, dirs[i], len) == 0 &&
            (path[len] == L'\\' || path[len] == 0))
            return TRUE;
    }
    return FALSE;
}

/* ============ 拦截记录 ============ */

static CRITICAL_SECTION g_rec_cs;
static volatile LONG g_rec_inited = 0;

static void rec_init(void)
{
    if (InterlockedCompareExchange(&g_rec_inited, 1, 0) == 0)
        InitializeCriticalSection(&g_rec_cs);
}

/* 记录文件超过 5MB 时只保留最近 2000 行，避免无限增长 */
#define RECORDS_MAX_BYTES (5 * 1024 * 1024)
#define RECORDS_KEEP_LINES 2000

static void trim_records(void)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(BD_RECORDS_FILE, GetFileExInfoStandard, &fad)) return;
    unsigned long long size = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (size < RECORDS_MAX_BYTES) return;

    FILE* f = _wfopen(BD_RECORDS_FILE, L"r, ccs=UTF-8");
    if (!f) return;

    wchar_t** keep = (wchar_t**)calloc(RECORDS_KEEP_LINES, sizeof(wchar_t*));
    if (!keep) { fclose(f); return; }
    int n = 0;
    wchar_t* line = (wchar_t*)malloc(8192 * sizeof(wchar_t));
    if (!line) { free(keep); fclose(f); return; }

    while (fgetws(line, 8192, f)) {
        if (n < RECORDS_KEEP_LINES) {
            size_t l = wcslen(line);
            keep[n] = (wchar_t*)malloc((l + 1) * sizeof(wchar_t));
            if (keep[n]) { wcscpy(keep[n], line); n++; }
        } else {
            /* 环形覆盖：丢掉最旧的一行 */
            free(keep[0]);
            memmove(keep, keep + 1, sizeof(wchar_t*) * (RECORDS_KEEP_LINES - 1));
            size_t l = wcslen(line);
            keep[RECORDS_KEEP_LINES - 1] = (wchar_t*)malloc((l + 1) * sizeof(wchar_t));
            if (keep[RECORDS_KEEP_LINES - 1]) wcscpy(keep[RECORDS_KEEP_LINES - 1], line);
        }
    }
    fclose(f);
    free(line);

    FILE* w = _wfopen(BD_RECORDS_FILE, L"w, ccs=UTF-8");
    if (w) {
        for (int i = 0; i < n; i++) fputws(keep[i], w);
        fclose(w);
    }
    for (int i = 0; i < n; i++) free(keep[i]);
    free(keep);
}

void bd_record_add(const wchar_t* type, const wchar_t* target, const wchar_t* choice)
{
    rec_init();
    if (!type) type = L"";
    if (!target) target = L"";
    if (!choice) choice = L"";

    /* 清理字段中的制表符/换行，避免破坏记录格式 */
    wchar_t t[64], tg[MAX_PATH], c[64];
    wcsncpy(t, type, 63); t[63] = 0;
    wcsncpy(tg, target, MAX_PATH - 1); tg[MAX_PATH - 1] = 0;
    wcsncpy(c, choice, 63); c[63] = 0;
    for (int i = 0; t[i]; i++) if (t[i] == L'\t' || t[i] == L'\r' || t[i] == L'\n') t[i] = L' ';
    for (int i = 0; tg[i]; i++) if (tg[i] == L'\t' || tg[i] == L'\r' || tg[i] == L'\n') tg[i] = L' ';
    for (int i = 0; c[i]; i++) if (c[i] == L'\t' || c[i] == L'\r' || c[i] == L'\n') c[i] = L' ';

    SYSTEMTIME st;
    GetLocalTime(&st);

    EnterCriticalSection(&g_rec_cs);
    trim_records();
    FILE* f = _wfopen(BD_RECORDS_FILE, L"a, ccs=UTF-8");
    if (f) {
        fwprintf(f, L"%04d-%02d-%02d %02d:%02d:%02d\t%s\t%s\t%s\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, t, tg, c);
        fclose(f);
    }
    LeaveCriticalSection(&g_rec_cs);
}

/* ============ 云端病毒库试用状态 ============ */

static int read_int_file(const wchar_t* path, int defVal)
{
    FILE* f = _wfopen(path, L"r, ccs=UTF-8");
    if (!f) return defVal;
    wchar_t line[64] = { 0 };
    int v = defVal;
    if (fgetws(line, 64, f)) v = _wtoi(line);
    fclose(f);
    return v;
}

static void write_int_file(const wchar_t* path, int v)
{
    bd_ensure_store_dir();
    FILE* f = _wfopen(path, L"w, ccs=UTF-8");
    if (f) { fwprintf(f, L"%d\n", v); fclose(f); }
}

int bd_cloud_get_minutes(void)
{
    if (GetFileAttributesW(BD_RESTRICTED) == INVALID_FILE_ATTRIBUTES) {
        write_int_file(BD_RESTRICTED, BD_TRIAL_MINUTES);
        return BD_TRIAL_MINUTES;
    }
    return read_int_file(BD_RESTRICTED, 0);
}

void bd_cloud_set_minutes(int minutes)
{
    if (minutes < 0) minutes = 0;
    write_int_file(BD_RESTRICTED, minutes);
}

int bd_cloud_get_userup(void)
{
    if (GetFileAttributesW(BD_USERUP) == INVALID_FILE_ATTRIBUTES) {
        write_int_file(BD_USERUP, 0);
        return 0;
    }
    return read_int_file(BD_USERUP, 0);
}

void bd_cloud_inc_userup(void)
{
    int v = bd_cloud_get_userup() + 1;
    write_int_file(BD_USERUP, v);
}

BOOL bd_cloud_is_unlocked(void)
{
    return bd_cloud_get_userup() >= BD_UNLOCK_SAMPLES;
}

BOOL bd_cloud_expired(void)
{
    return !bd_cloud_is_unlocked() && bd_cloud_get_minutes() <= 0;
}
