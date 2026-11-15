/* 安装目录与缓存目录策略
 *
 * 安装目录：即程序自身所在目录（安装器会把文件释放到那里）。
 * 缓存目录：默认 C:\BDtemp，可在安装时更改，位置记录在
 *           安装目录内的 BDCachePath.txt。
 *           启动时发现缓存目录不存在，自动回退到 C:\BDtemp。
 *
 * bd_cache_root() / bd_cache_path() 返回线程本地静态缓冲：
 * 勿在同一表达式中多次调用，也不要长期保存返回值。
 */
#ifndef BD_PATHS_H
#define BD_PATHS_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <wchar.h>

#define BD_INSTALL_DEFAULT L"C:\\Program Files\\BDApp"
#define BD_CACHE_DEFAULT   L"C:\\BDtemp"
/* 缓存位置记录文件名（放在安装目录内） */
#define BD_CACHE_PATH_NAME L"BDCachePath.txt"
/* 缓存位置的注册表备份：安装目录内文件被误删时仍能恢复用户的选择 */
#define BD_PATHS_REG_KEY   L"SOFTWARE\\XDH\\BDProtect"
#define BD_PATHS_REG_VALUE L"CacheDir"

extern wchar_t g_bdInstallDir[MAX_PATH];
extern wchar_t g_bdCacheDir[MAX_PATH];

/* 读取缓存目录记录（安装目录 = 程序所在目录）；必须在任何路径使用前调用 */
void bd_paths_init(void);
/* 设置并持久化安装目录（写入其下的 BDCachePath.txt） */
void bd_set_install_dir(const wchar_t* dir);
/* 设置并持久化缓存目录（创建目录并写 BDCachePath.txt） */
void bd_set_cache_dir(const wchar_t* dir);
/* 缓存目录不存在时回退到默认位置 */
void bd_fallback_cache_if_missing(void);

/* 缓存目录本身，如 D:\BDtemp */
const wchar_t* bd_cache_root(void);
/* 缓存目录下的文件/子目录完整路径 */
const wchar_t* bd_cache_path(const wchar_t* name);

#endif
