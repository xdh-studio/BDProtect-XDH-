# BDProtect 服务器使用说明

## 启动

```bash
php server.php            # 默认监听 28586
php server.php 28586      # 指定端口
```

要求 PHP 5.3 及以上（已在 PHP 5.x 上做过语法兼容，不使用 `??`、`random_bytes` 等 PHP 7 才有的特性；
PHP 5.6 以下没有 `hash_equals` / `random_bytes` 时程序会自动使用内置兼容实现）。

客户端（控制中心）通过 `IPconfig.ini` 中的 `server_ip` / `server_port` 连接。
如果使用 `back1.idcfengye.com:28586` 这类内网穿透，把穿透目标指向本机的 28586 端口即可。

## data 目录

| 文件 | 用途 |
| --- | --- |
| `BDProtectVersion.txt` | 最新主程序版本信息（Version / Build / Author） |
| `BDProtectSetup.exe` | 最新安装包（自动升级时下载运行） |
| `Wildlist.txt` | 病毒库（`文件大小 [MD5] 病毒名`；有 MD5 时按“大小 + 哈希”双重校验） |
| `WildlistVersion.txt` | 病毒库版本，内容有变化客户端就会拉取 Wildlist.txt |
| `PracticalToolbox.txt` | 实用工具箱列表（`名称 描述 文件名`） |
| `uninstall1.exe` 等 | 工具箱按需下载的实际程序 |
| `samples/` | 客户端提交的病毒样本，`index.tsv` 记录时间/大小/名称（索引丢失时会按目录中的 `.bin` 文件补全） |

权限要求：`data/admin_password.txt` 保存明文密码，建议只允许服务器运行用户读取（如 `chmod 600`，
程序在创建/修改密码时也会自动设为 0600）。

## 发布新版本

1. 编译新的 `setup.exe`，重命名为 `BDProtectSetup.exe` 放进 `data/`。
2. 修改 `data/BDProtectVersion.txt`，把 `Version:` 改成新版本号。
3. 修改 `data/Wildlist.txt` 后，务必同时修改 `data/WildlistVersion.txt`（任意不同内容即可触发更新）。

## 协议

```
read <文件名>          ->  OK <字节数>\n + 文件内容 / ERR notfound\n
up "<样本名>" <字节数>  ->  命令后紧跟原始文件内容，返回 OK\n
list                  ->  列出 data 目录可下载文件
```

管理程序（管理程序/BDAdmin.exe）使用挑战-应答认证，**密码本身不在网络上传输**：

```
客户端 -> hello
服务器 -> OK <32 位十六进制随机数>           （15 秒内必须完成下一步）
客户端 -> admin <随机数> <证明> <子命令> [参数...]
          证明 = sha256(随机数 + 密码) 的小写十六进制
```

认证失败按来源 IP 限流：10 分钟内最多 5 次，超限返回 `ERR ratelimit`。

```
admin <随机数> <证明> check                                     ->  OK / ERR auth
admin <随机数> <证明> setpwd "<新密码>"                          ->  OK
admin <随机数> <证明> samples                                   ->  OK\n + "样本名\t大小\t时间\n"
admin <随机数> <证明> getsample "<样本名>"                       ->  OK <字节数>\n + 内容
admin <随机数> <证明> delsample "<样本名>"                       ->  OK（删除样本文件及记录）
admin <随机数> <证明> addvirus <大小> "<病毒名>" ["<样本名>"]
                                                                ->  OK（追加到 Wildlist.txt；
                                                                    提供样本名时自动写入该样本的 MD5）
admin <随机数> <证明> delvirus <大小> "<病毒名>"                 ->  OK
admin <随机数> <证明> editvirus <旧大小> "<旧名>" <新大小> "<新名>" ["<哈希>"]
                                                                ->  OK / ERR notfound
admin <随机数> <证明> pubwild "<版本>" "<日期>" "<说明>"          ->  OK（写 WildlistVersion.txt；版本必须是 a.b.c）
admin <随机数> <证明> pubapp <字节数> "<版本>" "<日期>" "<说明>" + 原始内容
                                                                ->  OK（写 BDProtectSetup.exe 与 BDProtectVersion.txt；
                                                                    先写临时文件再改名，上传中断不会破坏线上包）
admin <随机数> <证明> settools <字节数> + UTF-8 文本           ->  OK（写 PracticalToolbox.txt）
                                                                    每行格式：名称 说明 文件名.exe
admin <随机数> <证明> puttool <字节数> "<文件名>" + 原始内容     ->  OK（写 data/<文件名>，用于新增工具程序）
```

## 实用工具箱管理

管理程序主界面点击「工具箱管理」即可：

- **添加工具**：填写名称/说明/程序文件名，可同时选择本地 exe 上传到服务器；保存后客户端下次启动即可看到。
- **修改选中**：改名称、说明、程序文件名，也可重新选择一个本地 exe 覆盖上传。
- **删除选中**：从列表中移除（服务器上的程序文件保留）。
- **上移 / 下移**：调整客户端显示顺序。
- 所有修改会立即写回服务器 `data/PracticalToolbox.txt`，无需手动发布。
- 工具名称和文件名不能含空格；说明可以含空格；条目必须指向 `.exe`，不能指向本体程序。

## 批量上传程序（批量上传程序/BatchUpload.exe）

用于把某个文件夹里所有文件的特征（大小、MD5、名称）一次性写入云端病毒库：

1. 启动后输入管理密码（与 BDAdmin 相同，服务器 `data/admin_password.txt`）。
2. 选择文件夹，可勾选「包含子文件夹」。
3. 点「扫描文件夹」：程序计算每个文件的 MD5，并与云端 `Wildlist.txt` 对比，
   在列表中标记 **新增 / 新增（云端有同大小条目）/ 重复：云端已有 / 重复：本文件夹内已有**。
4. 点「上传新增特征」：确认后逐条写入云端病毒库。程序只使用服务器**已有**的管理命令
   （`addvirus` 写“大小+名称”，再用 `editvirus` 补上 MD5），**不需要修改/重新部署 server.php**。
   上传完成后会重新读取 `Wildlist.txt` 核对 MD5 是否真的写入。
5. 默认勾选「上传后自动发布新病毒库版本」：上传成功后把 `WildlistVersion.txt` 版本号升一位并发布，
   客户端下次启动才会自动拉取新病毒库；不勾选则需到管理程序里手动发布。

> 每条约需 2 次请求（addvirus + editvirus），文件很多时上传耗时较长，界面有进度提示。
> 若上传后提示“云端找不到对应 MD5”，说明服务器上的 `server.php` 过旧、`editvirus` 不支持哈希参数。

也支持 HTTP 方式：
`GET server.php?read=Wildlist.txt`，`POST server.php?up=SampleName`。
