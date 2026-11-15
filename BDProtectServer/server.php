<?php
/**
 * BDProtect 升级 / 病毒库 / 样本提交服务器
 *
 * 运行方式（TCP 模式，默认监听 28586）：
 *     php server.php
 *     php server.php 28586
 *
 * 客户端协议（纯 TCP，一行命令 + 换行）：
 *     read <文件名>          ->  "OK <字节数>\n" + 文件原始内容
 *                               失败时返回 "ERR notfound\n"
 *     up "<样本名>" <字节数>  ->  命令后紧跟 <字节数> 字节的原始文件内容
 *                               成功时返回 "OK\n"
 *     list                   ->  列出 data 目录下可下载的文件
 *
 * 管理程序协议（挑战-应答认证，密码本身不在网络上传输）：
 *     1. 客户端发送  hello
 *        服务器返回  OK <32 位十六进制随机数>      （15 秒内必须完成认证）
 *     2. 客户端发送  admin <随机数> <证明> <子命令> [参数...]
 *        其中 <证明> = sha256(随机数 + 密码) 的小写十六进制
 *
 *     admin <随机数> <证明> check                             ->  OK / ERR auth
 *     admin <随机数> <证明> setpwd "<新密码>"                  ->  OK
 *     admin <随机数> <证明> samples                           ->  OK\n + 多行 "样本名\t大小\t时间\n"
 *     admin <随机数> <证明> getsample "<样本名>"               ->  OK <字节数>\n + 原始内容
 *     admin <随机数> <证明> delsample "<样本名>"               ->  OK
 *     admin <随机数> <证明> addvirus <大小> "<病毒名>" ["<样本名>"]
 *                                                            ->  OK（提供样本名时自动写入 MD5 哈希）
 *     admin <随机数> <证明> delvirus <大小> "<病毒名>"          ->  OK
 *     admin <随机数> <证明> editvirus <旧大小> "<旧名>" <新大小> "<新名>" ["<哈希>"]
 *                                                            ->  OK / ERR notfound
 *     admin <随机数> <证明> pubwild "<版本>" "<日期>" "<说明>"   ->  OK（写 WildlistVersion.txt）
 *     admin <随机数> <证明> pubapp <字节数> "<版本>" "<日期>" "<说明>" + 原始内容
 *                                                            ->  OK（写 BDProtectSetup.exe 与 BDProtectVersion.txt）
 *     admin <随机数> <证明> settools <字节数> + 原始内容（UTF-8 文本） ->  OK（写 PracticalToolbox.txt）
 *     admin <随机数> <证明> puttool <字节数> "<文件名>" + 原始内容 ->  OK（写 data/<文件名>，用于新增工具程序）
 *
 * 认证失败按来源 IP 限流：10 分钟内最多 5 次，超限返回 ERR ratelimit。
 * 管理密码保存在 data/admin_password.txt，不存在时自动创建为 "admin"。
 *
 * 同一个文件也支持 HTTP 访问（当部署在 Web 服务器上时）：
 *     GET  server.php?read=Wildlist.txt
 *     POST server.php?up=SampleName      （请求体为样本原始内容）
 *
 * 注意：文件均存放在 server/data/ 目录，样本存放在 server/data/samples/。
 */

define('DATA_DIR', __DIR__ . '/data');
define('SAMPLE_DIR', DATA_DIR . '/samples');
define('DEFAULT_PORT', 28586);
define('ADMIN_PWD_FILE', DATA_DIR . '/admin_password.txt');
define('WILDLIST_FILE', DATA_DIR . '/Wildlist.txt');
define('ADMIN_FAIL_FILE', DATA_DIR . '/admin_fail.json');

/* 密码错误限流：10 分钟内最多 5 次 */
define('ADMIN_MAX_FAILS', 5);
define('ADMIN_FAIL_WINDOW', 600);
/* 认证挑战的有效期（秒）：hello 之后必须在此时限内完成认证 */
define('ADMIN_NONCE_TTL', 15);

/* 样本大小限制：必须大于 3KB 且小于 500MB（与客户端一致） */
define('SAMPLE_MIN_SIZE', 3 * 1024);
define('SAMPLE_MAX_SIZE', 500 * 1024 * 1024);

/* ---------------- 通用辅助 ---------------- */

function ensure_dirs()
{
    if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0775, true);
    if (!is_dir(SAMPLE_DIR)) @mkdir(SAMPLE_DIR, 0775, true);
}

/**
 * 规范化请求的文件名，阻止目录穿越。
 * 支持省略 .exe 后缀（例如 read uninstall1）。
 */
function resolve_download_name($name)
{
    $name = trim($name, " \t\r\n\"'");
    $name = basename(str_replace('\\', '/', $name));
    if ($name === '' || $name === '.' || $name === '..') return null;

    $direct = DATA_DIR . '/' . $name;
    if (is_file($direct)) return $direct;

    if (strpos($name, '.') === false) {
        $withExe = DATA_DIR . '/' . $name . '.exe';
        if (is_file($withExe)) return $withExe;
    }
    return null;
}

function sanitize_sample_name($name)
{
    $name = trim($name, " \t\r\n\"'");
    $name = basename(str_replace('\\', '/', $name));
    $name = preg_replace('/[^\p{L}\p{N}._\- ]+/u', '_', $name);
    if (!is_string($name) || $name === '' || $name === '.' || $name === '..')
        $name = 'sample_' . time();
    return $name;
}

function send_all($sock, $data)
{
    $len = strlen($data);
    $sent = 0;
    while ($sent < $len) {
        $n = @fwrite($sock, substr($data, $sent));
        if ($n === false || $n === 0) return false;
        $sent += $n;
    }
    return true;
}

function cmd_read($sock, $name)
{
    $path = resolve_download_name($name);
    if ($path === null) {
        send_all($sock, "ERR notfound\n");
        return;
    }
    $size = filesize($path);
    if (!send_all($sock, "OK {$size}\n")) return;

    $fp = fopen($path, 'rb');
    if (!$fp) return;
    while (!feof($fp)) {
        $chunk = fread($fp, 65536);
        if ($chunk === false || $chunk === '') break;
        if (!send_all($sock, $chunk)) break;
    }
    fclose($fp);
}

function cmd_upload($sock, $name, $size)
{
    /* 与客户端一致的大小限制：>3KB 且 <500MB。
       不符合时直接拒绝，不读取任何数据，防止恶意超大占用磁盘。 */
    if ($size <= SAMPLE_MIN_SIZE || $size >= SAMPLE_MAX_SIZE) {
        send_all($sock, "ERR size\n");
        return;
    }

    $name = sanitize_sample_name($name);
    $target = SAMPLE_DIR . '/' . $name . '.bin';

    $fp = fopen($target, 'wb');
    if (!$fp) { send_all($sock, "ERR storage\n"); return; }

    $remaining = $size;
    while ($remaining > 0) {
        $chunk = fread($sock, min(65536, $remaining));
        if ($chunk === false || $chunk === '') break;
        fwrite($fp, $chunk);
        $remaining -= strlen($chunk);
    }
    fclose($fp);

    /* 记录样本元信息，便于后台处理 */
    $meta = sprintf("%s\t%d\t%s\n", date('Y-m-d H:i:s'), $size, $name);
    @file_put_contents(SAMPLE_DIR . '/index.tsv', $meta, FILE_APPEND | LOCK_EX);

    if ($remaining === 0) send_all($sock, "OK\n");
    else send_all($sock, "ERR incomplete\n");
}

function cmd_list($sock)
{
    $entries = @scandir(DATA_DIR);
    $out = "OK\n";
    if ($entries) {
        foreach ($entries as $e) {
            if ($e === '.' || $e === '..' || $e === 'samples') continue;
            if (is_file(DATA_DIR . '/' . $e)) $out .= $e . "\t" . filesize(DATA_DIR . '/' . $e) . "\n";
        }
    }
    send_all($sock, $out);
}

/* ---------------- 管理程序命令 ---------------- */

/**
 * 读取管理密码；文件不存在或为空时自动创建为 "admin"。
 */
function admin_get_password()
{
    if (!is_file(ADMIN_PWD_FILE)) {
        @file_put_contents(ADMIN_PWD_FILE, "admin", LOCK_EX);
        @chmod(ADMIN_PWD_FILE, 0600);
        return 'admin';
    }
    $pwd = trim((string)@file_get_contents(ADMIN_PWD_FILE));
    if ($pwd === '') {
        $pwd = 'admin';
        @file_put_contents(ADMIN_PWD_FILE, $pwd, LOCK_EX);
        @chmod(ADMIN_PWD_FILE, 0600);
    }
    return $pwd;
}

/**
 * 把命令行拆成参数，支持 "带空格的参数"。
 */
function admin_tokenize($line)
{
    $tokens = array();
    if (preg_match_all('/"([^"]*)"|(\S+)/', $line, $m, PREG_SET_ORDER)) {
        foreach ($m as $mm) {
            /* 不用 ??，兼容 PHP 5.x 服务器 */
            $tokens[] = (isset($mm[0][0]) && $mm[0][0] === '"') ? (isset($mm[1]) ? $mm[1] : '') : $mm[2];
        }
    }
    return $tokens;
}

/**
 * 校验密码错误次数：同一 IP 在窗口期内错误过多则拒绝。
 * 返回 true 表示允许继续尝试。
 */
function admin_attempt_allowed($ip)
{
    $data = admin_load_fails();
    $now = time();
    $rec = isset($data[$ip]) ? $data[$ip] : array('count' => 0, 'first' => $now);
    if ($now - $rec['first'] > ADMIN_FAIL_WINDOW) {
        $rec = array('count' => 0, 'first' => $now);
    }
    return $rec['count'] < ADMIN_MAX_FAILS;
}

function admin_record_fail($ip)
{
    $data = admin_load_fails();
    $now = time();
    $rec = isset($data[$ip]) ? $data[$ip] : array('count' => 0, 'first' => $now);
    if ($now - $rec['first'] > ADMIN_FAIL_WINDOW) {
        $rec = array('count' => 0, 'first' => $now);
    }
    $rec['count']++;
    $data[$ip] = $rec;
    /* 清理过期记录，避免文件无限增长 */
    foreach ($data as $k => $v) {
        if ($now - $v['first'] > ADMIN_FAIL_WINDOW) unset($data[$k]);
    }
    @file_put_contents(ADMIN_FAIL_FILE, json_encode($data), LOCK_EX);
}

function admin_clear_fail($ip)
{
    $data = admin_load_fails();
    if (isset($data[$ip])) {
        unset($data[$ip]);
        @file_put_contents(ADMIN_FAIL_FILE, json_encode($data), LOCK_EX);
    }
}

function admin_load_fails()
{
    if (!is_file(ADMIN_FAIL_FILE)) return array();
    $raw = @file_get_contents(ADMIN_FAIL_FILE);
    if ($raw === false || $raw === '') return array();
    $data = json_decode($raw, true);
    return is_array($data) ? $data : array();
}

/* 随机数生成：兼容 PHP 5.x（random_bytes 是 PHP 7 才有的） */
function admin_random_nonce()
{
    if (function_exists('random_bytes')) {
        return bin2hex(random_bytes(16));
    }
    if (function_exists('openssl_random_pseudo_bytes')) {
        $b = openssl_random_pseudo_bytes(16);
        if (is_string($b) && strlen($b) === 16) return bin2hex($b);
    }
    $fp = @fopen('/dev/urandom', 'rb');
    if ($fp) {
        $b = fread($fp, 16);
        fclose($fp);
        if (is_string($b) && strlen($b) === 16) return bin2hex($b);
    }
    /* 最后兜底：仅用于拒绝服务防护性极低的场景，仍保证每次不同 */
    $out = '';
    for ($i = 0; $i < 16; $i++) $out .= sprintf('%02x', mt_rand(0, 255));
    return $out;
}

/* 常量时间比较，PHP 5.6 以下没有 hash_equals */
function admin_hash_equals($known, $given)
{
    if (function_exists('hash_equals')) return hash_equals($known, $given);
    if (!is_string($known) || !is_string($given) || strlen($known) !== strlen($given)) return false;
    $diff = 0;
    for ($i = 0; $i < strlen($known); $i++) $diff |= ord($known[$i]) ^ ord($given[$i]);
    return $diff === 0;
}

/* 认证证明：sha256(随机数 + 密码)，双方用同一算法，密码不在网络上传输 */
function admin_proof($nonce, $pwd)
{
    return hash('sha256', $nonce . $pwd);
}

/**
 * 解析 Wildlist.txt 的一行。支持两种格式：
 *     大小 病毒名
 *     大小 哈希32位 病毒名
 * 返回 array(size, hash, name) 或 null。
 */
function parse_wild_line($line)
{
    $line = trim($line);
    if ($line === '' || $line[0] === '#' || $line[0] === ';') return null;
    if (!preg_match('/^(\d+)(?:\s+([0-9a-fA-F]{32}))?\s+(.+)$/u', $line, $m)) return null;
    $hash = isset($m[2]) ? strtolower($m[2]) : '';
    return array($m[1], $hash, trim($m[3]));
}

/**
 * 原子更新 Wildlist.txt：在文件锁内读取、交给回调处理、写临时文件再改名。
 * 回调接收行数组，返回新行数组；返回 false 表示放弃写入。
 */
function wildlist_update($mutator)
{
    $fp = @fopen(WILDLIST_FILE, 'c+');
    if (!$fp) return false;
    if (!flock($fp, LOCK_EX)) { fclose($fp); return false; }
    $raw = stream_get_contents($fp);
    $lines = ($raw === false || $raw === '') ? array() : preg_split('/\r\n|\r|\n/', $raw);
    $result = $mutator($lines);
    if ($result === false) { flock($fp, LOCK_UN); fclose($fp); return false; }
    $out = implode("\n", $result);
    if ($out !== '' && substr($out, -1) !== "\n") $out .= "\n";
    $tmp = WILDLIST_FILE . '.tmp.' . getmypid();
    $written = (@file_put_contents($tmp, $out) !== false);
    /* Windows 上不能改名覆盖一个仍打开着的文件，必须先释放句柄再 rename */
    flock($fp, LOCK_UN);
    fclose($fp);
    $ok = $written && @rename($tmp, WILDLIST_FILE);
    if (!$ok) @unlink($tmp);
    return $ok;
}

/* 版本号必须是 a.b.c 形式的纯数字 */
function valid_version($v)
{
    return is_string($v) && preg_match('/^\d{1,4}\.\d{1,4}\.\d{1,4}$/', $v) === 1;
}

function cmd_admin($sock, $line, $nonce, $ip)
{
    $t = admin_tokenize($line);
    /* 格式：admin <随机数> <证明> <子命令> [参数...] */
    if (count($t) < 4 || !is_string($nonce) || $nonce === '') {
        send_all($sock, "ERR badcmd\n");
        return;
    }

    $nonceGiven = $t[1];
    $proof = strtolower($t[2]);
    $sub = strtolower($t[3]);
    $arg = array_slice($t, 4);

    if (!admin_hash_equals($nonce, $nonceGiven)) {
        send_all($sock, "ERR auth\n");
        return;
    }
    if (!admin_attempt_allowed($ip)) {
        send_all($sock, "ERR ratelimit\n");
        return;
    }

    $expected = admin_proof($nonce, admin_get_password());
    if (!admin_hash_equals($expected, $proof)) {
        admin_record_fail($ip);
        send_all($sock, "ERR auth\n");
        return;
    }
    admin_clear_fail($ip);

    switch ($sub) {
    case 'check':
        send_all($sock, "OK\n");
        return;

    case 'setpwd': {
        if (!isset($arg[0]) || $arg[0] === '' || strlen($arg[0]) > 200) { send_all($sock, "ERR badcmd\n"); return; }
        /* 密码按一行保存，不能含换行或回车 */
        if (strpbrk($arg[0], "\r\n") !== false) { send_all($sock, "ERR badcmd\n"); return; }
        $tmp = ADMIN_PWD_FILE . '.tmp';
        if (@file_put_contents($tmp, $arg[0], LOCK_EX) === false || !@rename($tmp, ADMIN_PWD_FILE)) {
            @unlink($tmp);
            send_all($sock, "ERR storage\n");
            return;
        }
        @chmod(ADMIN_PWD_FILE, 0600);
        send_all($sock, "OK\n");
        return;
    }

    case 'samples': {
        $out = "OK\n";
        $seen = array();
        $idx = SAMPLE_DIR . '/index.tsv';
        if (is_file($idx)) {
            $fp = fopen($idx, 'rb');
            if ($fp) {
                while (($l = fgets($fp)) !== false) {
                    $l = rtrim($l, "\r\n");
                    if ($l === '') continue;
                    /* index.tsv 格式: 时间\t大小\t样本名 */
                    $c = explode("\t", $l);
                    if (count($c) < 3) continue;
                    $time = $c[0]; $size = $c[1]; $name = $c[2];
                    $bin = SAMPLE_DIR . '/' . $name . '.bin';
                    if (!is_file($bin)) continue;   /* 已被删除的样本不再列出 */
                    $seen[$name] = true;
                    $out .= $name . "\t" . filesize($bin) . "\t" . $time . "\n";
                }
                fclose($fp);
            }
        }
        /* 兜底：index.tsv 丢失或写入失败时，直接根据样本文件补全列表，
           否则这些样本会永远无法在管理程序中看到 */
        $files = @scandir(SAMPLE_DIR);
        if ($files) {
            foreach ($files as $f) {
                if (substr($f, -4) !== '.bin') continue;
                $name = substr($f, 0, -4);
                if (isset($seen[$name])) continue;
                $bin = SAMPLE_DIR . '/' . $f;
                $out .= $name . "\t" . filesize($bin) . "\t" . date('Y-m-d H:i:s', filemtime($bin)) . "\n";
            }
        }
        send_all($sock, $out);
        return;
    }

    case 'getsample': {
        if (!isset($arg[0]) || $arg[0] === '') { send_all($sock, "ERR badcmd\n"); return; }
        $name = sanitize_sample_name($arg[0]);
        $path = SAMPLE_DIR . '/' . $name . '.bin';
        if (!is_file($path)) { send_all($sock, "ERR notfound\n"); return; }
        $size = filesize($path);
        if (!send_all($sock, "OK {$size}\n")) return;
        $fp = fopen($path, 'rb');
        if (!$fp) return;
        while (!feof($fp)) {
            $chunk = fread($fp, 65536);
            if ($chunk === false || $chunk === '') break;
            if (!send_all($sock, $chunk)) break;
        }
        fclose($fp);
        return;
    }

    case 'delsample': {
        if (!isset($arg[0]) || $arg[0] === '') { send_all($sock, "ERR badcmd\n"); return; }
        $name = sanitize_sample_name($arg[0]);
        @unlink(SAMPLE_DIR . '/' . $name . '.bin');
        /* 同步移除 index.tsv 中该样本的记录 */
        $idx = SAMPLE_DIR . '/index.tsv';
        if (is_file($idx)) {
            $lines = @file($idx, FILE_IGNORE_NEW_LINES);
            if ($lines !== false) {
                $keep = array();
                foreach ($lines as $l) {
                    if ($l === '') continue;
                    $c = explode("\t", $l);
                    if (count($c) >= 3 && $c[2] === $name) continue;
                    $keep[] = $l;
                }
                @file_put_contents($idx, $keep ? implode("\n", $keep) . "\n" : '');
            }
        }
        send_all($sock, "OK\n");
        return;
    }

    case 'addvirus': {
        if (count($arg) < 2 || !ctype_digit($arg[0]) || trim($arg[1]) === '') {
            send_all($sock, "ERR badcmd\n");
            return;
        }
        $size = $arg[0];
        $name = trim(preg_replace('/[\r\n]+/', ' ', $arg[1]));

        /* 可选第三个参数为服务器上的样本名：自动计算 MD5 写入病毒库，
           这样客户端可以“大小 + 哈希”双重校验，减少误报。 */
        $hash = '';
        if (isset($arg[2]) && $arg[2] !== '') {
            $sample = SAMPLE_DIR . '/' . sanitize_sample_name($arg[2]) . '.bin';
            if (is_file($sample)) {
                $h = @md5_file($sample);
                if ($h !== false) $hash = $h;
            }
        }

        $newLine = $size . ($hash !== '' ? ' ' . $hash : '') . ' ' . $name;
        $ok = wildlist_update(function ($lines) use ($newLine, $size, $name) {
            foreach ($lines as $l) {
                $p = parse_wild_line($l);
                if ($p && $p[0] === $size && $p[2] === $name) return $lines; /* 重复，不再追加 */
            }
            $lines[] = $newLine;
            return $lines;
        });
        if ($ok === false) { send_all($sock, "ERR storage\n"); return; }
        send_all($sock, "OK\n");
        return;
    }

    case 'delvirus':
    case 'editvirus': {
        $isEdit = ($sub === 'editvirus');
        if ((!$isEdit && count($arg) < 2) || ($isEdit && count($arg) < 4)) { send_all($sock, "ERR badcmd\n"); return; }
        if (!ctype_digit($arg[0]) || ($isEdit && !ctype_digit($arg[2]))) { send_all($sock, "ERR badcmd\n"); return; }

        $oldSize = $arg[0];
        $oldName = trim($arg[1]);
        $found = false;
        $ok = wildlist_update(function ($lines) use (&$found, $isEdit, $oldSize, $oldName, $arg) {
            $out = array();
            foreach ($lines as $l) {
                $p = parse_wild_line($l);
                if ($p && !$found && $p[0] === $oldSize && $p[2] === $oldName) {
                    $found = true;
                    if ($isEdit) {
                        $newSize = $arg[2];
                        $newName = trim(preg_replace('/[\r\n]+/', ' ', $arg[3]));
                        $newHash = isset($arg[4]) ? strtolower(trim($arg[4])) : '';
                        if ($newHash !== '' && !preg_match('/^[0-9a-f]{32}$/', $newHash)) $newHash = '';
                        $out[] = $newSize . ($newHash !== '' ? ' ' . $newHash : '') . ' ' . $newName;
                    }
                    continue;
                }
                $out[] = $l;
            }
            return $found ? $out : false;
        });
        if (!$found) { send_all($sock, "ERR notfound\n"); return; }
        if ($ok === false) { send_all($sock, "ERR storage\n"); return; }
        send_all($sock, "OK\n");
        return;
    }

    case 'pubwild': {
        if (count($arg) < 3) { send_all($sock, "ERR badcmd\n"); return; }
        if (!valid_version($arg[0])) { send_all($sock, "ERR badcmd\n"); return; }
        $content = "Version: {$arg[0]}\nBuild: {$arg[1]}\nAuthor: {$arg[2]}\n";
        $tmp = DATA_DIR . '/WildlistVersion.txt.tmp';
        if (@file_put_contents($tmp, $content) === false || !@rename($tmp, DATA_DIR . '/WildlistVersion.txt')) {
            @unlink($tmp);
            send_all($sock, "ERR storage\n");
            return;
        }
        send_all($sock, "OK\n");
        return;
    }

    case 'settools': {
        if (!isset($arg[0]) || !ctype_digit($arg[0])) { send_all($sock, "ERR badcmd\n"); return; }
        $size = (int)$arg[0];
        if ($size < 0 || $size > 1048576) { send_all($sock, "ERR badcmd\n"); return; }

        $body = '';
        $remaining = $size;
        while ($remaining > 0) {
            $chunk = fread($sock, min(65536, $remaining));
            if ($chunk === false || $chunk === '') break;
            $body .= $chunk;
            $remaining -= strlen($chunk);
        }
        if ($remaining !== 0) { send_all($sock, "ERR incomplete\n"); return; }

        /* 重新校验每一行：名称 说明 文件名；名称/文件名不允许空格，
           且工具程序必须是 .exe、不能指向本体文件 */
        $reserved = array('bdprotect.exe', 'bdmain.exe', 'uninstall.exe', 'bdprotectsetup.exe');
        $out = '';
        foreach (preg_split('/\r\n|\r|\n/', $body) as $l) {
            $l = trim($l);
            if ($l === '') continue;
            if ($l[0] === '#') { $out .= $l . "\n"; continue; }
            if (!preg_match('/^(\S+)\s+(.+?)\s+(\S+)$/u', $l, $mm)) continue;
            $exe = strtolower(basename(str_replace('\\', '/', $mm[3])));
            if (substr($exe, -4) !== '.exe') continue;
            if (in_array($exe, $reserved, true)) continue;
            $out .= $mm[1] . ' ' . trim($mm[2]) . ' ' . $mm[3] . "\n";
        }
        if (trim($out) === '' || trim(preg_replace('/^#.*$/m', '', $out)) === '') {
            /* 空工具箱也要写一行注释，保证文件非空 */
            $out = "# 工具箱为空\n";
        }

        $tmp = DATA_DIR . '/PracticalToolbox.txt.tmp';
        if (@file_put_contents($tmp, $out) === false) { send_all($sock, "ERR storage\n"); return; }
        if (!@rename($tmp, DATA_DIR . '/PracticalToolbox.txt')) {
            @unlink($tmp);
            send_all($sock, "ERR storage\n");
            return;
        }
        send_all($sock, "OK\n");
        return;
    }

    case 'puttool': {
        if (count($arg) < 2 || !ctype_digit($arg[0])) { send_all($sock, "ERR badcmd\n"); return; }
        $size = (int)$arg[0];
        if ($size <= 0 || $size > 512 * 1024 * 1024) { send_all($sock, "ERR badcmd\n"); return; }

        /* 只允许安全的 ASCII 文件名，且不能覆盖本体程序 */
        $name = basename(str_replace('\\', '/', $arg[1]));
        $name = preg_replace('/[^A-Za-z0-9._\-]+/', '_', $name);
        if ($name === '' || $name === '.' || $name === '..') $name = 'tool_' . time() . '.exe';
        if (!preg_match('/\.exe$/i', $name)) $name .= '.exe';
        $reserved = array('bdprotect.exe', 'bdmain.exe', 'uninstall.exe',
                          'bdprotectsetup.exe', 'wildlist.txt', 'wildlistversion.txt',
                          'practicaltoolbox.txt', 'bdprotectversion.txt');
        if (in_array(strtolower($name), $reserved, true)) $name = 'tool_' . $name;

        $target = DATA_DIR . '/' . $name;
        $fp = fopen($target, 'wb');
        if (!$fp) { send_all($sock, "ERR storage\n"); return; }
        $remaining = $size;
        while ($remaining > 0) {
            $chunk = fread($sock, min(65536, $remaining));
            if ($chunk === false || $chunk === '') break;
            fwrite($fp, $chunk);
            $remaining -= strlen($chunk);
        }
        fclose($fp);
        if ($remaining !== 0) { @unlink($target); send_all($sock, "ERR incomplete\n"); return; }
        send_all($sock, "OK\n");
        return;
    }

    case 'pubapp': {
        if (count($arg) < 4 || !ctype_digit($arg[0])) { send_all($sock, "ERR badcmd\n"); return; }
        if (!valid_version($arg[1])) { send_all($sock, "ERR badcmd\n"); return; }
        $size = (int)$arg[0];
        if ($size <= 0) { send_all($sock, "ERR badcmd\n"); return; }

        /* 先写临时文件，完整接收并校验后再改名：
           上传中断时不会留下半个安装包覆盖线上版本。 */
        $tmp = DATA_DIR . '/BDProtectSetup.exe.uploading';
        $target = DATA_DIR . '/BDProtectSetup.exe';
        $fp = @fopen($tmp, 'wb');
        if (!$fp) { send_all($sock, "ERR storage\n"); return; }
        $remaining = $size;
        while ($remaining > 0) {
            $chunk = fread($sock, min(65536, $remaining));
            if ($chunk === false || $chunk === '') break;
            fwrite($fp, $chunk);
            $remaining -= strlen($chunk);
        }
        fclose($fp);
        if ($remaining !== 0) { @unlink($tmp); send_all($sock, "ERR incomplete\n"); return; }
        if (!@rename($tmp, $target)) {
            @unlink($tmp);
            send_all($sock, "ERR storage\n");
            return;
        }
        $content = "Version: {$arg[1]}\nBuild: {$arg[2]}\nAuthor: {$arg[3]}\n";
        $vtmp = DATA_DIR . '/BDProtectVersion.txt.tmp';
        if (@file_put_contents($vtmp, $content) === false || !@rename($vtmp, DATA_DIR . '/BDProtectVersion.txt')) {
            @unlink($vtmp);
            send_all($sock, "ERR storage\n");
            return;
        }
        send_all($sock, "OK\n");
        return;
    }
    }

    send_all($sock, "ERR unknown\n");
}

/* ---------------- TCP 服务 ---------------- */

function client_ip($client)
{
    $name = @stream_socket_get_name($client, true);
    if ($name === false) return 'unknown';
    $pos = strrpos($name, ':');
    return $pos === false ? $name : substr($name, 0, $pos);
}

function handle_client($client)
{
    $ip = client_ip($client);
    $nonce = null;
    $nonceAt = 0;

    while (true) {
        stream_set_timeout($client, $nonce === null ? 30 : ADMIN_NONCE_TTL);
        $line = fgets($client, 4096);
        if ($line === false) break;
        $line = rtrim($line, "\r\n");
        if ($line === '') break;

        /* 认证握手：hello 返回一次性随机数，同一条连接上随后发 admin 命令。
           密码本身不上网，只发送 sha256(随机数 + 密码)。 */
        if (preg_match('/^hello$/i', $line)) {
            $nonce = admin_random_nonce();
            $nonceAt = time();
            if (!send_all($client, "OK {$nonce}\n")) break;
            continue;
        }

        /* 业务命令（尤其是上传安装包）可能持续较久，放宽单次读写超时 */
        stream_set_timeout($client, 120);

        if (preg_match('/^read\s+(.+)$/i', $line, $m)) {
            cmd_read($client, $m[1]);
        } elseif (preg_match('/^up\s+"([^"]*)"\s+(\d+)$/i', $line, $m)) {
            cmd_upload($client, $m[1], (int)$m[2]);
        } elseif (preg_match('/^up\s+(\S+)\s+(\d+)$/i', $line, $m)) {
            cmd_upload($client, $m[1], (int)$m[2]);
        } elseif (preg_match('/^list$/i', $line)) {
            cmd_list($client);
        } elseif (preg_match('/^admin\s+/i', $line)) {
            if ($nonce === null || time() - $nonceAt > ADMIN_NONCE_TTL) {
                send_all($client, "ERR auth\n");
            } else {
                cmd_admin($client, $line, $nonce, $ip);
                $nonce = null;      /* 一次性使用 */
            }
        } else {
            send_all($client, "ERR unknown\n");
        }
        break;   /* 一条连接只处理一条业务命令 */
    }
    fclose($client);
}

function run_tcp_server($port)
{
    $server = @stream_socket_server("tcp://0.0.0.0:{$port}", $errno, $errstr);
    if (!$server) {
        fwrite(STDERR, "无法监听端口 {$port}: {$errstr} ({$errno})\n");
        exit(1);
    }
    echo "BDProtect server listening on 0.0.0.0:{$port}\n";
    echo "data dir: " . DATA_DIR . "\n";

    while (true) {
        $client = @stream_socket_accept($server, -1);
        if (!$client) continue;

        if (function_exists('pcntl_fork')) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                fclose($server);
                handle_client($client);
                exit(0);
            } elseif ($pid > 0) {
                fclose($client);
                pcntl_wait($status, WNOHANG);
            } else {
                handle_client($client);
            }
        } else {
            handle_client($client);
        }
    }
}

/* ---------------- HTTP 模式 ---------------- */

function run_http()
{
    header('Content-Type: application/octet-stream');

    if (isset($_GET['read'])) {
        $path = resolve_download_name($_GET['read']);
        if ($path === null) { http_response_code(404); echo "not found"; return; }
        header('Content-Length: ' . filesize($path));
        readfile($path);
        return;
    }

    if (isset($_GET['up']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $name = sanitize_sample_name($_GET['up']);
        $body = file_get_contents('php://input');
        if ($body === false || $body === '') { http_response_code(400); echo "empty"; return; }
        $len = strlen($body);
        if ($len <= SAMPLE_MIN_SIZE || $len >= SAMPLE_MAX_SIZE) { http_response_code(413); echo "size"; return; }
        file_put_contents(SAMPLE_DIR . '/' . $name . '.bin', $body);
        $meta = sprintf("%s\t%d\t%s\n", date('Y-m-d H:i:s'), strlen($body), $name);
        @file_put_contents(SAMPLE_DIR . '/index.tsv', $meta, FILE_APPEND | LOCK_EX);
        echo "OK\n";
        return;
    }

    echo "BDProtect server\n";
}

/* ---------------- 入口 ---------------- */

ensure_dirs();

if (PHP_SAPI === 'cli') {
    $port = DEFAULT_PORT;
    if (isset($argv[1]) && ctype_digit($argv[1])) $port = (int)$argv[1];
    run_tcp_server($port);
} else {
    run_http();
}
