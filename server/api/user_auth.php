<?php
/**
 * 普通用户账号、邮箱验证与会话（短信同步公开版）
 *
 * 账号存于站点私有目录的 users.json（0600），密码用 password_hash 保存；
 * 注册需邮箱验证码（verify_codes.json，10 分钟有效，最多错 5 次）。
 * 登录后下发 HttpOnly Cookie「lyy_user」，值为 sid.HMAC-SHA256(sid)，
 * sid 同时登记在服务端会话表 user_sessions.json 中，退出/封禁/改密可立即撤销。
 * SMTP 发件配置在 smtp_config.json（0600），授权码 AES-256-GCM 加密存储。
 */

require_once __DIR__ . '/admin_auth.php';

/** 站点私有目录（与站根同级、Web 根之外）：如 /var/www/example.com → /var/www/example.com_private */
function app_private_dir() {
    $dir = dirname(__DIR__, 2) . '/' . basename(dirname(__DIR__)) . '_private';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir;
}

/** 敏感文件路径：优先私有目录，兼容迁移前的 data 目录 */
function private_path($name) {
    $new = app_private_dir() . '/' . $name;
    if (is_file($new)) return $new;
    $legacy = __DIR__ . '/../data/' . $name;
    if (is_file($legacy)) return $legacy;
    return $new;
}

function user_data_dir() {
    return app_private_dir();
}

function user_secret() {
    static $secret = null;
    if ($secret !== null) return $secret;

    $file = private_path('user_secret');
    if (!is_file($file)) {
        $dir = dirname($file);
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        $tmp = $file . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, bin2hex(random_bytes(32)), LOCK_EX) !== false) {
            @rename($tmp, $file);
            @chmod($file, 0600);
        }
    }
    $secret = trim((string)@file_get_contents($file));
    return $secret;
}

function users_file() {
    return private_path('users.json');
}

function users_load() {
    $file = users_file();
    $data = is_file($file) ? json_decode((string)@file_get_contents($file), true) : null;
    if (!is_array($data) || !isset($data['users']) || !is_array($data['users'])) {
        $data = ['users' => []];
    }
    return $data;
}

function users_save($data) {
    $file = users_file();
    $dir = dirname($file);
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    $tmp = $file . '.tmp.' . getmypid();
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if ($json === false) return false;
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) return false;
    if (!@rename($tmp, $file)) return false;
    @chmod($file, 0600);
    return true;
}

/** 按用户名或邮箱查找（均不区分大小写） */
function user_by_login($data, $login) {
    $lower = mb_strtolower(trim((string)$login), 'UTF-8');
    if ($lower === '') return null;
    foreach ($data['users'] as $u) {
        $name = isset($u['username']) ? mb_strtolower($u['username'], 'UTF-8') : '';
        $mail = isset($u['email']) ? mb_strtolower($u['email'], 'UTF-8') : '';
        if ($name === $lower || $mail === $lower) return $u;
    }
    return null;
}

function user_by_email($data, $email) {
    $lower = mb_strtolower(trim((string)$email), 'UTF-8');
    if ($lower === '') return null;
    foreach ($data['users'] as $u) {
        if (isset($u['email']) && mb_strtolower($u['email'], 'UTF-8') === $lower) return $u;
    }
    return null;
}

/** 对外可见的用户字段 */
function user_public($u) {
    return [
        'id' => isset($u['id']) ? $u['id'] : '',
        'username' => isset($u['username']) ? $u['username'] : '',
        'email' => isset($u['email']) ? $u['email'] : '',
        'role' => isset($u['role']) ? $u['role'] : 'user',
        'createdAt' => isset($u['createdAt']) ? (int)$u['createdAt'] : 0
    ];
}

function user_token_ttl() {
    return 7 * 86400;
}

function user_sessions_file() {
    return app_private_dir() . '/user_sessions.json';
}

/** 会话表写入（排他锁），$fn(&$data) 返回 false 表示不落盘 */
function sessions_update($fn) {
    $file = user_sessions_file();
    $fp = @fopen($file, 'c+');
    if ($fp === false) return null;
    @flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $data = json_decode($raw, true);
    if (!is_array($data)) $data = [];
    $result = $fn($data);
    if ($result !== false) {
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data, JSON_UNESCAPED_UNICODE));
        fflush($fp);
    }
    @flock($fp, LOCK_UN);
    @fclose($fp);
    @chmod($file, 0600);
    return $result;
}

function sessions_read() {
    $file = user_sessions_file();
    if (!is_file($file)) return [];
    $fp = @fopen($file, 'r');
    if ($fp === false) return [];
    @flock($fp, LOCK_SH);
    $raw = stream_get_contents($fp);
    @flock($fp, LOCK_UN);
    @fclose($fp);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

/** 生成会话令牌：sid.HMAC(sid)，同时把 sid 写入服务端会话表（可随时撤销） */
function user_token_issue($userId, $ttl = null) {
    $ttl = $ttl === null ? user_token_ttl() : $ttl;
    $sid = bin2hex(random_bytes(16));
    $exp = time() + $ttl;
    sessions_update(function (&$data) use ($sid, $userId, $exp) {
        $now = time();
        foreach ($data as $k => $v) {
            if (!is_array($v) || (int)(isset($v['exp']) ? $v['exp'] : 0) < $now) unset($data[$k]);
        }
        $data[$sid] = [
            'userId' => $userId,
            'exp' => $exp,
            'createdAt' => $now,
            'ip' => client_ip()
        ];
        return true;
    });
    return $sid . '.' . hash_hmac('sha256', $sid, user_secret());
}

/** 校验令牌：签名有效 + 会话仍在服务端表中 + 未过期 */
function user_token_check($value) {
    if (!is_string($value) || !preg_match('/^([0-9a-f]{32})\.([0-9a-f]{64})$/', $value, $m)) return null;
    if (!hash_equals(hash_hmac('sha256', $m[1], user_secret()), $m[2])) return null;
    $sessions = sessions_read();
    if (!isset($sessions[$m[1]]) || !is_array($sessions[$m[1]])) return null;
    $rec = $sessions[$m[1]];
    if ((int)(isset($rec['exp']) ? $rec['exp'] : 0) < time()) return null;
    return (string)$rec['userId'];
}

/** 退出登录：删除当前会话 */
function user_session_revoke($value) {
    if (!is_string($value) || !preg_match('/^([0-9a-f]{32})\./', $value, $m)) return;
    $sid = $m[1];
    sessions_update(function (&$data) use ($sid) {
        unset($data[$sid]);
        return true;
    });
}

/** 撤销某个用户的全部会话（改密码 / 封禁时使用） */
function user_sessions_revoke_user($userId) {
    sessions_update(function (&$data) use ($userId) {
        foreach ($data as $k => $v) {
            if (is_array($v) && isset($v['userId']) && (string)$v['userId'] === (string)$userId) unset($data[$k]);
        }
        return true;
    });
}

function user_cookie_set($token, $ttl = null) {
    $ttl = $ttl === null ? user_token_ttl() : $ttl;
    setcookie('lyy_user', $token, [
        'expires' => time() + $ttl,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

function user_cookie_clear() {
    setcookie('lyy_user', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

/** 当前登录用户；管理员令牌有效时映射为内置管理员账号 */
function current_user() {
    static $cached = false;
    if ($cached !== false) return $cached;

    $userId = user_token_check(isset($_COOKIE['lyy_user']) ? $_COOKIE['lyy_user'] : '');
    if ($userId !== null) {
        $data = users_load();
        if (isset($data['users'][$userId]) && empty($data['users'][$userId]['banned'])) {
            $cached = $data['users'][$userId];
            return $cached;
        }
        $cached = null;
        return null;
    }

    if (admin_session_valid()) {
        $cached = [
            'id' => 'u_admin',
            'username' => '管理员',
            'email' => '',
            'role' => 'admin',
            'createdAt' => 0
        ];
        return $cached;
    }

    $cached = null;
    return null;
}

function require_user() {
    $user = current_user();
    if ($user === null) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => '请先登录'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    return $user;
}

function client_ip() {
    return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
}

/** 通用 JSON 文件加锁读写：$fn(&$data) 返回结果，返回 false 表示不写回 */
function json_locked($file, $fn) {
    $fp = @fopen($file, 'c+');
    if ($fp === false) return null;
    @flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $data = json_decode($raw, true);
    if (!is_array($data)) $data = [];
    $result = $fn($data);
    if ($result !== false) {
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data, JSON_UNESCAPED_UNICODE));
        fflush($fp);
    }
    @flock($fp, LOCK_UN);
    @fclose($fp);
    @chmod($file, 0600);
    return $result;
}

/** 滑动窗口限流：返回 true 表示已超限 */
function rate_limited($file, $key, $max, $window) {
    $limited = false;
    json_locked($file, function (&$data) use ($key, $max, $window, &$limited) {
        $now = time();
        $list = isset($data[$key]) && is_array($data[$key]) ? $data[$key] : [];
        $list = array_values(array_filter($list, function ($t) use ($now, $window) {
            return is_numeric($t) && $t > $now - $window;
        }));
        if (count($list) >= $max) {
            $limited = true;
        } else {
            $list[] = $now;
        }
        $data[$key] = $list;
        return true; // 无论是否超限都要写回：清理过期记录并累加计数
    });
    return $limited;
}

// ---------- SMTP 发信 ----------

/** SMTP 授权码加密密钥（32 字节，十六进制存于私有目录） */
function smtp_key() {
    static $key = null;
    if ($key !== null) return $key;
    $file = private_path('smtp_key');
    if (!is_file($file)) {
        $dir = dirname($file);
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        $tmp = $file . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, bin2hex(random_bytes(32)), LOCK_EX) !== false) {
            @rename($tmp, $file);
            @chmod($file, 0600);
        }
    }
    $hex = trim((string)@file_get_contents($file));
    $key = strlen($hex) === 64 ? hex2bin($hex) : null;
    return $key;
}

/** 加密授权码，返回可落盘的 {enc,iv,tag,data} */
function smtp_encrypt_pass($pass) {
    $key = smtp_key();
    if ($key === null) return null;
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($pass, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) return null;
    return [
        'enc' => 1,
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
        'data' => base64_encode($cipher)
    ];
}

function smtp_decrypt_pass($blob) {
    if (!is_array($blob) || !isset($blob['iv'], $blob['tag'], $blob['data'])) return '';
    $key = smtp_key();
    if ($key === null) return '';
    $plain = openssl_decrypt(
        base64_decode((string)$blob['data']), 'aes-256-gcm', $key, OPENSSL_RAW_DATA,
        base64_decode((string)$blob['iv']), base64_decode((string)$blob['tag'])
    );
    return $plain === false ? '' : $plain;
}

function smtp_config_save($cfg) {
    $file = private_path('smtp_config.json');
    $tmp = $file . '.tmp.' . getmypid();
    $json = json_encode($cfg, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if ($json === false) return false;
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) return false;
    if (!@rename($tmp, $file)) return false;
    @chmod($file, 0600);
    return true;
}

function smtp_config() {
    $file = private_path('smtp_config.json');
    if (!is_file($file)) return null;
    $cfg = json_decode((string)@file_get_contents($file), true);
    if (!is_array($cfg)) return null;
    $host = isset($cfg['host']) ? trim((string)$cfg['host']) : '';
    $user = isset($cfg['user']) ? trim((string)$cfg['user']) : '';

    // 授权码优先读密文；发现旧的明文 pass 时自动迁移为密文并删除明文字段
    if (!empty($cfg['passEnc'])) {
        $pass = smtp_decrypt_pass($cfg['passEnc']);
    } elseif (isset($cfg['pass']) && (string)$cfg['pass'] !== '') {
        $pass = (string)$cfg['pass'];
        $enc = smtp_encrypt_pass($pass);
        if ($enc !== null) {
            $cfg['passEnc'] = $enc;
            unset($cfg['pass']);
            smtp_config_save($cfg);
        }
    } else {
        $pass = '';
    }
    if ($host === '' || $user === '' || $pass === '') return null;
    return [
        'host' => $host,
        'port' => isset($cfg['port']) ? (int)$cfg['port'] : 465,
        'secure' => isset($cfg['secure']) ? (string)$cfg['secure'] : 'ssl',
        'user' => $user,
        'pass' => $pass,
        'from' => !empty($cfg['from']) ? (string)$cfg['from'] : $user,
        'fromName' => !empty($cfg['fromName']) ? (string)$cfg['fromName'] : '短信同步'
    ];
}

/** 发送 HTML 邮件；成功返回空字符串，失败返回错误说明 */
function smtp_send($to, $subject, $html) {
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return '收件邮箱格式不正确';
    $cfg = smtp_config();
    if ($cfg === null) return '邮件服务未配置';

    $prefix = $cfg['secure'] === 'ssl' ? 'ssl://' : '';
    $errno = 0;
    $errstr = '';
    $fp = @stream_socket_client($prefix . $cfg['host'] . ':' . $cfg['port'], $errno, $errstr, 15);
    if ($fp === false) return '无法连接邮件服务器';
    stream_set_timeout($fp, 20);

    $read = function () use ($fp) {
        $out = '';
        while (!feof($fp)) {
            $line = fgets($fp, 1024);
            if ($line === false) break;
            $out .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') break;
        }
        return $out;
    };
    $cmd = function ($line) use ($fp, $read) {
        fwrite($fp, $line . "\r\n");
        return $read();
    };
    $code = function ($resp) {
        return strlen($resp) >= 3 ? (int)substr($resp, 0, 3) : 0;
    };

    if ($code($read()) !== 220) {
        fclose($fp);
        return '邮件服务器无响应';
    }
    if ($code($cmd('EHLO linyuyang.top')) !== 250) {
        fclose($fp);
        return '邮件服务器握手失败';
    }
    if ($code($cmd('AUTH LOGIN')) !== 334) {
        fclose($fp);
        return '邮件服务器不支持登录';
    }
    if ($code($cmd(base64_encode($cfg['user']))) !== 334) {
        fclose($fp);
        return '邮箱账号被拒绝';
    }
    if ($code($cmd(base64_encode($cfg['pass']))) !== 235) {
        fclose($fp);
        return '邮箱授权码不正确';
    }
    if ($code($cmd('MAIL FROM:<' . $cfg['from'] . '>')) !== 250) {
        fclose($fp);
        return '发件地址被拒绝';
    }
    if ($code($cmd('RCPT TO:<' . $to . '>')) !== 250) {
        fclose($fp);
        return '收件地址被拒绝';
    }
    if ($code($cmd('DATA')) !== 354) {
        fclose($fp);
        return '邮件发送被拒绝';
    }

    $headers = [
        'From: =?UTF-8?B?' . base64_encode($cfg['fromName']) . '?= <' . $cfg['from'] . '>',
        'To: <' . $to . '>',
        'Subject: =?UTF-8?B?' . base64_encode($subject) . '?=',
        'Date: ' . date('r'),
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=UTF-8',
        'Content-Transfer-Encoding: base64',
        'Message-ID: <' . bin2hex(random_bytes(12)) . '@linyuyang.top>'
    ];
    $payload = implode("\r\n", $headers) . "\r\n\r\n"
        . chunk_split(base64_encode($html), 76, "\r\n");
    $payload = preg_replace('/^\./m', '..', $payload);

    fwrite($fp, $payload . "\r\n.\r\n");
    if ($code($read()) !== 250) {
        fclose($fp);
        return '邮件投递失败，请稍后重试';
    }
    $cmd('QUIT');
    fclose($fp);
    return '';
}
