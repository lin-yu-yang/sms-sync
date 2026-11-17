<?php
/**
 * 短信同步接口（公开版，多用户）
 *
 * 账号
 *   POST ?action=send-code   发送邮箱验证码（注册前）
 *   POST ?action=register    邮箱 + 验证码 创建账号并登录
 *   POST ?action=login       邮箱或用户名 + 密码 登录
 *   POST ?action=logout      退出登录
 *   GET  ?action=me          当前登录用户
 * 设备
 *   POST ?action=pair-code   登录后生成 6 位一次性绑定码（10 分钟）
 *   POST ?action=enroll      手机 APP 用绑定码换取设备令牌（请求头 X-Device-Token）
 *   GET  ?action=devices     已绑定设备列表
 *   POST ?action=revoke-device 解绑设备
 * 数据
 *   POST ?action=upload      设备上传短信（X-Device-Token）
 *   GET  ?action=list        查看自己的短信
 *   POST ?action=delete      删除自己的单条短信
 *   POST ?action=dedupe      清理自己的重复短信
 *
 * 每个账号数据完全隔离；短信以 AES-256-GCM 加密存于站点私有目录
 * （与站根同级的私有目录，Web 根之外，0600），写操作持排他锁；
 * 短信保留 90 天，每账号最多 3000 条、5 台设备。
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

date_default_timezone_set('Asia/Shanghai');

define('MAX_MESSAGES_PER_USER', 3000); // 每个账号最多保留的短信条数
define('MAX_DEVICES_PER_USER', 5);     // 每个账号最多绑定的设备数
define('MAX_BODY_LEN', 2000);          // 单条正文最大字符数
define('MAX_SENDER_LEN', 60);          // 号码/发送者最大长度
define('MAX_DEVICE_LEN', 60);          // 设备名最大长度
define('DEDUPE_WINDOW_MS', 90000);     // 同号码+同内容，时间相差 90 秒内视为重复
define('PAIR_TTL', 600);               // 设备绑定码有效期
define('CODE_TTL', 600);               // 邮箱验证码有效期
define('CODE_MAX_TRIES', 5);           // 邮箱验证码最多错误次数
define('LEGACY_OWNER', 'u_admin');     // 旧数据（无 owner）归属管理员
define('MAX_MESSAGE_AGE', 90 * 86400); // 短信保留 90 天，超期自动清理
define('UPLOAD_MAX_PER_MINUTE', 60);   // 单台设备每分钟最多上传次数
define('MAIL_GLOBAL_PER_HOUR', 60);    // 全站每小时最多发信数（保护 163 免费额度）
define('MAIL_PER_ADDRESS_PER_DAY', 3); // 同一收件邮箱每天最多发信数

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

function fail($code, $message) {
    http_response_code($code);
    echo json_encode(['success' => false, 'message' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

function json_body() {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

require_once __DIR__ . '/user_auth.php';

$dataDir = app_private_dir(); // 限流记录也放在 Web 根之外
$smsFile = private_path('sms.json');
$configFile = private_path('sms_config.json');
$pairFile = private_path('sms_pair.json');
$verifyFile = private_path('verify_codes.json');
$auditFile = app_private_dir() . '/audit.log';

/** 读取设备登记表；旧版的 uploadKey 字段自动作废 */
function load_config($file) {
    $cfg = [];
    if (file_exists($file)) {
        $cfg = json_decode((string)@file_get_contents($file), true);
    }
    if (!is_array($cfg)) $cfg = [];
    unset($cfg['uploadKey']);
    if (!isset($cfg['devices']) || !is_array($cfg['devices'])) $cfg['devices'] = [];
    return $cfg;
}

/** 短信内容加密密钥（32 字节，十六进制存储） */
function sms_key() {
    $file = private_path('sms_key');
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
    return strlen($hex) === 64 ? hex2bin($hex) : null;
}

function read_sms($file) {
    if (!file_exists($file)) return ['messages' => [], 'devices' => []];
    $raw = file_get_contents($file);
    if ($raw === false || trim($raw) === '') return ['messages' => [], 'devices' => []];
    $data = json_decode($raw, true);
    if (is_array($data) && isset($data['enc'], $data['iv'], $data['tag'], $data['data'])) {
        $key = sms_key();
        $plain = $key === null ? false : openssl_decrypt(
            base64_decode($data['data']), 'aes-256-gcm', $key, OPENSSL_RAW_DATA,
            base64_decode($data['iv']), base64_decode($data['tag'])
        );
        if ($plain === false) return ['messages' => [], 'devices' => []];
        $data = json_decode($plain, true);
    }
    if (!is_array($data)) return ['messages' => [], 'devices' => []];
    $messages = isset($data['messages']) && is_array($data['messages']) ? array_values($data['messages']) : [];
    foreach ($messages as $i => $m) {
        if (!is_array($m)) {
            unset($messages[$i]);
            continue;
        }
        // 旧数据没有 owner，统一归到管理员账号
        if (!isset($m['owner']) || !is_string($m['owner']) || $m['owner'] === '') {
            $messages[$i]['owner'] = LEGACY_OWNER;
        }
    }
    return [
        'messages' => array_values($messages),
        'devices' => isset($data['devices']) && is_array($data['devices']) ? $data['devices'] : []
    ];
}

/** 原子写回（AES-256-GCM 加密），避免并发写坏文件 */
function write_sms($file, $data) {
    $key = sms_key();
    if ($key === null) return false;
    $dir = dirname($file);
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    $tmp = $file . '.tmp.' . getmypid();

    $plain = json_encode($data, JSON_UNESCAPED_UNICODE);
    if ($plain === false) return false;
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) return false;

    $json = json_encode([
        'enc' => 1,
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
        'data' => base64_encode($cipher)
    ]);
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) return false;
    if (!@rename($tmp, $file)) return false;
    @chmod($file, 0600);
    return true;
}

/**
 * 短信库事务：全程持有排他锁，避免并发「读-改-写」互相覆盖导致丢短信。
 * $fn(array &$store) 返回 false 表示不写回；其他返回值原样透传。
 * 返回 false 表示加锁或写盘失败。
 */
function sms_transaction($file, $fn) {
    $lockFile = $file . '.lock';
    $lock = @fopen($lockFile, 'c');
    if ($lock === false) return false;
    @chmod($lockFile, 0600);
    if (!@flock($lock, LOCK_EX)) {
        @fclose($lock);
        return false;
    }
    $store = read_sms($file);
    $result = $fn($store);
    if ($result !== false && !write_sms($file, $store)) $result = false;
    @flock($lock, LOCK_UN);
    @fclose($lock);
    return $result;
}

/** 设备登记表事务（避免并发 enroll / 解绑互相覆盖） */
function config_update($file, $fn) {
    return json_locked($file, function (&$cfg) use ($fn) {
        if (!is_array($cfg)) $cfg = [];
        unset($cfg['uploadKey']);
        if (!isset($cfg['devices']) || !is_array($cfg['devices'])) $cfg['devices'] = [];
        return $fn($cfg);
    });
}

/** 短信时间（毫秒）换算为秒；无效时间返回 0 */
function msg_time_sec($m) {
    $t = isset($m['time']) ? (int)$m['time'] : 0;
    if ($t > 0) return $t > 100000000000 ? (int)($t / 1000) : $t;
    return isset($m['uploadedAt']) ? (int)$m['uploadedAt'] : 0;
}

/** 追加审计日志（JSONL，0600） */
function audit_log($file, $action, $actor, $target = '', $detail = '') {
    $line = json_encode([
        'at' => date('c'),
        'ip' => client_ip(),
        'actor' => (string)$actor,
        'action' => (string)$action,
        'target' => (string)$target,
        'detail' => (string)$detail
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($line === false) return;
    @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
    @chmod($file, 0600);
}

/** 密码强度校验：通过返回空字符串，否则返回提示 */
function password_problem($password, $username, $email) {
    $len = strlen($password);
    if ($len < 10) return '密码至少 10 位';
    if ($len > 64) return '密码不能超过 64 位';
    if (!preg_match('/[A-Za-z]/', $password) || !preg_match('/\d/', $password)) {
        return '密码需同时包含字母和数字';
    }
    if (preg_match('/^(.)\1+$/u', $password)) return '密码过于简单，请更换';
    static $weak = [
        '12345678', '123456789', '1234567890', 'password', 'password1', 'password123',
        'qwerty123', 'abc12345', '11111111', '88888888', 'a1234567', 'admin123',
        'iloveyou', 'iloveyou1', '1qaz2wsx', 'qazwsxedc', '1234abcd', 'abcd1234',
        'p@ssw0rd', 'welcome1', '66666666', '00000000', 'asdfghjkl', 'zxcvbnm123'
    ];
    $lower = strtolower($password);
    if (in_array($lower, $weak, true)) return '密码过于常见，请更换';
    $u = strtolower(trim($username));
    if ($u !== '' && $lower === $u) return '密码不能与用户名相同';
    $mail = strtolower(trim($email));
    $at = strpos($mail, '@');
    $local = $at === false ? $mail : substr($mail, 0, $at);
    if ($local !== '' && $lower === $local) return '密码不能与邮箱前缀相同';
    return '';
}

/** 同一用户 + 同一号码 + 相同内容，且时间相差不超过窗口，视为同一条短信的重复投递 */
function near_duplicate($map, $key, $time) {
    if ($key === '' || !isset($map[$key])) return false;
    foreach ($map[$key] as $t) {
        if (abs($t - $time) <= DEDUPE_WINDOW_MS) return true;
    }
    return false;
}

function clean_field($value, $maxLen) {
    if (!is_string($value)) return '';
    $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
    $text = trim($text);
    if (mb_strlen($text, 'UTF-8') > $maxLen) {
        $text = mb_substr($text, 0, $maxLen, 'UTF-8');
    }
    return $text;
}

/** 设备记录的归属用户（旧记录无 userId 时归管理员） */
function device_owner($info) {
    return (is_array($info) && isset($info['userId']) && is_string($info['userId']) && $info['userId'] !== '')
        ? $info['userId'] : LEGACY_OWNER;
}

/** 按令牌查找设备，返回 [token, info] 或 null */
function find_device($cfg, $token) {
    if ($token === '' || empty($cfg['devices'])) return null;
    foreach ($cfg['devices'] as $t => $info) {
        if (hash_equals((string)$t, $token)) return [(string)$t, $info];
    }
    return null;
}

function count_user_devices($cfg, $userId) {
    $count = 0;
    foreach ($cfg['devices'] as $info) {
        if (device_owner($info) === $userId) $count++;
    }
    return $count;
}

function mail_template($code) {
    $code = htmlspecialchars($code, ENT_QUOTES, 'UTF-8');
    return '<div style="font-family:-apple-system,Segoe UI,PingFang SC,Microsoft YaHei,sans-serif;'
        . 'max-width:480px;margin:0 auto;padding:28px 24px;background:#0a0a0a;color:#fff;border-radius:14px">'
        . '<h2 style="font-size:18px;margin:0 0 6px;color:#fff">短信同步 · 邮箱验证</h2>'
        . '<p style="font-size:13px;color:#a1a1aa;line-height:1.8;margin:0 0 18px">你正在注册「短信同步」，验证码 10 分钟内有效：</p>'
        . '<div style="font-size:32px;font-weight:800;letter-spacing:8px;color:#00e599;text-align:center;'
        . 'padding:14px 0;background:rgba(0,229,153,.08);border:1px solid rgba(0,229,153,.35);border-radius:10px">'
        . $code . '</div>'
        . '<p style="font-size:12px;color:#6b6b72;line-height:1.9;margin:18px 0 0">'
        . '如果这不是你的操作，请忽略本邮件。<br>本邮件由系统自动发送，请勿直接回复。</p>'
        . '</div>';
}

$method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? (string)$_GET['action'] : '';
if ($action === '' && $method === 'POST') {
    $input = json_body();
    $action = isset($input['action']) ? (string)$input['action'] : '';
}
if ($method === 'POST' && $action === '') {
    $action = 'upload';
}

// ==================== 账号 ====================

if ($action === 'me') {
    $user = current_user();
    if ($user === null) fail(401, '未登录');
    echo json_encode(['success' => true, 'user' => user_public($user)], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'send-code') {
    if ($method !== 'POST') fail(405, '请使用 POST');
    $input = json_body();
    $email = strtolower(trim((string)(isset($input['email']) ? $input['email'] : '')));
    $username = trim((string)(isset($input['username']) ? $input['username'] : ''));
    $password = (string)(isset($input['password']) ? $input['password'] : '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail(400, '请输入正确的邮箱地址');
    if (!preg_match('/^[A-Za-z0-9_\x{4e00}-\x{9fa5}]{3,20}$/u', $username)) {
        fail(400, '用户名需 3-20 位，仅限中英文、数字、下划线');
    }
    $pwProblem = password_problem($password, $username, $email);
    if ($pwProblem !== '') fail(400, $pwProblem);

    $users = users_load();
    if (count($users['users']) >= 5000) fail(503, '注册人数已达上限');
    // 不在此处暴露邮箱/用户名是否已存在（避免账号枚举），统一在验证码校验通过后提示
    if (smtp_config() === null) fail(503, '邮件服务尚未配置，暂时无法注册');

    // 三层配额：全站每小时总量（保护 163 免费额度）→ 单邮箱每天 → 单 IP 每小时
    if (rate_limited($dataDir . '/mail_global.json', 'global', MAIL_GLOBAL_PER_HOUR, 3600)) {
        fail(503, '今日注册人数较多，请稍后再试');
    }
    if (rate_limited($dataDir . '/mail_email.json', 'mail:' . md5($email), MAIL_PER_ADDRESS_PER_DAY, 86400)) {
        fail(429, '该邮箱今日验证码发送次数已达上限，请明天再试或联系管理员');
    }
    if (rate_limited($dataDir . '/mail_rate.json', 'ip:' . client_ip(), 5, 3600)) {
        fail(429, '发送过于频繁，请一小时后再试');
    }

    $now = time();
    $tooSoon = json_locked($verifyFile, function (&$codes) use ($email, $now) {
        return isset($codes[$email]['sentAt']) && $now - (int)$codes[$email]['sentAt'] < 60;
    });
    if ($tooSoon === true) fail(429, '验证码已发送，请 60 秒后再试');

    $code = (string)random_int(100000, 999999);
    $error = smtp_send($email, '短信同步 - 邮箱验证码', mail_template($code));
    if ($error !== '') fail(502, $error);

    json_locked($verifyFile, function (&$codes) use ($email, $code, $username, $password, $now) {
        foreach ($codes as $k => $v) {
            if (!is_array($v) || (int)(isset($v['exp']) ? $v['exp'] : 0) < $now) unset($codes[$k]);
        }
        $codes[$email] = [
            'code' => $code,
            'username' => $username,
            'passHash' => password_hash($password, PASSWORD_DEFAULT),
            'exp' => $now + CODE_TTL,
            'tries' => 0,
            'sentAt' => $now
        ];
        return true;
    });

    echo json_encode(['success' => true, 'expiresIn' => CODE_TTL], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'register') {
    if ($method !== 'POST') fail(405, '请使用 POST');
    $input = json_body();
    $email = strtolower(trim((string)(isset($input['email']) ? $input['email'] : '')));
    $code = preg_replace('/\D/', '', (string)(isset($input['code']) ? $input['code'] : ''));

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail(400, '请输入正确的邮箱地址');
    if (strlen($code) !== 6) fail(400, '请输入 6 位邮箱验证码');
    if (rate_limited($dataDir . '/reg_rate.json', 'ip:' . client_ip(), 10, 3600)) {
        fail(429, '注册过于频繁，请稍后再试');
    }

    $now = time();
    $checked = json_locked($verifyFile, function (&$codes) use ($email, $code, $now) {
        if (!isset($codes[$email]) || !is_array($codes[$email])) {
            return ['error' => '请先获取邮箱验证码'];
        }
        $rec = $codes[$email];
        if ((int)(isset($rec['exp']) ? $rec['exp'] : 0) < $now) {
            unset($codes[$email]);
            return ['error' => '验证码已过期，请重新获取'];
        }
        if ((int)(isset($rec['tries']) ? $rec['tries'] : 0) >= CODE_MAX_TRIES) {
            unset($codes[$email]);
            return ['error' => '验证码错误次数过多，请重新获取'];
        }
        if (!hash_equals((string)$rec['code'], $code)) {
            $codes[$email]['tries'] = (int)(isset($rec['tries']) ? $rec['tries'] : 0) + 1;
            return ['error' => '验证码不正确'];
        }
        unset($codes[$email]);
        return [
            'username' => (string)$rec['username'],
            'passHash' => (string)$rec['passHash']
        ];
    });

    if (!is_array($checked) || isset($checked['error'])) {
        fail(400, is_array($checked) && isset($checked['error']) ? $checked['error'] : '验证失败，请重新获取验证码');
    }

    $users = users_load();
    if (count($users['users']) >= 5000) fail(503, '注册人数已达上限');
    if (user_by_email($users, $email) !== null) fail(409, '该邮箱已注册，请直接登录');
    if (user_by_login($users, $checked['username']) !== null) fail(409, '该用户名已被占用');

    $id = 'u_' . bin2hex(random_bytes(8));
    $users['users'][$id] = [
        'id' => $id,
        'username' => $checked['username'],
        'email' => $email,
        'passHash' => $checked['passHash'],
        'createdAt' => $now,
        'lastLogin' => $now,
        'failCount' => 0,
        'lockedUntil' => 0,
        'banned' => false
    ];
    if (!users_save($users)) fail(500, '保存失败，请稍后重试');

    audit_log($auditFile, 'register', $id, $checked['username'], $email);
    user_cookie_set(user_token_issue($id));
    echo json_encode([
        'success' => true,
        'user' => user_public($users['users'][$id])
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'login') {
    if ($method !== 'POST') fail(405, '请使用 POST');
    $input = json_body();
    $login = trim((string)(isset($input['login']) ? $input['login'] : ''));
    $password = (string)(isset($input['password']) ? $input['password'] : '');
    if ($login === '' || $password === '') fail(400, '请输入账号和密码');
    if (rate_limited($dataDir . '/login_rate.json', 'ip:' . client_ip(), 20, 600)) {
        fail(429, '尝试过于频繁，请 10 分钟后再试');
    }

    $users = users_load();
    $user = user_by_login($users, $login);
    if ($user === null) {
        usleep(300000);
        fail(401, '账号或密码错误');
    }
    if (!empty($user['lockedUntil']) && (int)$user['lockedUntil'] > time()) {
        fail(429, '密码错误次数过多，请 10 分钟后再试');
    }
    if (!password_verify($password, (string)$user['passHash'])) {
        $user['failCount'] = (int)(isset($user['failCount']) ? $user['failCount'] : 0) + 1;
        if ($user['failCount'] >= 5) {
            $user['failCount'] = 0;
            $user['lockedUntil'] = time() + 600;
        }
        $users['users'][$user['id']] = $user;
        users_save($users);
        fail(401, '账号或密码错误');
    }
    if (!empty($user['banned'])) fail(403, '该账号已被停用');

    $user['failCount'] = 0;
    $user['lockedUntil'] = 0;
    $user['lastLogin'] = time();
    $users['users'][$user['id']] = $user;
    users_save($users);

    user_cookie_set(user_token_issue($user['id']));
    echo json_encode([
        'success' => true,
        'user' => user_public($user)
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'logout') {
    user_session_revoke(isset($_COOKIE['lyy_user']) ? $_COOKIE['lyy_user'] : '');
    user_cookie_clear();
    echo json_encode(['success' => true], JSON_UNESCAPED_UNICODE);
    exit;
}

// ==================== 管理员 ====================

/** 管理员身份依赖 lyy_admin 签名 Cookie（与普通用户会话相互独立） */
function require_admin() {
    if (!admin_session_valid()) fail(401, '需要管理员权限');
}

if ($action === 'admin-users') {
    require_admin();
    $users = users_load();
    $store = read_sms($smsFile);
    $cfg = load_config($configFile);

    $msgCount = [];
    foreach ($store['messages'] as $m) {
        $o = isset($m['owner']) ? (string)$m['owner'] : LEGACY_OWNER;
        $msgCount[$o] = isset($msgCount[$o]) ? $msgCount[$o] + 1 : 1;
    }

    $list = [];
    foreach ($users['users'] as $u) {
        $id = isset($u['id']) ? (string)$u['id'] : '';
        $list[] = [
            'id' => $id,
            'username' => isset($u['username']) ? (string)$u['username'] : '',
            'email' => isset($u['email']) ? (string)$u['email'] : '',
            'createdAt' => (int)(isset($u['createdAt']) ? $u['createdAt'] : 0),
            'lastLogin' => (int)(isset($u['lastLogin']) ? $u['lastLogin'] : 0),
            'banned' => !empty($u['banned']),
            'messages' => isset($msgCount[$id]) ? $msgCount[$id] : 0,
            'devices' => count_user_devices($cfg, $id)
        ];
    }
    usort($list, function ($a, $b) {
        return $b['createdAt'] - $a['createdAt'];
    });
    echo json_encode(['success' => true, 'users' => $list], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'admin-ban') {
    require_admin();
    if ($method !== 'POST') fail(405, '请使用 POST');
    $input = json_body();
    $id = isset($input['id']) && is_string($input['id']) ? trim($input['id']) : '';
    $banned = !empty($input['banned']);
    if ($id === '') fail(400, '缺少用户 id');
    if ($id === LEGACY_OWNER) fail(400, '内置管理员账号不可封禁');

    $users = users_load();
    if (!isset($users['users'][$id])) fail(400, '用户不存在');
    $users['users'][$id]['banned'] = $banned;
    if (!users_save($users)) fail(500, '保存失败，请稍后重试');
    // 封禁立即生效：撤销该账号全部已签发会话
    if ($banned) user_sessions_revoke_user($id);

    audit_log(
        $auditFile,
        $banned ? 'ban-user' : 'unban-user',
        'admin',
        $id,
        isset($users['users'][$id]['username']) ? (string)$users['users'][$id]['username'] : ''
    );

    echo json_encode(['success' => true, 'banned' => $banned], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'admin-audit') {
    require_admin();
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 200;
    if ($limit < 1) $limit = 200;
    if ($limit > 1000) $limit = 1000;

    $lines = [];
    if (is_file($auditFile)) {
        $fp = @fopen($auditFile, 'r');
        if ($fp !== false) {
            @flock($fp, LOCK_SH);
            while (($line = fgets($fp)) !== false) {
                $lines[] = $line;
                if (count($lines) > $limit) array_shift($lines);
            }
            @flock($fp, LOCK_UN);
            @fclose($fp);
        }
    }
    $out = [];
    foreach ($lines as $line) {
        $rec = json_decode($line, true);
        if (is_array($rec)) $out[] = $rec;
    }
    echo json_encode(['success' => true, 'events' => array_reverse($out)], JSON_UNESCAPED_UNICODE);
    exit;
}

// ==================== 设备绑定 ====================

if ($action === 'enroll') {
    if ($method !== 'POST') fail(405, '请使用 POST 绑定');
    if (rate_limited($dataDir . '/enroll_rate.json', 'ip:' . client_ip(), 10, 600)) {
        fail(429, '尝试过于频繁，请 10 分钟后再试');
    }

    $input = json_body();
    $code = isset($input['code']) && is_string($input['code']) ? preg_replace('/\D/', '', $input['code']) : '';
    $device = clean_field(isset($input['device']) ? $input['device'] : '', MAX_DEVICE_LEN);
    if ($device === '') $device = '安卓手机';
    if (strlen($code) !== 6) fail(400, '请输入 6 位绑定码');

    $checked = json_locked($pairFile, function (&$data) use ($code) {
        $now = time();
        if (!isset($data['codes']) || !is_array($data['codes'])) {
            return ['error' => '绑定码无效，请在网页重新生成'];
        }
        foreach ($data['codes'] as $k => $v) {
            if (!is_array($v) || (int)(isset($v['exp']) ? $v['exp'] : 0) < $now) unset($data['codes'][$k]);
        }
        if (!isset($data['codes'][$code]) || !is_array($data['codes'][$code])) {
            return ['error' => '绑定码无效或已过期，请在网页重新生成'];
        }
        $userId = (string)$data['codes'][$code]['userId'];
        unset($data['codes'][$code]);
        return ['userId' => $userId];
    });

    if (!is_array($checked) || isset($checked['error'])) {
        fail(400, is_array($checked) && isset($checked['error']) ? $checked['error'] : '绑定码无效');
    }

    $token = bin2hex(random_bytes(24));
    $now = time();
    $full = false;
    $saved = config_update($configFile, function (&$cfg) use ($checked, $device, $token, $now, &$full) {
        if (count_user_devices($cfg, $checked['userId']) >= MAX_DEVICES_PER_USER) {
            $full = true;
            return false;
        }
        $cfg['devices'][$token] = [
            'userId' => $checked['userId'],
            'name' => $device,
            'createdAt' => $now,
            'lastSeen' => $now,
            'ip' => client_ip()
        ];
        return true;
    });
    if ($full) fail(409, '该账号已绑定 ' . MAX_DEVICES_PER_USER . ' 台设备，请先在网页解绑旧设备');
    if ($saved !== true) fail(500, '服务端保存失败，请稍后重试');

    audit_log($auditFile, 'bind-device', $checked['userId'], $device, substr($token, 0, 12));

    echo json_encode([
        'success' => true,
        'token' => $token,
        'device' => $device
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ---------- 以下需要登录 ----------

if ($action === 'pair-code') {
    $me = require_user();
    if ($method !== 'POST') fail(405, '请使用 POST 生成绑定码');

    $cfg = load_config($configFile);
    if (count_user_devices($cfg, $me['id']) >= MAX_DEVICES_PER_USER) {
        fail(409, '已绑定 ' . MAX_DEVICES_PER_USER . ' 台设备，请先解绑旧设备');
    }

    $pair = json_locked($pairFile, function (&$data) use ($me) {
        $now = time();
        if (!isset($data['codes']) || !is_array($data['codes'])) $data['codes'] = [];
        foreach ($data['codes'] as $k => $v) {
            if (!is_array($v) || (int)(isset($v['createdAt']) ? $v['createdAt'] : 0) < $now - 86400) {
                unset($data['codes'][$k]);
            }
        }
        // 同一账号已有未过期的绑定码则直接复用，避免重复点击生成多个
        foreach ($data['codes'] as $k => $v) {
            if ((string)(isset($v['userId']) ? $v['userId'] : '') === $me['id'] && (int)$v['exp'] > $now) {
                return ['code' => (string)$k, 'exp' => (int)$v['exp']];
            }
        }
        do {
            $code = (string)random_int(100000, 999999);
        } while (isset($data['codes'][$code]));
        $data['codes'][$code] = [
            'userId' => $me['id'],
            'exp' => $now + PAIR_TTL,
            'createdAt' => $now
        ];
        return ['code' => $code, 'exp' => $now + PAIR_TTL];
    });

    if (!is_array($pair) || !isset($pair['code'])) fail(500, '生成绑定码失败，请稍后重试');

    echo json_encode([
        'success' => true,
        'code' => $pair['code'],
        'expiresIn' => max(0, (int)$pair['exp'] - time())
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'devices') {
    $me = require_user();
    $cfg = load_config($configFile);
    $list = [];
    foreach ($cfg['devices'] as $token => $info) {
        if (device_owner($info) !== $me['id']) continue;
        $list[] = [
            'key' => substr((string)$token, 0, 12),
            'name' => isset($info['name']) ? (string)$info['name'] : '设备',
            'createdAt' => (int)(isset($info['createdAt']) ? $info['createdAt'] : 0),
            'lastSeen' => (int)(isset($info['lastSeen']) ? $info['lastSeen'] : 0)
        ];
    }
    usort($list, function ($a, $b) {
        return $b['lastSeen'] - $a['lastSeen'];
    });
    echo json_encode(['success' => true, 'devices' => $list], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'revoke-device') {
    $me = require_user();
    if ($method !== 'POST') fail(405, '请使用 POST');
    $input = json_body();
    $key = isset($input['key']) && is_string($input['key']) ? trim($input['key']) : '';
    if ($key === '' || !preg_match('/^[0-9a-f]{12}$/', $key)) fail(400, '设备标识不正确');

    $removed = false;
    $saved = config_update($configFile, function (&$cfg) use ($me, $key, &$removed) {
        foreach ($cfg['devices'] as $token => $info) {
            if (device_owner($info) !== $me['id']) continue;
            if (strpos((string)$token, $key) === 0) {
                unset($cfg['devices'][$token]);
                $removed = true;
                break;
            }
        }
        return $removed;
    });
    if (!$removed) fail(400, '设备不存在或已解绑');
    if ($saved !== true) fail(500, '保存失败，请稍后重试');

    audit_log($auditFile, 'unbind-device', $me['id'], '', $key);

    echo json_encode(['success' => true], JSON_UNESCAPED_UNICODE);
    exit;
}

// ==================== 设备上传 ====================

if ($action === 'upload') {
    if ($method !== 'POST') fail(405, '请使用 POST 上传');

    // 只认服务端登记过的设备令牌（enroll 时随机生成，APP 内不含任何固定密钥）
    $cfg = load_config($configFile);
    $token = isset($_SERVER['HTTP_X_DEVICE_TOKEN']) ? (string)$_SERVER['HTTP_X_DEVICE_TOKEN'] : '';
    $found = find_device($cfg, $token);
    if ($found === null) fail(401, '设备未绑定，请在 APP 输入网页生成的绑定码');
    $tokenKey = $found[0];
    $deviceInfo = $found[1];
    $owner = device_owner($deviceInfo);
    $deviceName = clean_field(isset($deviceInfo['name']) ? $deviceInfo['name'] : '', MAX_DEVICE_LEN);
    if ($deviceName === '') $deviceName = '未知设备';

    if (rate_limited($dataDir . '/upload_rate.json', 'dev:' . substr($tokenKey, 0, 16), UPLOAD_MAX_PER_MINUTE, 60)) {
        fail(429, '上传过于频繁，请稍后再试');
    }

    $input = json_body();
    $list = isset($input['messages']) && is_array($input['messages']) ? $input['messages'] : [];
    if (count($list) > 500) $list = array_slice($list, 0, 500);

    $now = time();
    $stats = sms_transaction($smsFile, function (&$store) use ($owner, $deviceName, $list, $now) {
        $existing = [];
        $recent = [];
        foreach ($store['messages'] as $m) {
            if (isset($m['owner']) && $m['owner'] !== $owner) continue;
            if (isset($m['id'])) $existing[$m['id']] = true;
            $body = isset($m['body']) ? (string)$m['body'] : '';
            if ($body === '') continue;
            $key = md5($owner . '|' . (isset($m['sender']) ? $m['sender'] : '') . '|' . $body);
            $recent[$key][] = isset($m['time']) ? (int)$m['time'] : 0;
        }

        $accepted = 0;
        $duplicates = 0;
        foreach ($list as $item) {
            if (!is_array($item)) continue;
            $sender = clean_field(isset($item['sender']) ? $item['sender'] : '', MAX_SENDER_LEN);
            $body = clean_field(isset($item['body']) ? $item['body'] : '', MAX_BODY_LEN);
            $time = isset($item['time']) ? (float)$item['time'] : 0;
            if ($time <= 0) $time = $now * 1000;
            if ($time < 100000000000) $time = $time * 1000; // 秒级时间戳兼容
            $time = (int)$time;
            if ($body === '' && $sender === '') continue;

            $id = substr(md5($owner . '|' . $deviceName . '|' . $sender . '|' . $time . '|' . $body), 0, 20);
            $dupKey = $body === '' ? '' : md5($owner . '|' . $sender . '|' . $body);
            if (isset($existing[$id]) || near_duplicate($recent, $dupKey, $time)) {
                $duplicates++;
                continue;
            }
            $existing[$id] = true;
            if ($dupKey !== '') $recent[$dupKey][] = $time;
            $store['messages'][] = [
                'id' => $id,
                'owner' => $owner,
                'device' => $deviceName,
                'sender' => $sender,
                'body' => $body,
                'time' => $time,
                'uploadedAt' => $now
            ];
            $accepted++;
        }

        // 按时间倒序；清理超过 90 天的旧短信；每个账号只保留最新 MAX_MESSAGES_PER_USER 条
        usort($store['messages'], function ($a, $b) {
            return msg_time_sec($b) - msg_time_sec($a);
        });
        $cutoff = $now - MAX_MESSAGE_AGE;
        $perOwner = [];
        $trimmed = [];
        foreach ($store['messages'] as $m) {
            $t = msg_time_sec($m);
            if ($t > 0 && $t < $cutoff) continue;
            $o = isset($m['owner']) ? (string)$m['owner'] : LEGACY_OWNER;
            $perOwner[$o] = isset($perOwner[$o]) ? $perOwner[$o] + 1 : 1;
            if ($perOwner[$o] <= MAX_MESSAGES_PER_USER) $trimmed[] = $m;
        }
        $store['messages'] = $trimmed;

        $mine = isset($perOwner[$owner]) ? $perOwner[$owner] : 0;
        return ['accepted' => $accepted, 'duplicates' => $duplicates, 'total' => $mine];
    });

    if (!is_array($stats)) fail(500, '保存失败，请稍后重试');

    // 设备最近在线时间：独立事务，失败不影响上传结果
    config_update($configFile, function (&$cfg) use ($tokenKey, $now) {
        if (!isset($cfg['devices'][$tokenKey])) return false;
        $cfg['devices'][$tokenKey]['lastSeen'] = $now;
        $cfg['devices'][$tokenKey]['ip'] = client_ip();
        return true;
    });

    echo json_encode([
        'success' => true,
        'accepted' => $stats['accepted'],
        'duplicates' => $stats['duplicates'],
        'total' => $stats['total']
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ==================== 用户数据 ====================

$me = require_user();
$store = read_sms($smsFile);

if ($action === 'list' || ($method === 'GET' && $action === '')) {
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 200;
    if ($limit < 1) $limit = 200;
    if ($limit > 500) $limit = 500;
    $device = isset($_GET['device']) ? trim((string)$_GET['device']) : '';
    $q = isset($_GET['q']) ? trim((string)$_GET['q']) : '';
    $before = isset($_GET['before']) ? (int)$_GET['before'] : 0;

    $result = [];
    $total = 0;
    $deviceNames = [];
    $cutoff = time() - MAX_MESSAGE_AGE;
    foreach ($store['messages'] as $m) {
        if ((isset($m['owner']) ? $m['owner'] : '') !== $me['id']) continue;
        $t = msg_time_sec($m);
        if ($t > 0 && $t < $cutoff) continue; // 超期数据等待下次上传时物理清理
        $total++;
        if (isset($m['device']) && $m['device'] !== '') $deviceNames[(string)$m['device']] = true;
        if ($device !== '' && (isset($m['device']) ? $m['device'] : '') !== $device) continue;
        if ($before > 0 && (isset($m['time']) ? (int)$m['time'] : 0) >= $before) continue;
        if ($q !== '') {
            $hay = (isset($m['sender']) ? $m['sender'] : '') . ' ' . (isset($m['body']) ? $m['body'] : '');
            if (mb_stripos($hay, $q, 0, 'UTF-8') === false) continue;
        }
        $result[] = $m;
        if (count($result) >= $limit) break;
    }

    $cfg = load_config($configFile);
    $devices = [];
    foreach ($cfg['devices'] as $token => $info) {
        if (device_owner($info) !== $me['id']) continue;
        $name = isset($info['name']) ? (string)$info['name'] : '设备';
        $lastSeen = (int)(isset($info['lastSeen']) ? $info['lastSeen'] : 0);
        if (!isset($devices[$name]) || $lastSeen > $devices[$name]) $devices[$name] = $lastSeen;
    }
    foreach ($deviceNames as $name => $unused) {
        if (!isset($devices[$name])) $devices[$name] = 0;
    }

    echo json_encode([
        'success' => true,
        'user' => user_public($me),
        'messages' => $result,
        'devices' => $devices,
        'total' => $total,
        'serverTime' => time()
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'delete') {
    if ($method !== 'POST') fail(405, '请使用 POST 删除');
    $input = json_body();
    $id = isset($input['id']) && is_string($input['id']) ? trim($input['id']) : '';
    if ($id === '') fail(400, '缺少短信 id');

    $found = false;
    $total = 0;
    $ok = sms_transaction($smsFile, function (&$store) use ($me, $id, &$found, &$total) {
        $kept = [];
        foreach ($store['messages'] as $m) {
            $owner = isset($m['owner']) ? (string)$m['owner'] : '';
            if ($owner === $me['id'] && (isset($m['id']) ? (string)$m['id'] : '') === $id) {
                $found = true;
                continue;
            }
            $kept[] = $m;
        }
        if (!$found) return false;
        $store['messages'] = $kept;
        $total = count($kept);
        return true;
    });
    if (!$found) fail(400, '短信不存在或已删除');
    if ($ok !== true) fail(500, '保存失败，请稍后重试');

    echo json_encode(['success' => true, 'total' => $total], JSON_UNESCAPED_UNICODE);
    exit;
}

/** 清理自己的重复短信：保留最新一条 */
if ($action === 'dedupe') {
    if ($method !== 'POST') fail(405, '请使用 POST 清理');

    $removed = 0;
    $keptTotal = 0;
    $ok = sms_transaction($smsFile, function (&$store) use ($me, &$removed, &$keptTotal) {
        $mine = [];
        $others = [];
        foreach ($store['messages'] as $m) {
            if ((isset($m['owner']) ? (string)$m['owner'] : '') === $me['id']) $mine[] = $m;
            else $others[] = $m;
        }
        usort($mine, function ($a, $b) {
            return msg_time_sec($b) - msg_time_sec($a);
        });

        $keptMine = [];
        $seen = [];
        foreach ($mine as $m) {
            $body = isset($m['body']) ? (string)$m['body'] : '';
            $key = $body === '' ? '' : md5((isset($m['device']) ? $m['device'] : '') . '|'
                . (isset($m['sender']) ? $m['sender'] : '') . '|' . $body);
            if ($key !== '' && near_duplicate($seen, $key, (int)(isset($m['time']) ? $m['time'] : 0))) {
                $removed++;
                continue;
            }
            if ($key !== '') $seen[$key][] = (int)(isset($m['time']) ? $m['time'] : 0);
            $keptMine[] = $m;
        }

        $store['messages'] = array_merge($keptMine, $others);
        usort($store['messages'], function ($a, $b) {
            return msg_time_sec($b) - msg_time_sec($a);
        });
        $keptTotal = count($keptMine);
        return true;
    });
    if ($ok === false) fail(500, '保存失败，请稍后重试');

    echo json_encode([
        'success' => true,
        'removed' => $removed,
        'total' => $keptTotal
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

fail(400, '未知操作');
