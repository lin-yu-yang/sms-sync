<?php
/**
 * 管理员签名令牌
 *
 * 登录成功后由 api/auth.php 下发 HttpOnly Cookie「lyy_admin」，
 * 值为「过期时间戳.HMAC-SHA256(过期时间戳, 服务端密钥)」。
 * 密钥保存在与站根同级的私有目录（Web 根之外，0600），
 * 迁移前会兼容读取旧的 data/admin_secret。
 * 因此客户端无法伪造管理员身份（旧的 cloud_disk_authenticated=true 可被任意伪造）。
 */

function admin_secret() {
    static $secret = null;
    if ($secret !== null) return $secret;

    $dir = dirname(__DIR__, 2) . '/' . basename(dirname(__DIR__)) . '_private';
    $file = $dir . '/admin_secret';
    $legacy = __DIR__ . '/../data/admin_secret';

    if (!is_file($file) && is_file($legacy)) {
        $secret = trim((string)@file_get_contents($legacy));
        return $secret;
    }
    if (!is_file($file)) {
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

/** 令牌有效期（秒） */
function admin_token_ttl() {
    return 86400;
}

/** 生成新令牌 */
function admin_token_issue($ttl = null) {
    $exp = time() + ($ttl === null ? admin_token_ttl() : $ttl);
    return $exp . '.' . hash_hmac('sha256', (string)$exp, admin_secret());
}

/** 校验令牌格式、签名与有效期 */
function admin_token_check($value) {
    if (!is_string($value) || !preg_match('/^(\d{9,12})\.([0-9a-f]{64})$/', $value, $m)) return false;
    if ((int)$m[1] < time()) return false;
    return hash_equals(hash_hmac('sha256', $m[1], admin_secret()), $m[2]);
}

/** 当前请求是否携带有效管理员令牌 */
function admin_session_valid() {
    return admin_token_check(isset($_COOKIE['lyy_admin']) ? $_COOKIE['lyy_admin'] : '');
}
