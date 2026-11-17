# 短信同步 · SMS Sync

把安卓手机收到的短信同步到你自己的网页：多账号隔离、加密存储、可私有部署。不依赖任何第三方短信云服务。

- 手机端：安卓 App 读取收件箱，通过设备令牌上传
- 服务端：PHP 7.4 + 文件存储（无数据库），AES-256-GCM 加密
- 网页端：登录、搜索、去重、删除、设备解绑、管理员面板

## 架构

```
┌──────────────┐   HTTPS + X-Device-Token   ┌──────────────┐
│  Android App │ ─────────────────────────▶ │   PHP API    │
└──────────────┘                            │  sms.php     │
                                            └──────┬───────┘
┌──────────────┐   HTTPS + 会话 Cookie             │ AES-256-GCM
│   浏览器      │ ─────────────────────────────────┤
└──────────────┘                                   ▼
                                    ┌──────────────────────────┐
                                    │  站点私有目录（Web 根外）  │
                                    │  sms.json / users.json …  │
                                    └──────────────────────────┘
```

## 功能

- 邮箱验证码注册 / 登录，密码 bcrypt 存储，密码强度校验
- 服务端会话表：退出登录、封禁账号立即失效
- 账号数据完全隔离（管理员也只能看到自己的短信）
- 设备绑定码 + 设备令牌，每账号最多 5 台，可在线解绑
- 短信 AES-256-GCM 加密落盘，密钥与数据分离
- 保留 90 天，每账号最多 3000 条，重复短信 90 秒内自动去重
- 限流：发信（全站 / 单邮箱 / 单 IP）、登录、注册、绑定、上传
- 管理员：用户列表、封禁 / 解封、审计日志
- 安卓端 TLS 证书公钥固定（Certificate Pinning）

## 快速开始

### 环境要求

- PHP 7.4+，扩展 `openssl`、`mbstring`、`json`
- Nginx / Apache，已配置 HTTPS
- 可写目录：与站点根同级的私有目录

### 部署

1. 把 `server/sms.html` 和 `server/api/` 放到站点根目录。
2. 创建与站点根同级的私有目录（PHP-FPM 用户可读写，建议 0700）：

   ```
   /var/www/example.com          ← 站点根
   /var/www/example.com_private  ← 私有目录（目录名 = 站点根目录名 + "_private"）
   ```

   若启用了 `open_basedir`，需要把私有目录加入白名单。
3. 复制 `server/smtp_config.sample.json` 到私有目录并改名为 `smtp_config.json`，填写邮箱与 SMTP 授权码。首次读取时授权码会自动加密为 `passEnc`，明文 `pass` 会被删除。
4. 打开 `https://你的域名/sms.html` 注册账号，按页面提示绑定手机。
5. 管理员令牌由你自己的管理员入口签发（本仓库不含登录页）：

   ```php
   require __DIR__ . '/api/admin_auth.php';
   setcookie('lyy_admin', admin_token_issue(), [
       'expires'  => time() + 86400,
       'path'     => '/',
       'secure'   => true,
       'httponly' => true,
       'samesite' => 'Strict',
   ]);
   ```

### 目录结构

```
server/
  sms.html                前端页面
  api/
    sms.php               主接口
    user_auth.php         账号、会话、限流、SMTP
    admin_auth.php        管理员 HMAC 令牌
  smtp_config.sample.json SMTP 配置示例
android/
  AndroidManifest.xml
  build.sh                aapt2 + javac + d8 + apksigner 构建脚本
  java/ res/
```

## SMTP 配置

```json
{
  "host": "smtp.163.com",
  "port": 465,
  "secure": "ssl",
  "user": "your_account@163.com",
  "pass": "your_smtp_auth_code",
  "from": "your_account@163.com",
  "fromName": "短信同步"
}
```

## 接口

| 方法 | `action` | 说明 |
| --- | --- | --- |
| POST | `send-code` | 发送邮箱验证码 |
| POST | `register` | 邮箱 + 验证码注册并登录 |
| POST | `login` / `logout` | 登录 / 退出（退出即撤销会话） |
| GET | `me` | 当前用户 |
| POST | `pair-code` | 生成 6 位一次性绑定码（10 分钟有效） |
| POST | `enroll` | App 用绑定码换设备令牌 |
| GET | `devices` / POST `revoke-device` | 设备列表 / 解绑 |
| POST | `upload` | 设备上传短信（请求头 `X-Device-Token`） |
| GET | `list` | 短信列表（支持 `q`、`limit`） |
| POST | `delete` / `dedupe` | 删除单条 / 清理重复 |
| GET | `admin-users` / `admin-audit` | 管理员：用户列表 / 审计日志 |
| POST | `admin-ban` | 管理员：封禁 / 解封 |

上传示例：

```bash
curl -X POST 'https://你的域名/api/sms.php?action=upload' \
  -H 'X-Device-Token: <设备令牌>' \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"sender":"10086","body":"测试短信","time":1731732000000}]}'
```

## 安卓端

需要 JDK 8+、Android SDK `build-tools;34.0.0`、`platforms;android-34`：

```bash
bash android/build.sh
```

构建前修改：

- `java/top/linyuyang/sms/SyncHelper.java` 中的 `API_URL`、`ENROLL_URL`
- `build.sh` 中的签名文件路径
- `SyncHelper.java` 的 `PINNED_SPKI_SHA256`：当前固定 TrustAsia LiteSSL CA 与根 CA 公钥指纹，更换 CA 签发后需更新并重新发版

## 安全设计

| 项目 | 做法 |
| --- | --- |
| 密码 | `password_hash`（bcrypt），最少 10 位且含字母数字 |
| 会话 | 服务端会话表 + HMAC 签名 Cookie，可即时撤销 |
| 数据 | AES-256-GCM，密钥存私有目录，不进 Web 根 |
| 传输 | 全站 HTTPS + App 端证书公钥固定 |
| 限流 | 滑动窗口，按 IP / 邮箱 / 设备维度 |
| 越权 | 所有读写按 `owner` 过滤，管理员不跨账号读取 |

已知限制：文件存储适合单机小规模（数千账号内）；未内置多租户（一套程序一个站点）；未实现 MFA；iOS 无法读取短信。

## 许可

[MIT](LICENSE)

## 免责声明

本项目用于同步**本人设备**的短信。请遵守所在地法律法规，不得用于窃取、监控他人通信或任何骚扰、诈骗用途。部署者对自己服务器上的数据负全部责任。
