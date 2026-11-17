package top.linyuyang.sms;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * 短信读取与上传：读取系统短信收件箱，批量 POST 到 linyuyang.top。
 * 同一设备由服务器按 号码+时间+内容 去重，重复上传不会产生重复记录。
 */
final class SyncHelper {

    static final String PREFS = "sms_sync";
    static final String KEY_LAST_SYNC = "lastSyncAt";
    static final String KEY_LAST_ACCEPTED = "lastAccepted";
    static final String KEY_LAST_TOTAL = "lastTotal";
    static final String KEY_LAST_ERROR = "lastError";
    static final String KEY_LAST_DATE = "lastMessageDate";
    static final String KEY_DEVICE_TOKEN = "deviceToken";

    private static final String API_URL = "https://linyuyang.top/api/sms.php?action=upload";
    private static final String ENROLL_URL = "https://linyuyang.top/api/sms.php?action=enroll";
    private static final Uri INBOX = Uri.parse("content://sms/inbox");
    private static final int MAX_BATCH = 300;
    private static final int JOB_ID = 1101;

    /**
     * 证书固定：证书链中任一证书的公钥 SPKI SHA-256 命中即放行。
     * 这里固定 TrustAsia LiteSSL RSA CA 2025 与 TrustAsia TLS RSA Root CA，
     * 换发新的站点证书（叶证书）时中间 CA 不变，同步不会中断；
     * 若签发 CA 被替换，需要重新发版更新指纹。
     */
    private static final String[] PINNED_SPKI_SHA256 = {
            "Wt2ZC+IE3Cpf6hRflokHnxyZR+ZD82TqFkj1/fmYndc=",
            "ViiHLiRf5mFIuAut6snED2JS5kL6lZWuzks+ili4/UY="
    };
    private static SSLSocketFactory pinnedFactory;

    private SyncHelper() {
    }

    static class Msg {
        String sender = "";
        String body = "";
        long time;
    }

    static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static String deviceName(Context context) {
        String name = (Build.MANUFACTURER + " " + Build.MODEL).trim();
        if (name.isEmpty()) name = "安卓手机";
        if (name.length() > 40) name = name.substring(0, 40);
        return name;
    }

    static boolean hasPermission(Context context) {
        if (Build.VERSION.SDK_INT < 23) return true;
        return context.checkSelfPermission("android.permission.READ_SMS") == 0
                && context.checkSelfPermission("android.permission.RECEIVE_SMS") == 0;
    }

    /** 本机已绑定的设备令牌（为空表示尚未绑定） */
    static String token(Context context) {
        String token = prefs(context).getString(KEY_DEVICE_TOKEN, "");
        return token == null ? "" : token;
    }

    static void setToken(Context context, String token) {
        prefs(context).edit().putString(KEY_DEVICE_TOKEN, token == null ? "" : token).apply();
    }

    static boolean isEnrolled(Context context) {
        return token(context).length() >= 32;
    }

    /** 用网页生成的 6 位一次性绑定码换取设备令牌，并保存到本机 */
    static String enroll(Context context, String code) throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("code", code);
        payload.put("device", deviceName(context));
        JSONObject result = post(context, ENROLL_URL, payload.toString(), false);
        String token = result.optString("token", "");
        if (token.length() < 32) throw new Exception("服务器返回的设备令牌无效");
        setToken(context, token);
        return token;
    }

    /** 读取收件箱；since 为 0 时读取最近一批 */
    static List<Msg> readInbox(Context context, long since, int limit) {
        List<Msg> list = new ArrayList<>();
        ContentResolver resolver = context.getContentResolver();
        Cursor cursor = null;
        try {
            String[] projection = new String[]{"address", "body", "date"};
            String selection = since > 0 ? ("date >= " + since) : null;
            cursor = resolver.query(INBOX, projection, selection, null, "date DESC");
            if (cursor == null) return list;
            while (cursor.moveToNext() && list.size() < limit) {
                String address = cursor.getString(0);
                String body = cursor.getString(1);
                long date = cursor.getLong(2);
                if (TextUtils.isEmpty(address) && TextUtils.isEmpty(body)) continue;
                Msg msg = new Msg();
                msg.sender = address == null ? "" : address;
                msg.body = body == null ? "" : body;
                msg.time = date > 0 ? date : System.currentTimeMillis();
                list.add(msg);
            }
        } finally {
            if (cursor != null) cursor.close();
        }
        return list;
    }

    /** 上传一批短信，返回服务器响应 */
    static JSONObject upload(Context context, List<Msg> messages) throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("device", deviceName(context));
        JSONArray array = new JSONArray();
        for (Msg msg : messages) {
            JSONObject item = new JSONObject();
            item.put("sender", msg.sender);
            String body = msg.body;
            if (body.length() > 2000) body = body.substring(0, 2000);
            item.put("body", body);
            item.put("time", msg.time);
            array.put(item);
        }
        payload.put("messages", array);
        return post(context, API_URL, payload.toString(), true);
    }

    private static String spkiSha256(X509Certificate cert) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.encodeToString(digest.digest(cert.getPublicKey().getEncoded()), Base64.NO_WRAP);
        } catch (Exception e) {
            return "";
        }
    }

    /** 先做系统 CA 校验，再校验证书链公钥指纹（防中间人劫持） */
    private static synchronized SSLSocketFactory pinnedFactory() throws Exception {
        if (pinnedFactory != null) return pinnedFactory;

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        X509TrustManager system = null;
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                system = (X509TrustManager) tm;
                break;
            }
        }
        if (system == null) throw new Exception("系统证书库不可用");
        final X509TrustManager delegate = system;

        X509TrustManager pinning = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                delegate.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                delegate.checkServerTrusted(chain, authType);
                if (chain == null) throw new CertificateException("服务器证书链为空");
                for (X509Certificate cert : chain) {
                    String pin = spkiSha256(cert);
                    for (String expected : PINNED_SPKI_SHA256) {
                        if (expected.equals(pin)) return;
                    }
                }
                throw new CertificateException("服务器证书指纹不匹配，已阻止连接");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return delegate.getAcceptedIssuers();
            }
        };

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{pinning}, new SecureRandom());
        pinnedFactory = context.getSocketFactory();
        return pinnedFactory;
    }

    private static JSONObject post(Context context, String apiUrl, String body, boolean auth) throws Exception {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(apiUrl);
            conn = (HttpURLConnection) url.openConnection();
            if (conn instanceof HttpsURLConnection) {
                ((HttpsURLConnection) conn).setSSLSocketFactory(pinnedFactory());
            }
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(20000);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            if (auth) {
                String token = token(context);
                if (token.isEmpty()) throw new Exception("设备未绑定，请先输入网页生成的绑定码");
                conn.setRequestProperty("X-Device-Token", token);
            }
            conn.setRequestProperty("User-Agent", "LinSmsSync/1.5");

            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes("UTF-8"));
            os.close();

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
            StringBuilder sb = new StringBuilder();
            if (is != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
                reader.close();
            }

            JSONObject json = sb.length() == 0 ? new JSONObject() : new JSONObject(sb.toString());
            if (code == 401) {
                // 令牌被服务端作废（例如清空设备登记），清除本机令牌以便重新绑定
                setToken(context, "");
            }
            if (code != 200 || !json.optBoolean("success")) {
                String message = json.optString("message", "服务器返回 " + code);
                throw new Exception(message);
            }
            return json;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** 同步收件箱：首次上传最近的历史短信，之后只上传增量 */
    static String syncInbox(Context context) {
        if (!isEnrolled(context)) {
            prefs(context).edit().putString(KEY_LAST_ERROR, "设备未绑定，请先输入网页生成的绑定码").apply();
            return "设备未绑定，请先输入绑定码";
        }
        SharedPreferences sp = prefs(context);
        long lastDate = sp.getLong(KEY_LAST_DATE, 0);
        long since = lastDate > 0 ? lastDate - 60000L : 0;
        try {
            List<Msg> messages = readInbox(context, since, MAX_BATCH);
            if (messages.isEmpty()) {
                sp.edit().putLong(KEY_LAST_SYNC, System.currentTimeMillis())
                        .putString(KEY_LAST_ERROR, "").apply();
                return "没有新短信";
            }
            JSONObject result = upload(context, messages);
            long newest = 0;
            for (Msg msg : messages) {
                if (msg.time > newest) newest = msg.time;
            }
            int accepted = result.optInt("accepted");
            sp.edit()
                    .putLong(KEY_LAST_SYNC, System.currentTimeMillis())
                    .putInt(KEY_LAST_ACCEPTED, accepted)
                    .putInt(KEY_LAST_TOTAL, result.optInt("total"))
                    .putLong(KEY_LAST_DATE, newest > lastDate ? newest : lastDate)
                    .putString(KEY_LAST_ERROR, "")
                    .apply();
            return accepted > 0 ? ("新上传 " + accepted + " 条") : "已是最新";
        } catch (SecurityException e) {
            sp.edit().putString(KEY_LAST_ERROR, "缺少短信权限，请在系统设置中允许读取短信").apply();
            return "缺少短信权限";
        } catch (Exception e) {
            String message = e.getMessage() == null ? "网络异常" : e.getMessage();
            sp.edit().putString(KEY_LAST_ERROR, message).apply();
            return "同步失败：" + message;
        }
    }

    /** 收到新短信时直接上传这一批（比读收件箱更快） */
    static String uploadReceived(Context context, List<Msg> messages) {
        if (messages.isEmpty()) return syncInbox(context);
        if (!isEnrolled(context)) return syncInbox(context);
        SharedPreferences sp = prefs(context);
        try {
            JSONObject result = upload(context, messages);
            long newest = 0;
            for (Msg msg : messages) {
                if (msg.time > newest) newest = msg.time;
            }
            long lastDate = sp.getLong(KEY_LAST_DATE, 0);
            sp.edit()
                    .putLong(KEY_LAST_SYNC, System.currentTimeMillis())
                    .putInt(KEY_LAST_ACCEPTED, result.optInt("accepted"))
                    .putInt(KEY_LAST_TOTAL, result.optInt("total"))
                    .putLong(KEY_LAST_DATE, newest > lastDate ? newest : lastDate)
                    .putString(KEY_LAST_ERROR, "")
                    .apply();
            return "已上传";
        } catch (Exception e) {
            // 直接上传失败时退回收件箱补传
            return syncInbox(context);
        }
    }

    /** 定时任务：每 15 分钟检查一次收件箱，弥补个别机型收不到广播的情况 */
    static void scheduleJob(Context context) {
        if (Build.VERSION.SDK_INT < 21) return;
        try {
            JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
            if (scheduler == null) return;
            JobInfo job = new JobInfo.Builder(JOB_ID, new ComponentName(context, SyncJobService.class))
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPeriodic(15 * 60 * 1000L)
                    .setPersisted(true)
                    .build();
            scheduler.schedule(job);
        } catch (Exception ignored) {
            /* 部分系统限制定时任务时忽略，广播仍可上传 */
        }
    }

    static String formatTime(long ms) {
        if (ms <= 0) return "—";
        SimpleDateFormat format = new SimpleDateFormat("MM-dd HH:mm", Locale.CHINA);
        format.setTimeZone(TimeZone.getTimeZone("Asia/Shanghai"));
        return format.format(new Date(ms));
    }
}
