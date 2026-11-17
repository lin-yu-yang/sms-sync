package top.linyuyang.sms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.telephony.SmsMessage;

import java.util.ArrayList;
import java.util.List;

/** 收到新短信广播：立刻上传到服务器 */
public class SmsReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (action == null || !"android.provider.Telephony.SMS_RECEIVED".equals(action)) return;

        final List<SyncHelper.Msg> messages = parse(intent);
        final Context appContext = context.getApplicationContext();
        final PendingResult pending = goAsync();

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // 优先从收件箱同步：收件箱里是系统合并后的完整短信，且时间戳唯一，
                    // 可以避免多段短信被拆开、以及广播时间与收件箱时间不一致导致的重复上传
                    String first = SyncHelper.syncInbox(appContext);
                    if ("没有新短信".equals(first)) {
                        // 个别机型收件箱写入有延迟，稍等再试一次
                        Thread.sleep(2000);
                        String second = SyncHelper.syncInbox(appContext);
                        if ("没有新短信".equals(second)) {
                            // 收件箱里始终没有，则退回到直接上传广播里的短信
                            SyncHelper.uploadReceived(appContext, messages);
                        }
                    }
                } catch (Throwable ignored) {
                    /* 失败由定时任务补传 */
                } finally {
                    pending.finish();
                }
            }
        }, "sms-upload").start();
    }

    private List<SyncHelper.Msg> parse(Intent intent) {
        List<SyncHelper.Msg> list = new ArrayList<>();
        Object[] pdus = null;
        try {
            Object extra = intent.getExtras() == null ? null : intent.getExtras().get("pdus");
            if (extra instanceof Object[]) pdus = (Object[]) extra;
        } catch (Exception ignored) {
            /* 广播格式异常时退回收件箱同步 */
        }
        if (pdus == null) return list;

        String format = null;
        try {
            format = intent.getStringExtra("format");
        } catch (Exception ignored) {
            /* 老系统没有 format */
        }

        for (Object pdu : pdus) {
            try {
                SmsMessage sms = Build.VERSION.SDK_INT >= 23
                        ? SmsMessage.createFromPdu((byte[]) pdu, format)
                        : SmsMessage.createFromPdu((byte[]) pdu);
                if (sms == null) continue;
                SyncHelper.Msg msg = new SyncHelper.Msg();
                String address = sms.getDisplayOriginatingAddress();
                if (address == null) address = sms.getOriginatingAddress();
                msg.sender = address == null ? "" : address;
                msg.body = sms.getMessageBody() == null ? "" : sms.getMessageBody();
                msg.time = sms.getTimestampMillis();
                if (msg.time <= 0) msg.time = System.currentTimeMillis();
                list.add(msg);
            } catch (Throwable ignored) {
                /* 单条解析失败不影响其他 */
            }
        }
        return list;
    }
}
