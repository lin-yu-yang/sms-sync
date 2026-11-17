package top.linyuyang.sms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** 开机或升级后重新登记定时同步任务 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (context == null) return;
        try {
            SyncHelper.scheduleJob(context.getApplicationContext());
        } catch (Throwable ignored) {
            /* 忽略 */
        }
    }
}
