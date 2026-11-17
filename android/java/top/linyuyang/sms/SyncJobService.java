package top.linyuyang.sms;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.os.Build;

/** 后台定时同步（15 分钟一次），需要网络可用 */
public class SyncJobService extends JobService {

    @Override
    public boolean onStartJob(final JobParameters params) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (SyncHelper.hasPermission(getApplicationContext())) {
                        SyncHelper.syncInbox(getApplicationContext());
                    }
                } catch (Throwable ignored) {
                    /* 下一轮再试 */
                } finally {
                    if (Build.VERSION.SDK_INT >= 21) jobFinished(params, false);
                }
            }
        }, "sms-job").start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true; // 中断后重新排队
    }
}
