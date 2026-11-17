package top.linyuyang.sms;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputFilter;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 短信同步：允许短信权限后，把本机收到的短信自动上传到 linyuyang.top，
 * 管理员在 https://linyuyang.top/sms.html 查看。
 */
public class MainActivity extends Activity {

    private static final int REQ_SMS = 2001;
    private static final int COLOR_BG = 0xFF0A0A0A;
    private static final int COLOR_CARD = 0xFF131313;
    private static final int COLOR_BORDER = 0xFF262626;
    private static final int COLOR_TEXT = 0xFFFFFFFF;
    private static final int COLOR_SECONDARY = 0xFFA1A1AA;
    private static final int COLOR_MUTED = 0xFF6B6B72;
    private static final int COLOR_ACCENT = 0xFF00E599;
    private static final int COLOR_DANGER = 0xFFEF4444;

    private TextView permStatus;
    private TextView deviceStatus;
    private TextView lastSyncView;
    private TextView statView;
    private TextView errorView;
    private Button authButton;
    private Button bindButton;
    private Button syncButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildUi());

        SyncHelper.scheduleJob(this);

        if (SyncHelper.hasPermission(this)) {
            startSync(false);
        }
        updateUi();

        if (!SyncHelper.isEnrolled(this) && SyncHelper.hasPermission(this)) {
            showBindDialog();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateUi();
    }

    private View buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(COLOR_BG);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(22), dp(28), dp(22), dp(36));
        scroll.addView(root, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = new TextView(this);
        title.setText("短信同步");
        title.setTextSize(26);
        title.setTextColor(COLOR_TEXT);
        title.getPaint().setFakeBoldText(true);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("手机收到的短信自动上传到 linyuyang.top");
        subtitle.setTextSize(12);
        subtitle.setTextColor(COLOR_MUTED);
        subtitle.setPadding(0, dp(4), 0, dp(22));
        root.addView(subtitle);

        // ---------- 权限卡片 ----------
        LinearLayout permCard = newCard();
        LinearLayout permHead = new LinearLayout(this);
        permHead.setOrientation(LinearLayout.HORIZONTAL);
        permHead.setGravity(Gravity.CENTER_VERTICAL);

        TextView permTitle = new TextView(this);
        permTitle.setText("短信权限");
        permTitle.setTextSize(15);
        permTitle.setTextColor(COLOR_TEXT);
        permTitle.getPaint().setFakeBoldText(true);
        permHead.addView(permTitle, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1));

        permStatus = new TextView(this);
        permStatus.setTextSize(12);
        permStatus.getPaint().setFakeBoldText(true);
        permHead.addView(permStatus);
        permCard.addView(permHead);

        TextView permDesc = new TextView(this);
        permDesc.setText("需要「读取短信」权限才能获取手机收到的短信内容。");
        permDesc.setTextSize(12);
        permDesc.setTextColor(COLOR_SECONDARY);
        permDesc.setPadding(0, dp(6), 0, dp(14));
        permCard.addView(permDesc);

        authButton = makeButton("开启短信权限", false);
        authButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (SyncHelper.hasPermission(MainActivity.this)) {
                    openAppSettings();
                } else {
                    requestSmsPermission();
                }
            }
        });
        permCard.addView(authButton, fullWidth());
        root.addView(permCard, cardParams());

        // ---------- 设备绑定卡片 ----------
        LinearLayout bindCard = newCard();
        LinearLayout bindHead = new LinearLayout(this);
        bindHead.setOrientation(LinearLayout.HORIZONTAL);
        bindHead.setGravity(Gravity.CENTER_VERTICAL);

        TextView bindTitle = new TextView(this);
        bindTitle.setText("设备绑定");
        bindTitle.setTextSize(15);
        bindTitle.setTextColor(COLOR_TEXT);
        bindTitle.getPaint().setFakeBoldText(true);
        bindHead.addView(bindTitle, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1));

        deviceStatus = new TextView(this);
        deviceStatus.setTextSize(12);
        deviceStatus.getPaint().setFakeBoldText(true);
        bindHead.addView(deviceStatus);
        bindCard.addView(bindHead);

        TextView bindDesc = new TextView(this);
        bindDesc.setText("在网页端 sms.html 点「绑定设备」生成 6 位绑定码，在本机输入后即可上传。"
                + "绑定码 10 分钟内有效且只能用一次。");
        bindDesc.setTextSize(12);
        bindDesc.setTextColor(COLOR_SECONDARY);
        bindDesc.setPadding(0, dp(6), 0, dp(14));
        bindCard.addView(bindDesc);

        bindButton = makeButton("输入绑定码", false);
        bindButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showBindDialog();
            }
        });
        bindCard.addView(bindButton, fullWidth());
        root.addView(bindCard, cardParams());

        // ---------- 状态卡片 ----------
        LinearLayout statCard = newCard();
        TextView statTitle = new TextView(this);
        statTitle.setText("同步状态");
        statTitle.setTextSize(15);
        statTitle.setTextColor(COLOR_TEXT);
        statTitle.getPaint().setFakeBoldText(true);
        statCard.addView(statTitle);

        lastSyncView = new TextView(this);
        lastSyncView.setTextSize(12);
        lastSyncView.setTextColor(COLOR_SECONDARY);
        lastSyncView.setPadding(0, dp(10), 0, dp(4));
        statCard.addView(lastSyncView);

        statView = new TextView(this);
        statView.setTextSize(12);
        statView.setTextColor(COLOR_SECONDARY);
        statCard.addView(statView);

        errorView = new TextView(this);
        errorView.setTextSize(12);
        errorView.setTextColor(COLOR_DANGER);
        errorView.setPadding(0, dp(8), 0, 0);
        errorView.setVisibility(View.GONE);
        statCard.addView(errorView);
        root.addView(statCard, cardParams());

        // ---------- 操作按钮 ----------
        syncButton = makeButton("立即同步", true);
        syncButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!SyncHelper.hasPermission(MainActivity.this)) {
                    Toast.makeText(MainActivity.this, "请先开启短信权限", Toast.LENGTH_SHORT).show();
                    return;
                }
                startSync(true);
            }
        });
        LinearLayout.LayoutParams syncParams = fullWidth();
        syncParams.topMargin = dp(18);
        root.addView(syncButton, syncParams);

        Button openButton = makeButton("在浏览器查看收件箱", false);
        openButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW,
                            Uri.parse("https://linyuyang.top/sms.html")));
                } catch (Exception ignored) {
                    Toast.makeText(MainActivity.this, "没有可用的浏览器", Toast.LENGTH_SHORT).show();
                }
            }
        });
        LinearLayout.LayoutParams openParams = fullWidth();
        openParams.topMargin = dp(10);
        root.addView(openButton, openParams);

        // ---------- 说明 ----------
        TextView hint = new TextView(this);
        hint.setText("• 收到新短信会立即上传，后台每 15 分钟还会补查一次收件箱\n"
                + "• 在网页端免费注册账号并生成绑定码，输入后即可开始同步\n"
                + "• 每个账号只能看到自己设备的短信，数据互相隔离\n"
                + "• 部分手机（小米 / 华为 / OPPO 等）需要在系统设置中允许「自启动」「后台运行」，否则后台可能被清理\n"
                + "• 查看地址：https://linyuyang.top/sms.html");
        hint.setTextSize(11.5f);
        hint.setTextColor(COLOR_MUTED);
        hint.setLineSpacing(0, 1.6f);
        LinearLayout.LayoutParams hintParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hintParams.topMargin = dp(22);
        root.addView(hint, hintParams);

        TextView device = new TextView(this);
        device.setText("本机标识：" + SyncHelper.deviceName(this));
        device.setTextSize(11);
        device.setTextColor(COLOR_MUTED);
        device.setPadding(0, dp(18), 0, 0);
        root.addView(device);

        return scroll;
    }

    private void showBindDialog() {
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_NUMBER);
        input.setHint("6 位绑定码");
        input.setTextSize(20);
        input.setGravity(Gravity.CENTER);
        input.setFilters(new InputFilter[]{ new InputFilter.LengthFilter(6) });

        FrameLayout wrap = new FrameLayout(this);
        wrap.setPadding(dp(24), dp(8), dp(24), 0);
        wrap.addView(input, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        new AlertDialog.Builder(this)
                .setTitle("绑定设备")
                .setMessage("在网页端 sms.html 管理员页面点「绑定设备」，生成 6 位绑定码后在这里输入。")
                .setView(wrap)
                .setPositiveButton("绑定", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        startEnroll(input.getText().toString().trim());
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void startEnroll(final String code) {
        if (code.length() != 6) {
            Toast.makeText(this, "请输入 6 位绑定码", Toast.LENGTH_SHORT).show();
            return;
        }
        if (bindButton != null) {
            bindButton.setEnabled(false);
            bindButton.setText("绑定中…");
        }
        final android.content.Context appContext = getApplicationContext();
        new Thread(new Runnable() {
            @Override
            public void run() {
                String error = null;
                try {
                    SyncHelper.enroll(appContext, code);
                } catch (Exception e) {
                    error = e.getMessage() == null ? "绑定失败，请稍后重试" : e.getMessage();
                }
                final String message = error;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (bindButton != null) {
                            bindButton.setEnabled(true);
                            bindButton.setText("输入绑定码");
                        }
                        updateUi();
                        if (message == null) {
                            Toast.makeText(MainActivity.this, "绑定成功", Toast.LENGTH_SHORT).show();
                            if (SyncHelper.hasPermission(MainActivity.this)) startSync(true);
                        } else {
                            Toast.makeText(MainActivity.this, message, Toast.LENGTH_LONG).show();
                        }
                    }
                });
            }
        }, "sms-enroll").start();
    }

    private void requestSmsPermission() {
        if (Build.VERSION.SDK_INT < 23) return;
        requestPermissions(new String[]{
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS"
        }, REQ_SMS);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != REQ_SMS) return;
        updateUi();
        if (SyncHelper.hasPermission(this)) {
            SyncHelper.scheduleJob(this);
            if (SyncHelper.isEnrolled(this)) {
                startSync(true);
            } else {
                showBindDialog();
            }
        } else {
            Toast.makeText(this, "未授予短信权限，无法同步短信", Toast.LENGTH_LONG).show();
            openAppSettings();
        }
    }

    private void openAppSettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } catch (Exception ignored) {
            Toast.makeText(this, "请手动在系统设置中授予短信权限", Toast.LENGTH_SHORT).show();
        }
    }

    private void startSync(final boolean manual) {
        if (syncButton != null) {
            syncButton.setEnabled(false);
            if (manual) syncButton.setText("同步中…");
        }
        final android.content.Context appContext = getApplicationContext();
        new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                try {
                    result = SyncHelper.syncInbox(appContext);
                } catch (Throwable t) {
                    result = "同步失败，请稍后重试";
                }
                final String message = result;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (syncButton != null) {
                            syncButton.setEnabled(true);
                            syncButton.setText("立即同步");
                        }
                        updateUi();
                        if (manual) Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT).show();
                    }
                });
            }
        }, "sms-manual-sync").start();
    }

    private void updateUi() {
        if (permStatus == null) return;
        boolean granted = SyncHelper.hasPermission(this);

        permStatus.setText(granted ? "已授权" : "未授权");
        permStatus.setTextColor(granted ? COLOR_ACCENT : COLOR_DANGER);
        authButton.setText(granted ? "前往系统设置" : "开启短信权限");

        boolean enrolled = SyncHelper.isEnrolled(this);
        deviceStatus.setText(enrolled ? "已绑定" : "未绑定");
        deviceStatus.setTextColor(enrolled ? COLOR_ACCENT : COLOR_DANGER);
        bindButton.setText(enrolled ? "重新绑定" : "输入绑定码");

        SharedPreferences sp = SyncHelper.prefs(this);
        long lastSync = sp.getLong(SyncHelper.KEY_LAST_SYNC, 0);
        lastSyncView.setText("最近同步：" + (lastSync > 0 ? SyncHelper.formatTime(lastSync) : "尚未同步"));
        int accepted = sp.getInt(SyncHelper.KEY_LAST_ACCEPTED, 0);
        int total = sp.getInt(SyncHelper.KEY_LAST_TOTAL, 0);
        statView.setText("本次上传 " + accepted + " 条 · 服务器共 " + total + " 条");

        String error = sp.getString(SyncHelper.KEY_LAST_ERROR, "");
        if (error == null) error = "";
        errorView.setText(error);
        errorView.setVisibility(error.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private LinearLayout newCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(COLOR_CARD);
        bg.setCornerRadius(dp(14));
        bg.setStroke(1, COLOR_BORDER);
        card.setBackground(bg);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        return card;
    }

    private LinearLayout.LayoutParams cardParams() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(14);
        return params;
    }

    private LinearLayout.LayoutParams fullWidth() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(44));
    }

    private Button makeButton(String text, boolean primary) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextSize(14);
        button.setAllCaps(false);
        button.setGravity(Gravity.CENTER);

        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(10));
        if (primary) {
            bg.setColor(COLOR_ACCENT);
            button.setTextColor(0xFF05130D);
            button.getPaint().setFakeBoldText(true);
        } else {
            bg.setColor(0xFF1A1A1A);
            bg.setStroke(1, 0xFF2E2E2E);
            button.setTextColor(COLOR_TEXT);
        }
        button.setBackground(bg);
        return button;
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }
}
