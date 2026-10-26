package com.cqchat.app.transport

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.cqchat.app.ui.MainActivity

/**
 * Owns nearby-mode lifetime. Start only after BLE permissions are granted.
 * Stops when nearby mode is turned off — does not outlive user intent.
 */
class MeshForegroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val ch = NotificationChannel(CHANNEL, "CQchat 附近模式", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val open = PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                val n: Notification = NotificationCompat.Builder(this, CHANNEL)
                    .setContentTitle("CQchat 附近模式")
                    .setContentText("正在扫描与广播（系统可能限制后台）")
                    .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                    .setContentIntent(open)
                    .setOngoing(true)
                    .build()
                if (Build.VERSION.SDK_INT >= 34) {
                    startForeground(
                        NOTIF_ID, n,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
                    )
                } else {
                    startForeground(NOTIF_ID, n)
                }
            }
        }
        return START_STICKY
    }

    companion object {
        const val CHANNEL = "cqchat_mesh_fg"
        const val NOTIF_ID = 42
        const val ACTION_STOP = "com.cqchat.app.STOP_NEARBY"

        fun start(ctx: Context) {
            val i = Intent(ctx, MeshForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            val i = Intent(ctx, MeshForegroundService::class.java).setAction(ACTION_STOP)
            ctx.startService(i)
        }
    }
}
