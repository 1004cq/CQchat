package com.cqchat.app.notify

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

class LocalNotifier(private val context: Context) {
    init {
        val ch = NotificationChannel(CHANNEL, "CQchat", NotificationManager.IMPORTANCE_DEFAULT)
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(ch)
    }

    fun message(title: String, body: String) {
        val n = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(title)
            .setContentText(body)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(context).notify((System.currentTimeMillis() % Int.MAX_VALUE).toInt(), n)
        } catch (_: SecurityException) {
        }
    }

    fun nearby(name: String) = message("附近的人", "发现 $name")

    fun favoriteNearby(name: String) = message("收藏的人出现了", name)

    companion object {
        const val CHANNEL = "cqchat_local"
    }
}
