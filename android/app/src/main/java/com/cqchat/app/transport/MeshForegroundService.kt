package com.cqchat.app.transport

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat

/** Keeps BLE central/peripheral alive while app is backgrounded. */
class MeshForegroundService : Service() {
    private var mesh: BleMeshService? = null
    private var running = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val ch = NotificationChannel(CHANNEL, "CQchat 网格", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        val n: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("CQchat")
            .setContentText("附近扫描与广播中")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, n)
        mesh = BleMeshService(this, object : BleMeshListener {
            override fun onPacket(data: ByteArray) = Unit
            override fun onDiscover(tempId: ByteArray) = Unit
        })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action ?: ACTION_START) {
            ACTION_STOP -> {
                stopMesh()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelfResult(startId)
                return START_NOT_STICKY
            }
            ACTION_START -> startMesh()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopMesh()
        super.onDestroy()
    }

    private fun startMesh() {
        if (running) return
        running = true
        mesh?.start()
    }

    private fun stopMesh() {
        if (!running) return
        running = false
        mesh?.stop()
    }

    companion object {
        const val CHANNEL = "cqchat_mesh_fg"
        const val ACTION_START = "com.cqchat.app.transport.START_MESH"
        const val ACTION_STOP = "com.cqchat.app.transport.STOP_MESH"
        private const val NOTIFICATION_ID = 42
    }
}
