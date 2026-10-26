package com.cqchat.app.transport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import com.cqchat.app.protocol.CQ
import com.cqchat.app.protocol.TcpFrame
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.concurrent.thread

interface HotspotListener {
    fun onPacket(data: ByteArray)
    fun onPeersChanged(count: Int)
}

class HotspotTcpService(
    context: Context,
    private val listener: HotspotListener,
) {
    private val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val peers = ConcurrentHashMap<String, Socket>()
    private val pool = Executors.newCachedThreadPool()
    private var server: ServerSocket? = null
    @Volatile private var running = false

    val hasPeers: Boolean get() = peers.isNotEmpty()

    fun start() {
        running = true
        thread(name = "cq-tcp-listen") {
            try {
                server = ServerSocket(CQ.TCP_PORT)
                registerService()
                while (running) {
                    val s = server?.accept() ?: break
                    pool.execute { handleClient(s) }
                }
            } catch (_: Exception) {
            }
        }
        nsd.discoverServices(CQ.MDNS_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
    }

    fun stop() {
        running = false
        try { server?.close() } catch (_: Exception) {}
        peers.values.forEach { try { it.close() } catch (_: Exception) {} }
        peers.clear()
        try { nsd.stopServiceDiscovery(discoveryListener) } catch (_: Exception) {}
        try { nsd.unregisterService(registrationListener) } catch (_: Exception) {}
    }

    fun send(packet: ByteArray): Boolean {
        if (peers.isEmpty()) return false
        val frame = TcpFrame.encode(packet)
        for (s in peers.values) {
            pool.execute {
                try {
                    DataOutputStream(s.getOutputStream()).apply {
                        write(frame)
                        flush()
                    }
                } catch (_: Exception) {
                }
            }
        }
        return true
    }

    private fun registerService() {
        val info = NsdServiceInfo().apply {
            serviceName = "cqchat"
            serviceType = CQ.MDNS_TYPE
            port = CQ.TCP_PORT
            setAttribute("v", "1")
        }
        nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, registrationListener)
    }

    private fun handleClient(socket: Socket) {
        val key = socket.remoteSocketAddress?.toString() ?: return
        peers[key] = socket
        listener.onPeersChanged(peers.size)
        try {
            val input = DataInputStream(socket.getInputStream())
            while (running && !socket.isClosed) {
                val len = input.readInt()
                if (len <= 0 || len > 8_000_000) break
                val body = ByteArray(len)
                input.readFully(body)
                listener.onPacket(body)
            }
        } catch (_: Exception) {
        } finally {
            peers.remove(key)
            listener.onPeersChanged(peers.size)
            try { socket.close() } catch (_: Exception) {}
        }
    }

    private val registrationListener = object : NsdManager.RegistrationListener {
        override fun onServiceRegistered(serviceInfo: NsdServiceInfo) {}
        override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
        override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) {}
        override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
    }

    private val discoveryListener = object : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(regType: String) {}
        override fun onServiceFound(service: NsdServiceInfo) {
            nsd.resolveService(service, object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
                override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                    pool.execute {
                        try {
                            val s = Socket(serviceInfo.host, serviceInfo.port)
                            handleClient(s)
                        } catch (_: Exception) {
                        }
                    }
                }
            })
        }
        override fun onServiceLost(service: NsdServiceInfo) {}
        override fun onDiscoveryStopped(serviceType: String) {}
        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
    }
}
