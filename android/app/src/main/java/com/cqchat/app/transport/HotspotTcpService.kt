package com.cqchat.app.transport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import com.cqchat.app.protocol.CQ
import com.cqchat.app.protocol.TcpFrame
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
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
    private val discovered = ConcurrentHashMap<String, Endpoint>()
    private val serviceEndpoints = ConcurrentHashMap<String, MutableSet<String>>()
    private val reconnects = ConcurrentHashMap<String, ScheduledFuture<*>>()
    private val connecting = ConcurrentHashMap.newKeySet<String>()
    private val stateLock = Any()
    private var pool: ThreadPoolExecutor? = null
    private var scheduler: ScheduledThreadPoolExecutor? = null
    private var server: ServerSocket? = null
    @Volatile private var running = false

    val hasPeers: Boolean get() = peers.isNotEmpty()

    fun start() {
        synchronized(stateLock) {
            if (running) return
            running = true
            pool = newPool()
            scheduler = ScheduledThreadPoolExecutor(1)
            scheduler?.removeOnCancelPolicy = true
        }
        thread(name = "cq-tcp-listen", isDaemon = true) { listenLoop() }
        try {
            nsd.discoverServices(CQ.MDNS_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
        } catch (_: Exception) {
            // Discovery failure must not prevent incoming TCP connections.
        }
    }

    fun stop() {
        synchronized(stateLock) {
            if (!running) return
            running = false
        }
        try { nsd.stopServiceDiscovery(discoveryListener) } catch (_: Exception) {}
        try { nsd.unregisterService(registrationListener) } catch (_: Exception) {}
        reconnects.values.forEach { it.cancel(false) }
        reconnects.clear()
        reconnectAttempts.clear()
        discovered.clear()
        serviceEndpoints.clear()
        connecting.clear()
        try { server?.close() } catch (_: Exception) {}
        server = null
        peers.values.toList().forEach { try { it.close() } catch (_: Exception) {} }
        peers.clear()
        notifyPeersChanged()
        pool?.shutdownNow()
        scheduler?.shutdownNow()
        pool = null
        scheduler = null
    }

    fun send(packet: ByteArray): Boolean {
        if (!running || peers.isEmpty() || packet.size > CQ.TCP_MAX_FRAME_BYTES) return false
        val frame = TcpFrame.encode(packet)
        var accepted = false
        peers.values.toList().forEach { socket ->
            try {
                pool?.execute {
                    try {
                        writeFrame(socket, frame)
                    } catch (_: Exception) {
                        closePeer(socket)
                    }
                }
                accepted = true
            } catch (_: RejectedExecutionException) {
                // A full queue provides backpressure instead of creating more threads.
            }
        }
        return accepted
    }

    private fun newPool(): ThreadPoolExecutor = ThreadPoolExecutor(
        2,
        CQ.TCP_MAX_WORKERS,
        30L,
        TimeUnit.SECONDS,
        java.util.concurrent.ArrayBlockingQueue(CQ.TCP_WORK_QUEUE),
        Executors.defaultThreadFactory(),
        ThreadPoolExecutor.AbortPolicy(),
    )

    private fun listenLoop() {
        try {
            ServerSocket().also {
                it.reuseAddress = true
                it.bind(InetSocketAddress(CQ.TCP_PORT))
                server = it
            }
            if (!running) {
                server?.close()
                return
            }
            registerService()
            while (running) {
                val socket = server?.accept() ?: break
                socket.tcpNoDelay = true
                socket.soTimeout = CQ.TCP_READ_TIMEOUT_MS
                submitClient(socket, null)
            }
        } catch (_: SocketException) {
            // Expected when stop() closes the server socket.
        } catch (_: Exception) {
            if (running) server?.close()
        }
    }

    private fun submitClient(socket: Socket, endpoint: String?) {
        try {
            pool?.execute { handleClient(socket, endpoint) } ?: socket.close()
        } catch (_: RejectedExecutionException) {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    private fun registerService() {
        val info = NsdServiceInfo().apply {
            serviceName = "cqchat"
            serviceType = CQ.MDNS_TYPE
            port = CQ.TCP_PORT
            setAttribute("v", "1")
        }
        try { nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, registrationListener) } catch (_: Exception) {}
    }

    private fun handleClient(socket: Socket, endpoint: String?) {
        val key = socket.remoteSocketAddress?.toString() ?: socket.toString()
        val previous = peers.putIfAbsent(key, socket)
        if (previous != null) {
            try { socket.close() } catch (_: Exception) {}
            if (endpoint != null) connecting.remove(endpoint)
            return
        }
        if (endpoint != null) reconnectAttempts.remove(endpoint)
        notifyPeersChanged()
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())
        var lastActivity = System.nanoTime()
        try {
            while (running && !socket.isClosed) {
                try {
                    val length = input.readInt()
                    lastActivity = System.nanoTime()
                    when {
                        length == CQ.TCP_PING_FRAME -> writeControl(socket, output, CQ.TCP_PONG_FRAME)
                        length == CQ.TCP_PONG_FRAME -> Unit
                        length <= 0 || length > CQ.TCP_MAX_FRAME_BYTES -> break
                        else -> {
                            val body = ByteArray(length)
                            input.readFully(body)
                            listener.onPacket(body)
                        }
                    }
                } catch (_: SocketTimeoutException) {
                    val idleMs = (System.nanoTime() - lastActivity) / 1_000_000L
                    if (idleMs >= CQ.TCP_HEARTBEAT_TIMEOUT_MS) break
                    writeControl(socket, output, CQ.TCP_PING_FRAME)
                }
            }
        } catch (_: Exception) {
            // Disconnects and malformed frames are cleaned up in finally.
        } finally {
            peers.remove(key, socket)
            notifyPeersChanged()
            try { socket.close() } catch (_: Exception) {}
            if (endpoint != null) {
                connecting.remove(endpoint)
                scheduleReconnect(endpoint)
            }
        }
    }

    private fun writeFrame(socket: Socket, frame: ByteArray) {
        synchronized(socket) {
            DataOutputStream(socket.getOutputStream()).apply {
                write(frame)
                flush()
            }
        }
    }

    private fun writeControl(socket: Socket, output: DataOutputStream, code: Int) {
        // Data frames use the same socket lock. A separate output-stream lock
        // would still allow PING/PONG bytes to interleave with a data frame.
        synchronized(socket) {
            output.writeInt(code)
            output.flush()
        }
    }

    private fun closePeer(socket: Socket) {
        try { socket.close() } catch (_: Exception) {}
        peers.entries.firstOrNull { it.value === socket }?.let { peers.remove(it.key, socket) }
        notifyPeersChanged()
    }

    private fun notifyPeersChanged() {
        if (running) listener.onPeersChanged(peers.size)
    }

    private fun connect(endpoint: Endpoint) {
        if (!running || !connecting.add(endpoint.key)) return
        try {
            val socket = Socket()
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(endpoint.host, endpoint.port), CQ.TCP_CONNECT_TIMEOUT_MS)
            socket.soTimeout = CQ.TCP_READ_TIMEOUT_MS
            submitClient(socket, endpoint.key)
        } catch (_: Exception) {
            connecting.remove(endpoint.key)
            scheduleReconnect(endpoint.key)
        }
    }

    private fun scheduleReconnect(key: String) {
        val endpoint = discovered[key] ?: return
        val attempt = reconnectAttempts.compute(key) { _, old -> ((old ?: 0) + 1).coerceAtMost(CQ.TCP_MAX_RECONNECT_ATTEMPTS) } ?: 1
        if (attempt > CQ.TCP_MAX_RECONNECT_ATTEMPTS || !running) return
        reconnects.remove(key)?.cancel(false)
        val delay = (CQ.TCP_RECONNECT_BASE_DELAY_MS shl (attempt - 1).coerceAtMost(5))
            .coerceAtMost(CQ.TCP_RECONNECT_MAX_DELAY_MS)
        scheduler?.let { exec ->
            try {
                reconnects[key] = exec.schedule({ reconnects.remove(key); connect(endpoint) }, delay, TimeUnit.MILLISECONDS)
            } catch (_: RejectedExecutionException) {}
        }
    }

    private val reconnectAttempts = ConcurrentHashMap<String, Int>()

    private data class Endpoint(val host: java.net.InetAddress, val port: Int) {
        val key: String get() = "${host.hostAddress}:$port"
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
            try {
                nsd.resolveService(service, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
                    override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                        val host = serviceInfo.host ?: return
                        val endpoint = Endpoint(host, serviceInfo.port)
                        if (discovered.putIfAbsent(endpoint.key, endpoint) == null) {
                            serviceEndpoints.computeIfAbsent(serviceInfo.serviceName) {
                                ConcurrentHashMap.newKeySet()
                            }.add(endpoint.key)
                            reconnectAttempts.remove(endpoint.key)
                            connect(endpoint)
                        }
                    }
                })
            } catch (_: Exception) {}
        }
        override fun onServiceLost(service: NsdServiceInfo) {
            val keys = serviceEndpoints.remove(service.serviceName).orEmpty()
            keys.forEach { key ->
                discovered.remove(key)
                reconnects.remove(key)?.cancel(false)
                connecting.remove(key)
                reconnectAttempts.remove(key)
            }
        }
        override fun onDiscoveryStopped(serviceType: String) {}
        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
    }
}
