package com.cqchat.app.transport

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import com.cqchat.app.chat.DedupCache
import com.cqchat.app.protocol.CQ
import com.cqchat.app.protocol.CQPacket
import com.cqchat.app.protocol.BleMiniFragmenter
import com.cqchat.app.protocol.BleMiniReassembler
import com.cqchat.app.protocol.BleMeshPacketCodec
import com.cqchat.app.protocol.FragmentReassembler
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

interface BleMeshListener {
    fun onPacket(data: ByteArray)
    fun onDiscover(tempId: ByteArray)
}

@SuppressLint("MissingPermission")
class BleMeshService(
    private val context: Context,
    private val listener: BleMeshListener,
) {
    private val adapter: BluetoothAdapter? =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
    private val handler = Handler(Looper.getMainLooper())
    private val lock = Any()

    private var started = false
    private var generation = 0L
    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var scanner: BluetoothLeScanner? = null
    private val connections = ConcurrentHashMap<String, Connection>()
    private val knownDevices = ConcurrentHashMap<String, BluetoothDevice>()
    private val retryCounts = ConcurrentHashMap<String, Int>()
    private val retryRunnables = ConcurrentHashMap<String, Runnable>()
    private val serverPayloadByAddress = ConcurrentHashMap<String, Int>()
    private val notificationQueues = ConcurrentHashMap<String, ArrayDeque<ByteArray>>()
    private val notificationBusy = ConcurrentHashMap<String, Boolean>()
    private val dedup = DedupCache()
    private val reassembler = FragmentReassembler()
    private val miniReassembler = BleMiniReassembler()

    @Volatile
    var tempId: ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }
        private set

    private val rotate = object : Runnable {
        override fun run() {
            if (!isStarted()) return
            SecureRandom().nextBytes(tempId)
            startAdvertising()
            handler.postDelayed(this, CQ.TEMP_ID_ROTATE_SECS * 1000)
        }
    }

    private class Connection(
        val address: String,
        val gatt: BluetoothGatt,
        val generation: Long,
    ) {
        val queue: ArrayDeque<Op> = ArrayDeque()
        var busy = false
        var mtuPayload = DEFAULT_ATT_PAYLOAD
        var inbox: BluetoothGattCharacteristic? = null
        var retryCount = 0
    }

    private sealed class Op {
        class Mtu : Op()
        class Discover : Op()
        class Cccd(val characteristic: BluetoothGattCharacteristic, val descriptor: BluetoothGattDescriptor) : Op()
        class Write(val characteristic: BluetoothGattCharacteristic, val value: ByteArray) : Op()
    }

    fun start() {
        synchronized(lock) {
            if (started) return
            started = true
            generation++
            val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            gattServer = mgr.openGattServer(context, serverCallback)
            val service = BluetoothGattService(CQ.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            val inbox = BluetoothGattCharacteristic(
                CQ.INBOX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE or
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or
                    BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_WRITE or BluetoothGattCharacteristic.PERMISSION_READ,
            )
            inbox.addDescriptor(BluetoothGattDescriptor(UUID_CCCD, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE))
            service.addCharacteristic(inbox)
            gattServer?.addService(service)
            advertiser = adapter?.bluetoothLeAdvertiser
            scanner = adapter?.bluetoothLeScanner
            startAdvertising()
            startScanning()
            handler.postDelayed(rotate, CQ.TEMP_ID_ROTATE_SECS * 1000)
        }
    }

    fun stop() {
        val oldConnections: List<Connection>
        synchronized(lock) {
            if (!started) return
            started = false
            generation++ // invalidates every callback already in flight
            handler.removeCallbacksAndMessages(null)
            advertiser?.stopAdvertising(advertiseCallback)
            scanner?.stopScan(scanCallback)
            retryRunnables.clear()
            oldConnections = connections.values.toList()
            connections.clear()
            knownDevices.clear()
            retryCounts.clear()
            serverPayloadByAddress.clear()
            notificationQueues.clear()
            notificationBusy.clear()
            reassembler.clear()
            miniReassembler.clear()
            oldConnections.forEach { connection ->
                connection.queue.clear()
                connection.busy = false
                connection.gatt.disconnect()
                connection.gatt.close()
            }
            gattServer?.close()
            gattServer = null
            advertiser = null
            scanner = null
        }
    }

    fun send(packetData: ByteArray) {
        if (!isStarted()) return
        val serverDevices = gattServer?.connectedDevices.orEmpty()
        for (device in serverDevices) {
            val maxPayload = serverPayloadByAddress[device.address] ?: DEFAULT_ATT_PAYLOAD
            val chunks = packetChunks(packetData, maxPayload)
            chunks.forEach { chunk -> enqueueNotification(device, chunk) }
        }
        connections.values.forEach { connection ->
            val characteristic = connection.inbox ?: return@forEach
            packetChunks(packetData, connection.mtuPayload).forEach { chunk ->
                enqueue(connection, Op.Write(characteristic, chunk))
            }
        }
    }

    private fun packetChunks(packet: ByteArray, maxPayload: Int): List<ByteArray> {
        return BleMeshPacketCodec.split(packet, maxPayload)
    }

    private fun isStarted(): Boolean = synchronized(lock) { started }

    private fun enqueueNotification(device: BluetoothDevice, chunk: ByteArray) {
        handler.post {
            if (!isStarted()) return@post
            val queue = notificationQueues.getOrPut(device.address) { ArrayDeque() }
            if (queue.size >= MAX_NOTIFICATION_QUEUE) return@post
            queue.addLast(chunk.copyOf())
            pumpNotification(device)
        }
    }

    private fun pumpNotification(device: BluetoothDevice) {
        if (!isStarted() || notificationBusy[device.address] == true) return
        val queue = notificationQueues[device.address] ?: return
        val chunk = queue.pollFirst() ?: return
        val characteristic = gattServer?.getService(CQ.SERVICE_UUID)?.getCharacteristic(CQ.INBOX_UUID)
        if (characteristic == null || gattServer?.connectedDevices?.none { it.address == device.address } == true) {
            notificationQueues.remove(device.address)
            notificationBusy.remove(device.address)
            return
        }
        characteristic.value = chunk
        notificationBusy[device.address] = true
        val accepted = gattServer?.notifyCharacteristicChanged(device, characteristic, false) == true
        if (!accepted) {
            notificationBusy[device.address] = false
            pumpNotification(device)
        }
    }

    private fun startAdvertising() {
        if (!isStarted()) return
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(CQ.SERVICE_UUID))
            .addServiceData(ParcelUuid(CQ.SERVICE_UUID), byteArrayOf(CQ.VERSION.toByte()) + tempId)
            .setIncludeDeviceName(false)
            .build()
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        advertiser?.stopAdvertising(advertiseCallback)
        advertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    private fun startScanning() {
        if (!isStarted()) return
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(CQ.SERVICE_UUID)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_BALANCED).build()
        scanner?.startScan(listOf(filter), settings, scanCallback)
    }

    private fun handleIncoming(data: ByteArray) {
        BleMiniFragmenter.decode(data)?.let { fragment ->
            miniReassembler.ingest(fragment)?.let { handleIncoming(it) }
            return
        }
        val pkt = CQPacket.decode(data) ?: return
        if (pkt.version != CQ.VERSION) return
        // A non-zero next_hop is a per-hop unicast constraint. Packets for a
        // different next hop must not be delivered or relayed by this node.
        if (!CQPacket.isBroadcastAddress(pkt.nextHop) && !pkt.nextHop.contentEquals(tempId)) return
        if (pkt.type == CQ.Type.FRAGMENT) {
            reassembler.ingest(pkt)?.let { handleIncoming(it) }
            return
        }
        if (pkt.type != CQ.Type.ACK && dedup.seen(pkt.msgId)) return
        listener.onPacket(data)
        // The local destination consumes the packet and does not relay it.
        // destination/next_hop are authenticated end-to-end and therefore
        // cannot be rewritten by a relay. TTL remains the only mutable hop
        // field in this envelope.
        val isLocalDestination =
            !CQPacket.isBroadcastAddress(pkt.destination) && pkt.destination.contentEquals(tempId)
        if (!isLocalDestination && pkt.ttl > 1) {
            send(pkt.copy(ttl = pkt.ttl - 1).encode())
        }
    }

    private fun connect(device: BluetoothDevice) {
        if (!isStarted() || connections.containsKey(device.address)) return
        // A placeholder prevents duplicate connectGatt calls while CONNECTING.
        val gatt = device.connectGatt(context, false, gattCallback)
        val connection = Connection(device.address, gatt, generation)
        connections.putIfAbsent(device.address, connection)?.let {
            gatt.close()
            return
        }
        knownDevices[device.address] = device
    }

    private fun enqueue(connection: Connection, op: Op) {
        handler.post {
            if (!isCurrent(connection)) return@post
            connection.queue.add(op)
            pump(connection)
        }
    }

    private fun pump(connection: Connection) {
        if (!isCurrent(connection) || connection.busy) return
        val op = connection.queue.poll() ?: return
        connection.busy = true
        val accepted = when (op) {
            is Op.Mtu -> connection.gatt.requestMtu(517)
            is Op.Discover -> connection.gatt.discoverServices()
            is Op.Cccd -> {
                op.descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                connection.gatt.setCharacteristicNotification(op.characteristic, true)
                connection.gatt.writeDescriptor(op.descriptor)
            }
            is Op.Write -> {
                op.characteristic.value = op.value
                connection.gatt.writeCharacteristic(op.characteristic)
            }
        }
        if (!accepted) finish(connection)
    }

    private fun finish(connection: Connection) {
        if (!isCurrent(connection)) return
        connection.busy = false
        pump(connection)
    }

    private fun isCurrent(connection: Connection): Boolean =
        isStarted() && connection.generation == generation && connections[connection.address] === connection

    private fun disconnect(connection: Connection, scheduleRetry: Boolean) {
        if (connections.remove(connection.address, connection)) {
            connection.queue.clear()
            connection.busy = false
            connection.gatt.close()
        }
        if (scheduleRetry && isStarted()) scheduleRetry(connection.address)
    }

    private fun scheduleRetry(address: String) {
        val attempt = (retryCounts[address] ?: 0) + 1
        if (attempt > MAX_RETRIES || retryRunnables.containsKey(address)) return
        retryCounts[address] = attempt
        val delay = RETRY_DELAYS_MS[attempt - 1]
        val targetGeneration = generation
        val runnable = Runnable {
            retryRunnables.remove(address)
            if (isStarted() && generation == targetGeneration && !connections.containsKey(address)) {
                knownDevices[address]?.let { connect(it) }
            }
        }
        retryRunnables[address] = runnable
        handler.postDelayed(runnable, delay)
    }

    private val advertiseCallback = object : AdvertiseCallback() {}

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            handler.post {
                if (!isStarted()) return@post
                result.scanRecord?.getServiceData(ParcelUuid(CQ.SERVICE_UUID))?.let { sd ->
                    if (sd.size >= 17) listener.onDiscover(sd.copyOfRange(1, 17))
                }
                val device = result.device ?: return@post
                knownDevices[device.address] = device
                retryRunnables.remove(device.address)?.let { handler.removeCallbacks(it) }
                retryCounts.remove(device.address)
                connect(device)
            }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            handler.post {
                val connection = connections[gatt.device.address] ?: return@post
                if (!isCurrent(connection) || connection.gatt !== gatt) {
                    gatt.close()
                    return@post
                }
                if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
                    retryCounts.remove(connection.address)
                    enqueue(connection, Op.Mtu())
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED || status != BluetoothGatt.GATT_SUCCESS) {
                    disconnect(connection, true)
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            handler.post {
                val connection = connections[gatt.device.address] ?: return@post
                if (!isCurrent(connection) || connection.gatt !== gatt) return@post
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    connection.mtuPayload = (mtu - ATT_OVERHEAD).coerceAtLeast(1)
                }
                finish(connection)
                enqueue(connection, Op.Discover())
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            handler.post {
                val connection = connections[gatt.device.address] ?: return@post
                if (!isCurrent(connection) || connection.gatt !== gatt) return@post
                val characteristic = gatt.getService(CQ.SERVICE_UUID)?.getCharacteristic(CQ.INBOX_UUID)
                val descriptor = characteristic?.getDescriptor(UUID_CCCD)
                if (status == BluetoothGatt.GATT_SUCCESS && characteristic != null && descriptor != null) {
                    connection.inbox = characteristic
                    finish(connection)
                    enqueue(connection, Op.Cccd(characteristic, descriptor))
                } else {
                    finish(connection)
                    disconnect(connection, true)
                }
            }
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            handler.post {
                connections[gatt.device.address]?.takeIf { isCurrent(it) }?.let {
                    if (status == BluetoothGatt.GATT_SUCCESS) finish(it) else disconnect(it, true)
                }
            }
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            handler.post {
                connections[gatt.device.address]?.takeIf { isCurrent(it) }?.let {
                    if (status == BluetoothGatt.GATT_SUCCESS) finish(it) else disconnect(it, true)
                }
            }
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            handler.post {
                connections[gatt.device.address]?.takeIf { isCurrent(it) }?.let {
                    characteristic.value?.let { value -> handleIncoming(value) }
                }
            }
        }
    }

    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                handler.post {
                    notificationQueues.remove(device.address)
                    notificationBusy.remove(device.address)
                    serverPayloadByAddress.remove(device.address)
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            if (isStarted()) serverPayloadByAddress[device.address] = (mtu - ATT_OVERHEAD).coerceAtLeast(1)
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            val valid = isStarted() &&
                characteristic.uuid == CQ.INBOX_UUID &&
                !preparedWrite && offset == 0 && value != null && value.isNotEmpty()
            if (valid) handleIncoming(value!!)
            if (responseNeeded) {
                gattServer?.sendResponse(
                    device,
                    requestId,
                    if (valid) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED,
                    0,
                    null,
                )
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            handler.post {
                notificationBusy[device.address] = false
                if (status == BluetoothGatt.GATT_SUCCESS) pumpNotification(device)
                else {
                    notificationQueues.remove(device.address)
                    notificationBusy.remove(device.address)
                }
            }
        }
    }

    companion object {
        private const val ATT_OVERHEAD = 3
        private const val DEFAULT_ATT_PAYLOAD = 20
        private const val FRAGMENT_HEADER_SIZE = 4
        private const val MAX_NOTIFICATION_QUEUE = 64
        private val RETRY_DELAYS_MS = longArrayOf(1_000L, 2_000L, 4_000L)
        private val UUID_CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
