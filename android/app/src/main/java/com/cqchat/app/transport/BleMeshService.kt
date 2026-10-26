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
import com.cqchat.app.protocol.FragmentReassembler
import com.cqchat.app.protocol.Fragmenter
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

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

    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var scanner: BluetoothLeScanner? = null
    private val centrals = ConcurrentHashMap<String, BluetoothGatt>()
    private val inboxChars = ConcurrentHashMap<String, BluetoothGattCharacteristic>()
    private val writeQueues = ConcurrentHashMap<String, ConcurrentLinkedQueue<ByteArray>>()
    private val writeBusy = ConcurrentHashMap<String, Boolean>()
    private val mtuPayload = ConcurrentHashMap<String, Int>()
    private val dedup = DedupCache()
    private val reassembler = FragmentReassembler()
    private val handler = Handler(Looper.getMainLooper())

    @Volatile
    var tempId: ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }
        private set

    val effectivePayloadMtu: Int
        get() {
            val vals = mtuPayload.values
            val link = if (vals.isEmpty()) CQ.BLE_MTU_PAYLOAD else vals.minOrNull() ?: CQ.BLE_MTU_PAYLOAD
            return maxOf(20, minOf(CQ.BLE_MTU_PAYLOAD, link))
        }

    private val rotate = object : Runnable {
        override fun run() {
            SecureRandom().nextBytes(tempId)
            startAdvertising()
            handler.postDelayed(this, CQ.TEMP_ID_ROTATE_SECS * 1000)
        }
    }

    fun start() {
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
        inbox.addDescriptor(
            BluetoothGattDescriptor(
                UUID_CCCD,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
            )
        )
        service.addCharacteristic(inbox)
        gattServer?.addService(service)
        advertiser = adapter?.bluetoothLeAdvertiser
        scanner = adapter?.bluetoothLeScanner
        startAdvertising()
        startScanning()
        handler.postDelayed(rotate, CQ.TEMP_ID_ROTATE_SECS * 1000)
    }

    fun stop() {
        handler.removeCallbacks(rotate)
        try { advertiser?.stopAdvertising(advertiseCallback) } catch (_: Exception) {}
        try { scanner?.stopScan(scanCallback) } catch (_: Exception) {}
        centrals.values.forEach { try { it.close() } catch (_: Exception) {} }
        centrals.clear()
        try { gattServer?.close() } catch (_: Exception) {}
    }

    fun send(packetData: ByteArray) {
        val chunk = maxOf(64, effectivePayloadMtu - CQ.HEADER_SIZE - 4)
        val wire = if (packetData.size > effectivePayloadMtu) {
            val pkt = CQPacket.decode(packetData) ?: return
            Fragmenter.split(packetData, pkt.sender, pkt.msgId, pkt.ttl, chunk)
        } else listOf(packetData)

        for (piece in wire) {
            gattServer?.getService(CQ.SERVICE_UUID)?.getCharacteristic(CQ.INBOX_UUID)?.let { ch ->
                ch.value = piece
                gattServer?.connectedDevices?.forEach { device ->
                    gattServer?.notifyCharacteristicChanged(device, ch, false)
                }
            }
            for (addr in centrals.keys) {
                enqueue(addr, piece)
            }
        }
    }

    private fun enqueue(addr: String, data: ByteArray) {
        writeQueues.getOrPut(addr) { ConcurrentLinkedQueue() }.add(data)
        pump(addr)
    }

    private fun pump(addr: String) {
        if (writeBusy[addr] == true) return
        val q = writeQueues[addr] ?: return
        val data = q.poll() ?: return
        val gatt = centrals[addr] ?: return
        val ch = inboxChars[addr] ?: return
        writeBusy[addr] = true
        ch.value = data
        ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        if (!gatt.writeCharacteristic(ch)) {
            writeBusy[addr] = false
            q.add(data) // requeue
            handler.postDelayed({ pump(addr) }, 30)
        } else {
            handler.postDelayed({
                writeBusy[addr] = false
                pump(addr)
            }, 15)
        }
    }

    private fun startAdvertising() {
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
        try {
            advertiser?.stopAdvertising(advertiseCallback)
            advertiser?.startAdvertising(settings, data, advertiseCallback)
        } catch (_: Exception) {
        }
    }

    private fun startScanning() {
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(CQ.SERVICE_UUID)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_BALANCED).build()
        try {
            scanner?.startScan(listOf(filter), settings, scanCallback)
        } catch (_: Exception) {
        }
    }

    private fun handleIncoming(data: ByteArray) {
        val pkt = CQPacket.decode(data) ?: return
        if (pkt.version != CQ.VERSION) return
        if (pkt.type == CQ.Type.FRAGMENT) {
            reassembler.ingest(pkt)?.let { handleIncoming(it) }
            return
        }
        if (pkt.type != CQ.Type.ACK && dedup.seen(pkt.msgId)) return
        listener.onPacket(data)
        if (pkt.ttl > 1) {
            send(pkt.copy(ttl = pkt.ttl - 1).encode())
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {}

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val sd = result.scanRecord?.getServiceData(ParcelUuid(CQ.SERVICE_UUID))
            if (sd != null && sd.size >= 17) {
                listener.onDiscover(sd.copyOfRange(1, 17))
            }
            val device = result.device ?: return
            if (centrals.containsKey(device.address)) return
            device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val addr = gatt.device.address
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                centrals[addr] = gatt
                gatt.requestMtu(517)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                centrals.remove(addr)
                inboxChars.remove(addr)
                writeQueues.remove(addr)
                writeBusy.remove(addr)
                mtuPayload.remove(addr)
                try { gatt.close() } catch (_: Exception) {}
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                mtuPayload[gatt.device.address] = maxOf(20, mtu - 3)
            }
            gatt.discoverServices()
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val ch = gatt.getService(CQ.SERVICE_UUID)?.getCharacteristic(CQ.INBOX_UUID) ?: return
            inboxChars[gatt.device.address] = ch
            gatt.setCharacteristicNotification(ch, true)
            ch.getDescriptor(UUID_CCCD)?.let { cccd ->
                cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(cccd)
            }
            pump(gatt.device.address)
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            writeBusy[gatt.device.address] = false
            pump(gatt.device.address)
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            characteristic.value?.let { handleIncoming(it) }
        }
    }

    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            value?.let { handleIncoming(it) }
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }
        }
    }

    companion object {
        private val UUID_CCCD = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
