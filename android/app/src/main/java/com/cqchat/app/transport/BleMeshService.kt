package com.cqchat.app.transport

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import com.cqchat.app.chat.DedupCache
import com.cqchat.app.protocol.CQ
import com.cqchat.app.protocol.CQPacket
import com.cqchat.app.protocol.FragmentReassembler
import com.cqchat.app.protocol.Fragmenter
import java.security.SecureRandom
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

    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var scanner: BluetoothLeScanner? = null
    private val centrals = ConcurrentHashMap<String, BluetoothGatt>()
    private val inboxChars = ConcurrentHashMap<String, BluetoothGattCharacteristic>()
    private val dedup = DedupCache()
    private val reassembler = FragmentReassembler()

    @Volatile
    var tempId: ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }
        private set

    private val rotate = object : Runnable {
        override fun run() {
            SecureRandom().nextBytes(tempId)
            startAdvertising()
            handler.postDelayed(this, CQ.TEMP_ID_ROTATE_SECS * 1000)
        }
    }
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())

    fun start() {
        val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        gattServer = mgr.openGattServer(context, serverCallback)
        val service = BluetoothGattService(CQ.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val inbox = BluetoothGattCharacteristic(
            CQ.INBOX_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE or
                BluetoothGattCharacteristic.PERMISSION_READ,
        )
        val cccd = BluetoothGattDescriptor(
            UUID_CCCD,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
        )
        inbox.addDescriptor(cccd)
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
        advertiser?.stopAdvertising(advertiseCallback)
        scanner?.stopScan(scanCallback)
        centrals.values.forEach { it.close() }
        gattServer?.close()
    }

    fun send(packetData: ByteArray) {
        val wire = if (packetData.size > CQ.BLE_MTU_PAYLOAD) {
            val pkt = CQPacket.decode(packetData) ?: return
            Fragmenter.split(
                packetData, pkt.sender, pkt.msgId, pkt.ttl,
                chunkSize = maxOf(64, CQ.BLE_MTU_PAYLOAD - CQ.HEADER_SIZE - 4),
            )
        } else listOf(packetData)

        for (chunk in wire) {
            // Notify subscribed centrals via GATT server
            gattServer?.getService(CQ.SERVICE_UUID)?.getCharacteristic(CQ.INBOX_UUID)?.let { ch ->
                ch.value = chunk
                gattServer?.connectedDevices?.forEach { device ->
                    gattServer?.notifyCharacteristicChanged(device, ch, false)
                }
            }
            // Write to peripherals we connected as central
            for ((addr, gatt) in centrals) {
                val ch = inboxChars[addr] ?: continue
                ch.value = chunk
                gatt.writeCharacteristic(ch)
            }
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
        advertiser?.stopAdvertising(advertiseCallback)
        advertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    private fun startScanning() {
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(CQ.SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .build()
        scanner?.startScan(listOf(filter), settings, scanCallback)
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
            val relay = pkt.copy(ttl = pkt.ttl - 1)
            send(relay.encode())
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
            device.connectGatt(context, false, gattCallback)
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                centrals[gatt.device.address] = gatt
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                centrals.remove(gatt.device.address)
                inboxChars.remove(gatt.device.address)
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val ch = gatt.getService(CQ.SERVICE_UUID)?.getCharacteristic(CQ.INBOX_UUID) ?: return
            inboxChars[gatt.device.address] = ch
            gatt.setCharacteristicNotification(ch, true)
            val cccd = ch.getDescriptor(UUID_CCCD)
            cccd?.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            if (cccd != null) gatt.writeDescriptor(cccd)
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
        private val UUID_CCCD = java.util.UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
