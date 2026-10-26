package com.cqchat.app.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import android.graphics.Bitmap
import com.cqchat.app.chat.ChatEngine
import com.cqchat.app.chat.ChatMessage
import com.cqchat.app.chat.Peer
import com.cqchat.app.protocol.toHex
import com.cqchat.app.transport.MeshForegroundService
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : ComponentActivity() {
    private val engine: ChatEngine by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestPerms()
        startForegroundService(Intent(this, MeshForegroundService::class.java))
        engine.start()
        setContent {
            MaterialTheme {
                AppScaffold(engine)
            }
        }
    }

    private fun requestPerms() {
        val needed = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
        )
        if (Build.VERSION.SDK_INT >= 31) {
            needed += Manifest.permission.BLUETOOTH_SCAN
            needed += Manifest.permission.BLUETOOTH_CONNECT
            needed += Manifest.permission.BLUETOOTH_ADVERTISE
        }
        if (Build.VERSION.SDK_INT >= 33) {
            needed += Manifest.permission.POST_NOTIFICATIONS
        }
        val missing = needed.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            requestPermissions(missing.toTypedArray(), 1001)
        }
    }
}

@Composable
fun AppScaffold(engine: ChatEngine) {
    var tab by remember { mutableIntStateOf(0) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(selected = tab == 0, onClick = { tab = 0 }, label = { Text("公频") }, icon = { Text("📡") })
                NavigationBarItem(selected = tab == 1, onClick = { tab = 1 }, label = { Text("附近") }, icon = { Text("👥") })
                NavigationBarItem(selected = tab == 2, onClick = { tab = 2 }, label = { Text("我") }, icon = { Text("▣") })
            }
        }
    ) { pad ->
        Box(Modifier.padding(pad)) {
            when (tab) {
                0 -> PublicScreen(engine)
                1 -> PeersScreen(engine)
                2 -> MeScreen(engine)
            }
        }
    }
}

@Composable
fun PublicScreen(engine: ChatEngine) {
    var draft by remember { mutableStateOf("") }
    Column(Modifier.padding(12.dp)) {
        LazyColumn(Modifier.weight(1f)) {
            items(engine.publicMessages, key = { it.id.toHex() }) { msg ->
                Text("${msg.fromNickname}: ${msg.text ?: ""}", Modifier.padding(vertical = 4.dp))
            }
        }
        Row {
            OutlinedTextField(value = draft, onValueChange = { draft = it }, modifier = Modifier.weight(1f), label = { Text("公频") })
            Button(onClick = {
                val t = draft.trim()
                if (t.isNotEmpty()) {
                    engine.sendPublic(t)
                    draft = ""
                }
            }) { Text("发送") }
        }
    }
}

@Composable
fun PeersScreen(engine: ChatEngine) {
    var selected by remember { mutableStateOf<Peer?>(null) }
    if (selected != null) {
        PrivateScreen(engine, selected!!) { selected = null }
        return
    }
    LazyColumn(Modifier.padding(12.dp)) {
        items(engine.peers, key = { it.tempId.toHex() }) { peer ->
            ListItem(
                headlineContent = { Text(peer.nickname) },
                supportingContent = {
                    Text(
                        (peer.fingerprint?.toHex()?.take(16) ?: peer.tempId.toHex().take(8)) +
                            " · " + if (peer.verified) "已验证" else "未验证"
                    )
                },
                trailingContent = {
                    TextButton(onClick = { selected = peer }) { Text("打开") }
                }
            )
            HorizontalDivider()
        }
    }
}

@Composable
fun PrivateScreen(engine: ChatEngine, peer: Peer, onBack: () -> Unit) {
    var draft by remember { mutableStateOf("") }
    val fp = peer.fingerprint
    val msgs = fp?.let { engine.privateMessages[it.toHex()] } ?: emptyList()
    val context = LocalContext.current
    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null && fp != null) {
            val bytes = context.contentResolver.openInputStream(uri)?.readBytes()
            if (bytes != null) engine.sendPrivateImage(bytes, fp)
        }
    }
    Column(Modifier.padding(12.dp)) {
        TextButton(onClick = onBack) { Text("返回") }
        Text("${peer.nickname} · ${if (peer.verified) "已验证" else "未验证"}")
        if (fp == null) {
            Button(onClick = { engine.startPrivate(peer) }) { Text("建立私聊（Noise XX）") }
        }
        LazyColumn(Modifier.weight(1f)) {
            items(msgs, key = { it.id.toHex() }) { msg ->
                when (msg.status) {
                    ChatMessage.Status.QUEUED ->
                        Text("等待中…", color = MaterialTheme.colorScheme.tertiary)
                    ChatMessage.Status.SENT ->
                        Text("已交给附近", style = MaterialTheme.typography.labelSmall)
                    ChatMessage.Status.DELIVERED ->
                        Text("已送达", style = MaterialTheme.typography.labelSmall)
                    else -> {}
                }
                msg.text?.let { Text(it) }
                msg.thumbJpeg?.let { bytes ->
                    val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    if (bmp != null) {
                        Image(bmp.asImageBitmap(), contentDescription = null, modifier = Modifier.height(120.dp))
                    }
                }
                if (msg.kind == ChatMessage.Kind.VOICE) {
                    Text("语音 ${msg.voiceCqop?.size ?: 0} B")
                }
            }
        }
        Row {
            OutlinedTextField(value = draft, onValueChange = { draft = it }, modifier = Modifier.weight(1f))
            TextButton(onClick = { pickImage.launch("image/*") }) { Text("图") }
            Button(onClick = {
                if (fp != null) {
                    val t = draft.trim()
                    if (t.isNotEmpty()) {
                        engine.sendPrivateText(t, fp)
                        draft = ""
                    }
                }
            }) { Text("发") }
        }
    }
}

@Composable
fun MeScreen(engine: ChatEngine) {
    var nick by remember { mutableStateOf(engine.identity.nickname) }
    var scanResult by remember { mutableStateOf<String?>(null) }
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let {
            engine.markVerified(it)
            scanResult = it
        }
    }
    Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        OutlinedTextField(value = nick, onValueChange = {
            nick = it
            engine.identity.nickname = it
        }, label = { Text("昵称") })
        Spacer(Modifier.height(8.dp))
        Text("指纹", style = MaterialTheme.typography.labelMedium)
        Text(engine.identity.fingerprintHex, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(12.dp))
        QrImage(engine.identity.qrPayload())
        Spacer(Modifier.height(12.dp))
        Button(onClick = {
            val opts = ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            scanLauncher.launch(opts)
        }) { Text("扫对方二维码") }
        scanResult?.let { Text("已标记验证") }
    }
}

@Composable
fun QrImage(payload: String) {
    val bmp = remember(payload) {
        val bits = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 512, 512)
        val w = bits.width
        val h = bits.height
        val image = Bitmap.createBitmap(w, h, Bitmap.Config.RGB_565)
        for (x in 0 until w) for (y in 0 until h) {
            image.setPixel(x, y, if (bits[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
        }
        image
    }
    Image(bmp.asImageBitmap(), contentDescription = "QR", modifier = Modifier.size(200.dp))
}
