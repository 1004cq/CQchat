package com.cqchat.app.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.cqchat.app.chat.ChatEngine
import com.cqchat.app.chat.ChatMessage
import com.cqchat.app.chat.Peer
import com.cqchat.app.chat.PeerLinkPath
import com.cqchat.app.protocol.toHex
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

private val Navy = Color(0xFF152E61)
private val Cyan = Color(0xFF26A6D9)
private val Mint = Color(0xFF59D9A5)
private val Bg = Color(0xFFF5F7FA)

class MainActivity : ComponentActivity() {
    private val engine: ChatEngine by viewModels()

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
            if (result.values.all { it }) {
                engine.setNearbyEnabled(true)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = lightColorScheme(
                    primary = Navy,
                    secondary = Cyan,
                    tertiary = Mint,
                    background = Bg,
                    surface = Color.White,
                )
            ) {
                Surface(color = Bg, modifier = Modifier.fillMaxSize()) {
                    AppRoot(engine) { enableNearby() }
                }
            }
        }
    }

    private fun enableNearby() {
        val needed = buildList {
            if (Build.VERSION.SDK_INT >= 31) {
                add(Manifest.permission.BLUETOOTH_SCAN)
                add(Manifest.permission.BLUETOOTH_CONNECT)
                add(Manifest.permission.BLUETOOTH_ADVERTISE)
            } else {
                add(Manifest.permission.ACCESS_COARSE_LOCATION)
            }
            if (Build.VERSION.SDK_INT >= 33) {
                add(Manifest.permission.POST_NOTIFICATIONS)
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
        }.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (needed.isEmpty()) {
            engine.setNearbyEnabled(true)
        } else {
            permissionLauncher.launch(needed.toTypedArray())
        }
    }
}

@Composable
fun AppRoot(engine: ChatEngine, onEnableNearby: () -> Unit) {
    if (!engine.nearbyMode) {
        NearbyGate(onEnableNearby)
        return
    }
    var tab by remember { mutableIntStateOf(0) }
    Scaffold(
        containerColor = Bg,
        bottomBar = {
            NavigationBar(containerColor = Color.White) {
                NavigationBarItem(
                    selected = tab == 0, onClick = { tab = 0 },
                    label = { Text("附近") }, icon = { Text("◈") },
                )
                NavigationBarItem(
                    selected = tab == 1, onClick = { tab = 1 },
                    label = { Text("公频") }, icon = { Text("◎") },
                )
                NavigationBarItem(
                    selected = tab == 2, onClick = { tab = 2 },
                    label = { Text("我") }, icon = { Text("○") },
                )
            }
        }
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (tab) {
                0 -> PeersScreen(engine)
                1 -> PublicScreen(engine)
                2 -> MeScreen(engine)
            }
        }
    }
}

@Composable
fun NearbyGate(onEnable: () -> Unit) {
    Column(
        Modifier.fillMaxSize().background(Bg).padding(28.dp),
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        Spacer(Modifier.height(48.dp))
        Column {
            Text("CQchat", fontSize = 40.sp, fontWeight = FontWeight.Bold, color = Navy)
            Spacer(Modifier.height(12.dp))
            Text(
                "附近设备之间的加密消息。无账号，无服务器，数据不离开本机与附近链路。",
                fontSize = 18.sp, color = Color.Gray,
            )
            Spacer(Modifier.height(24.dp))
            Text("· 公开消息：附近所有人可见的公频广播")
            Text("· 私聊：端到端加密，仅双方可读")
            Text("· 身份密钥只存在本机，无数据收集")
            Text("· 关闭附近模式后停止扫描与广播")
        }
        Button(
            onClick = onEnable,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Navy),
        ) {
            Text("开启附近模式")
        }
    }
}

@Composable
fun MentionText(text: String, peers: List<Peer>, selfNick: String) {
    val names = remember(peers, selfNick) {
        (peers.map { it.nickname } + selfNick).filter { it.isNotEmpty() }.toSet()
    }
    val annotated = buildAnnotatedString {
        var i = 0
        while (i < text.length) {
            if (text[i] == '@') {
                val match = names.firstOrNull { name ->
                    text.startsWith("@$name", i) &&
                        (i + 1 + name.length >= text.length ||
                            !text[i + 1 + name.length].isLetterOrDigit())
                }
                if (match != null) {
                    withStyle(SpanStyle(color = Cyan, fontWeight = FontWeight.SemiBold)) {
                        append("@$match")
                    }
                    i += 1 + match.length
                    continue
                }
            }
            append(text[i])
            i++
        }
    }
    Text(annotated)
}

@Composable
fun PeerStatusRow(peer: Peer) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            when (peer.linkPath) {
                PeerLinkPath.BLE_DIRECT -> "⌁"
                PeerLinkPath.MESH_RELAY -> "⇄"
                PeerLinkPath.UNREACHABLE -> "×"
            },
            color = when (peer.linkPath) {
                PeerLinkPath.BLE_DIRECT -> Cyan
                PeerLinkPath.MESH_RELAY -> Color(0xFFE67E22)
                PeerLinkPath.UNREACHABLE -> Color.Gray
            },
            fontWeight = FontWeight.Bold,
        )
        if (peer.verified) Text("✓", color = Mint, fontWeight = FontWeight.Bold)
        when {
            peer.cryptoFailed -> Text("🔒!", color = Color.Red)
            peer.encrypted -> Text("🔒", color = Navy)
        }
        if (peer.favorite) Text("★", color = Color(0xFFE67E22))
    }
}

@Composable
fun PublicScreen(engine: ChatEngine) {
    var draft by remember { mutableStateOf("") }
    Column(Modifier.padding(12.dp)) {
        Text(
            "公开消息 · ${engine.transportHint}",
            color = Color.Gray, fontSize = 12.sp, modifier = Modifier.padding(bottom = 8.dp),
        )
        LazyColumn(Modifier.weight(1f)) {
            items(engine.publicMessages, key = { it.id.toHex() }) { msg ->
                Text("${msg.fromNickname} · 公开消息", color = Color.Gray, fontSize = 12.sp)
                MentionText(msg.text ?: "", engine.peers, engine.identity.nickname)
                Spacer(Modifier.height(8.dp))
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = draft, onValueChange = { draft = it },
                modifier = Modifier.weight(1f), label = { Text("公频文字，可用 @昵称") },
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                val t = draft.trim()
                if (t.isNotEmpty()) {
                    engine.sendPublic(t); draft = ""
                }
            }, colors = ButtonDefaults.buttonColors(containerColor = Navy)) { Text("发送") }
        }
    }
}

@Composable
fun PeersScreen(engine: ChatEngine) {
    var selected by remember { mutableStateOf<Peer?>(null) }
    var showTopology by remember { mutableStateOf(false) }
    if (showTopology) {
        TopologyScreen(engine) { showTopology = false }
        return
    }
    if (selected != null) {
        PrivateScreen(engine, selected!!) { selected = null }
        return
    }
    Column {
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("附近", fontWeight = FontWeight.Bold, fontSize = 22.sp, color = Navy)
            Row {
                TextButton(onClick = { showTopology = true }) { Text("拓扑") }
                TextButton(onClick = { engine.setNearbyEnabled(false) }) { Text("关闭") }
            }
        }
        if (engine.peers.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("正在发现附近设备…", color = Color.Gray)
            }
        } else {
            LazyColumn {
                items(engine.peers, key = { it.tempId.toHex() }) { peer ->
                    ListItem(
                        headlineContent = { Text(peer.nickname) },
                        supportingContent = {
                            val id = peer.fingerprint?.toHex()?.take(12) ?: peer.tempId.toHex().take(8)
                            Text("$id · ${peer.linkPath.label}")
                        },
                        trailingContent = { PeerStatusRow(peer) },
                        modifier = Modifier.fillMaxWidth().clickable { selected = peer },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
fun TopologyScreen(engine: ChatEngine, onBack: () -> Unit) {
    val peers = engine.peers
    Column(Modifier.fillMaxSize().background(Bg)) {
        TextButton(onClick = onBack, modifier = Modifier.padding(8.dp)) { Text("返回") }
        Text(
            "本地拓扑",
            fontWeight = FontWeight.Bold, fontSize = 20.sp, color = Navy,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        Text(
            "仅来自本机 BLE 发现，不上传",
            fontSize = 12.sp, color = Color.Gray,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
        Box(Modifier.fillMaxSize().padding(16.dp), contentAlignment = Alignment.Center) {
            Canvas(Modifier.fillMaxSize()) {
                val c = Offset(size.width / 2f, size.height / 2f)
                val r = min(size.width, size.height) * 0.32f
                peers.forEachIndexed { i, _ ->
                    val angle = (i.toDouble() / maxOf(peers.size, 1)) * 2 * Math.PI - Math.PI / 2
                    val p = Offset(
                        c.x + (cos(angle) * r).toFloat(),
                        c.y + (sin(angle) * r).toFloat(),
                    )
                    drawLine(Cyan.copy(alpha = 0.45f), c, p, strokeWidth = 3f)
                    drawCircle(if (peers[i].bleDirect) Cyan else Color(0xFFE67E22), 14f, p)
                }
                drawCircle(Navy, 22f, c)
            }
            Text("我", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
        LazyColumn(Modifier.padding(16.dp)) {
            items(peers, key = { it.tempId.toHex() }) { peer ->
                Text("· ${peer.nickname} · ${peer.linkPath.label}", fontSize = 13.sp)
            }
        }
    }
}

@Composable
fun PrivateScreen(engine: ChatEngine, peer: Peer, onBack: () -> Unit) {
    var draft by remember { mutableStateOf("") }
    val live = engine.peers.firstOrNull { it.tempId.contentEquals(peer.tempId) } ?: peer
    val fp = live.fingerprint
    val msgs = fp?.let { engine.privateMessages[it.toHex()] } ?: emptyList()
    val context = LocalContext.current
    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null && fp != null) {
            context.contentResolver.openInputStream(uri)?.readBytes()?.let {
                engine.sendPrivateImage(it, fp)
            }
        }
    }
    Column(Modifier.padding(12.dp)) {
        TextButton(onClick = onBack) { Text("返回") }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "${live.nickname} · ${if (live.verified) "已验证" else "未验证"}",
                fontWeight = FontWeight.SemiBold, color = Navy, modifier = Modifier.weight(1f),
            )
            if (fp != null && (live.verified || live.favorite)) {
                TextButton(onClick = { engine.setFavorite(!live.favorite, fp) }) {
                    Text(if (live.favorite) "★ 已收藏" else "☆ 收藏")
                }
            }
        }
        PeerStatusRow(live)
        Text("私聊 · 端到端加密 · ${live.linkPath.label}", fontSize = 12.sp, color = Color.Gray)
        if (fp == null) {
            Button(onClick = { engine.startPrivate(peer) }, colors = ButtonDefaults.buttonColors(containerColor = Navy)) {
                Text("建立私聊")
            }
        }
        LazyColumn(Modifier.weight(1f).padding(vertical = 8.dp)) {
            items(msgs, key = { it.id.toHex() }) { msg ->
                when (msg.status) {
                    ChatMessage.Status.QUEUED -> Text("等待中…", color = Color(0xFFE67E22), fontSize = 11.sp)
                    ChatMessage.Status.SENT -> Text("已交给附近 · ${msg.pathHint}", color = Color.Gray, fontSize = 11.sp)
                    ChatMessage.Status.DELIVERED -> Text("已送达", color = Mint, fontSize = 11.sp)
                    ChatMessage.Status.FAILED -> Text("失败", color = Color.Red, fontSize = 11.sp)
                    else -> {}
                }
                msg.text?.let { Text(it) }
                msg.thumbJpeg?.let { bytes ->
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.let {
                        Image(it.asImageBitmap(), null, Modifier.height(120.dp))
                    }
                }
                if (msg.kind == ChatMessage.Kind.VOICE) {
                    Text("语音 ${msg.voiceCqop?.size ?: 0} B", fontSize = 12.sp)
                }
                Spacer(Modifier.height(6.dp))
            }
        }
        Row {
            OutlinedTextField(value = draft, onValueChange = { draft = it }, modifier = Modifier.weight(1f))
            TextButton(onClick = { pickImage.launch("image/*") }) { Text("图") }
            Button(onClick = {
                if (fp != null) {
                    val t = draft.trim()
                    if (t.isNotEmpty()) {
                        engine.sendPrivateText(t, fp); draft = ""
                    }
                }
            }, colors = ButtonDefaults.buttonColors(containerColor = Navy)) { Text("发") }
        }
    }
}

@Composable
fun MeScreen(engine: ChatEngine) {
    var nick by remember(engine.identityRevision) { mutableStateOf(engine.identity.nickname) }
    var scanResult by remember { mutableStateOf<String?>(null) }
    var wipeConfirm by remember { mutableStateOf(false) }
    var titleTaps by remember { mutableIntStateOf(0) }
    var lastTap by remember { mutableLongStateOf(0L) }
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let {
            engine.markVerified(it)
            scanResult = it
        }
    }
    Column(
        Modifier
            .padding(16.dp)
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "我",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = Navy,
            modifier = Modifier.pointerInput(Unit) {
                detectTapGestures {
                    val now = System.currentTimeMillis()
                    titleTaps = if (now - lastTap > 1200) 1 else titleTaps + 1
                    lastTap = now
                    if (titleTaps >= 3) {
                        titleTaps = 0
                        wipeConfirm = true
                    }
                }
            },
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = nick,
            onValueChange = { nick = it; engine.identity.nickname = it },
            label = { Text("昵称") },
        )
        Spacer(Modifier.height(8.dp))
        Text("指纹（当面核对 · 仅本机）", color = Color.Gray)
        Text(
            engine.identity.fingerprintHex,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
        )
        Text(
            "无账号、无数据收集。身份密钥只存在本机 Keystore。",
            fontSize = 12.sp, color = Color.Gray,
            modifier = Modifier.padding(vertical = 8.dp),
        )
        Text(
            "公开消息：公频广播，附近可见。\n私聊：Noise 端到端加密会话。",
            fontSize = 12.sp, color = Color.Gray,
        )
        Spacer(Modifier.height(12.dp))
        key(engine.identityRevision) {
            QrImage(engine.identity.qrPayload())
        }
        Text("扫码后将绑定为已验证身份", fontSize = 12.sp, color = Color.Gray)
        Spacer(Modifier.height(12.dp))
        Button(onClick = {
            scanLauncher.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE))
        }, colors = ButtonDefaults.buttonColors(containerColor = Navy)) {
            Text("扫对方二维码")
        }
        scanResult?.let { Text("已标记验证", color = Mint) }
        Spacer(Modifier.height(24.dp))
        OutlinedButton(
            onClick = { wipeConfirm = true },
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.Red),
        ) {
            Text("紧急清除…")
        }
        Text(
            "连点标题三次也可触发。确认后清除本机全部身份密钥、会话和消息并更换新密钥，不可恢复。",
            fontSize = 12.sp, color = Color.Gray,
            modifier = Modifier.padding(8.dp),
        )
        Spacer(Modifier.height(16.dp))
        TextButton(onClick = { engine.setNearbyEnabled(false) }) { Text("关闭附近模式") }
    }
    if (wipeConfirm) {
        AlertDialog(
            onDismissRequest = { wipeConfirm = false },
            title = { Text("紧急清除") },
            text = { Text("将清除本机全部身份密钥、会话和消息，不可恢复") },
            confirmButton = {
                TextButton(onClick = {
                    wipeConfirm = false
                    engine.emergencyWipe()
                    nick = engine.identity.nickname
                    scanResult = null
                }) { Text("确认清除并更换密钥") }
            },
            dismissButton = {
                TextButton(onClick = { wipeConfirm = false }) { Text("取消") }
            },
        )
    }
}

@Composable
fun QrImage(payload: String) {
    val bmp = remember(payload) {
        val bits = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 512, 512)
        Bitmap.createBitmap(bits.width, bits.height, Bitmap.Config.RGB_565).also { image ->
            for (x in 0 until bits.width) for (y in 0 until bits.height) {
                image.setPixel(x, y, if (bits[x, y]) 0xFF152E61.toInt() else 0xFFFFFFFF.toInt())
            }
        }
    }
    Image(bmp.asImageBitmap(), "QR", Modifier.size(200.dp))
}
