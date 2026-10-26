import SwiftUI

/// v2 克制版：附近模式门闩 → 附近 / 公频 / 我。少装饰，状态可解释。
struct ContentView: View {
    @EnvironmentObject var engine: ChatEngine
    @State private var tab = 0

    var body: some View {
        Group {
            if !engine.nearbyMode {
                NearbyGateView()
            } else {
                TabView(selection: $tab) {
                    PeerListView()
                        .tabItem { Label("附近", systemImage: "dot.radiowaves.left.and.right") }
                        .tag(0)
                    PublicChannelView()
                        .tabItem { Label("公频", systemImage: "megaphone") }
                        .tag(1)
                    MeView()
                        .tabItem { Label("我", systemImage: "person.crop.circle") }
                        .tag(2)
                }
                .tint(CQTheme.navy)
            }
        }
    }
}

enum CQTheme {
    static let navy = Color(red: 0.08, green: 0.18, blue: 0.38)
    static let cyan = Color(red: 0.15, green: 0.65, blue: 0.85)
    static let mint = Color(red: 0.35, green: 0.85, blue: 0.65)
    static let bg = Color(red: 0.96, green: 0.97, blue: 0.99)
}

struct NearbyGateView: View {
    @EnvironmentObject var engine: ChatEngine

    var body: some View {
        ZStack {
            CQTheme.bg.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 24) {
                Spacer()
                Text("CQchat")
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .foregroundStyle(CQTheme.navy)
                Text("附近设备之间的加密消息。无账号，无服务器，数据不离开本机与附近链路。")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 10) {
                    Label("公开消息：附近所有人可见的公频广播", systemImage: "megaphone")
                    Label("私聊：端到端加密，仅双方可读", systemImage: "lock")
                    Label("身份密钥只存在本机，无数据收集", systemImage: "iphone")
                    Label("关闭附近模式后停止扫描与广播", systemImage: "antenna.radiowaves.left.and.right.slash")
                }
                .font(.subheadline)
                .foregroundStyle(CQTheme.navy.opacity(0.85))
                Spacer()
                Button {
                    engine.setNearbyMode(true)
                } label: {
                    Text("开启附近模式")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(CQTheme.navy)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
            }
            .padding(28)
        }
    }
}

struct PublicChannelView: View {
    @EnvironmentObject var engine: ChatEngine
    @State private var draft = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Text("公开消息 · \(engine.transportHint)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(CQTheme.bg)
                List(engine.publicMessages) { msg in
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(msg.fromNickname) · 公开消息")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        MentionText(text: msg.text ?? "", peers: engine.peers, selfNick: engine.nickname)
                    }
                    .listRowBackground(CQTheme.bg)
                }
                .listStyle(.plain)
                HStack {
                    TextField("公频文字，可用 @昵称", text: $draft)
                        .textFieldStyle(.roundedBorder)
                    Button("发送") {
                        let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !t.isEmpty else { return }
                        engine.sendPublic(t)
                        draft = ""
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(CQTheme.navy)
                }
                .padding()
            }
            .background(CQTheme.bg)
            .navigationTitle("公频")
        }
    }
}

/// Local-only @nickname highlight in public channel.
struct MentionText: View {
    let text: String
    let peers: [Peer]
    let selfNick: String

    var body: some View {
        Text(attributed)
    }

    private var attributed: AttributedString {
        var result = AttributedString(text)
        let names = Set(peers.map(\.nickname) + [selfNick]).filter { !$0.isEmpty }
            .sorted { $0.count > $1.count }
        for name in names {
            let needle = "@\(name)"
            var searchStart = text.startIndex
            while searchStart < text.endIndex,
                  let range = text.range(of: needle, range: searchStart..<text.endIndex) {
                if let lower = AttributedString.Index(range.lowerBound, within: result),
                   let upper = AttributedString.Index(range.upperBound, within: result) {
                    result[lower..<upper].foregroundColor = CQTheme.cyan
                    result[lower..<upper].font = .body.weight(.semibold)
                }
                searchStart = range.upperBound
            }
        }
        return result
    }
}

struct PeerStatusIcons: View {
    let peer: Peer

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: linkIcon)
                .foregroundStyle(linkColor)
                .accessibilityLabel(peer.linkPath.rawValue)
            if peer.verified {
                Image(systemName: "checkmark.seal.fill")
                    .foregroundStyle(CQTheme.mint)
                    .accessibilityLabel("身份已验证")
            }
            if peer.cryptoFailed {
                Image(systemName: "lock.slash.fill")
                    .foregroundStyle(.red)
                    .accessibilityLabel("加密失败")
            } else if peer.encrypted {
                Image(systemName: "lock.fill")
                    .foregroundStyle(CQTheme.navy)
                    .accessibilityLabel("端到端加密会话中")
            }
            if peer.favorite {
                Image(systemName: "star.fill")
                    .foregroundStyle(.orange)
                    .accessibilityLabel("已收藏")
            }
        }
        .font(.caption)
    }

    private var linkIcon: String {
        switch peer.linkPath {
        case .bleDirect: return "antenna.radiowaves.left.and.right"
        case .meshRelay: return "point.3.connected.trianglepath.dotted"
        case .unreachable: return "wifi.slash"
        }
    }

    private var linkColor: Color {
        switch peer.linkPath {
        case .bleDirect: return CQTheme.cyan
        case .meshRelay: return .orange
        case .unreachable: return .secondary
        }
    }
}

struct PeerListView: View {
    @EnvironmentObject var engine: ChatEngine

    var body: some View {
        NavigationStack {
            List(engine.peers) { peer in
                NavigationLink {
                    PrivateChatView(peer: peer)
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(peer.nickname)
                                .font(.headline)
                            Text(statusLine(peer))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        PeerStatusIcons(peer: peer)
                    }
                }
            }
            .listStyle(.plain)
            .background(CQTheme.bg)
            .navigationTitle("附近")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    NavigationLink {
                        MeshTopologyView()
                    } label: {
                        Image(systemName: "circle.grid.cross")
                    }
                    .accessibilityLabel("本地 Mesh 拓扑")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("关闭") { engine.setNearbyMode(false) }
                }
            }
            .overlay {
                if engine.peers.isEmpty {
                    Text("正在发现附近设备…")
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func statusLine(_ peer: Peer) -> String {
        let id = peer.fingerprint.map { String($0.hex.prefix(12)) } ?? String(peer.tempId.hex.prefix(8))
        return "\(id) · \(peer.linkPath.rawValue)"
    }
}

struct MeshTopologyView: View {
    @EnvironmentObject var engine: ChatEngine

    var body: some View {
        GeometryReader { geo in
            let center = CGPoint(x: geo.size.width / 2, y: geo.size.height / 2)
            let radius = min(geo.size.width, geo.size.height) * 0.32
            let nodes = engine.peers
            ZStack {
                CQTheme.bg.ignoresSafeArea()
                Canvas { ctx, size in
                    for (i, _) in nodes.enumerated() {
                        let angle = (Double(i) / Double(max(nodes.count, 1))) * 2 * .pi - .pi / 2
                        let p = CGPoint(
                            x: center.x + CGFloat(cos(angle)) * radius,
                            y: center.y + CGFloat(sin(angle)) * radius
                        )
                        var path = Path()
                        path.move(to: center)
                        path.addLine(to: p)
                        ctx.stroke(path, with: .color(CQTheme.cyan.opacity(0.45)), lineWidth: 1.5)
                    }
                }
                Circle()
                    .fill(CQTheme.navy)
                    .frame(width: 28, height: 28)
                    .overlay(Text("我").font(.caption2).foregroundStyle(.white))
                    .position(center)
                ForEach(Array(nodes.enumerated()), id: \.element.id) { i, peer in
                    let angle = (Double(i) / Double(max(nodes.count, 1))) * 2 * .pi - .pi / 2
                    let p = CGPoint(
                        x: center.x + CGFloat(cos(angle)) * radius,
                        y: center.y + CGFloat(sin(angle)) * radius
                    )
                    VStack(spacing: 2) {
                        Circle()
                            .fill(peer.bleDirect ? CQTheme.cyan : Color.orange.opacity(0.85))
                            .frame(width: 18, height: 18)
                        Text(peer.nickname)
                            .font(.caption2)
                            .lineLimit(1)
                    }
                    .position(p)
                }
            }
        }
        .navigationTitle("本地拓扑")
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) {
            Text("仅来自本机 BLE 发现，不上传")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding()
        }
    }
}

struct PrivateChatView: View {
    @EnvironmentObject var engine: ChatEngine
    let peer: Peer
    @State private var draft = ""
    @State private var showPicker = false

    var messages: [ChatMessage] {
        guard let fp = peer.fingerprint else { return [] }
        return engine.privateMessages[fp] ?? []
    }

    var livePeer: Peer {
        engine.peers.first(where: { $0.id == peer.id }) ?? peer
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                PeerStatusIcons(peer: livePeer)
                Text(livePeer.linkPath.rawValue)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if let fp = livePeer.fingerprint, livePeer.verified || livePeer.favorite {
                    Button {
                        engine.setFavorite(!livePeer.favorite, fingerprint: fp)
                    } label: {
                        Image(systemName: livePeer.favorite ? "star.fill" : "star")
                            .foregroundStyle(.orange)
                    }
                    .accessibilityLabel(livePeer.favorite ? "取消收藏" : "收藏已验证身份")
                }
            }
            .padding(.horizontal)
            .padding(.top, 4)
            Text("私聊 · 端到端加密")
                .font(.caption2)
                .foregroundStyle(.secondary)
            if peer.fingerprint == nil {
                Button("建立私聊") { engine.startPrivate(with: peer) }
                    .buttonStyle(.borderedProminent)
                    .tint(CQTheme.navy)
                    .padding()
            }
            List(messages) { msg in
                VStack(alignment: .leading, spacing: 4) {
                    statusLabel(msg)
                    if let t = msg.text { Text(t) }
                    if let thumb = msg.thumbJPEG, let ui = UIImage(data: thumb) {
                        Image(uiImage: ui).resizable().scaledToFit().frame(maxHeight: 120)
                    }
                    if msg.kind == .voice {
                        Text("语音 \(msg.voiceCQOP?.count ?? 0) B").font(.caption)
                    }
                }
            }
            .listStyle(.plain)
            HStack {
                TextField("私聊", text: $draft)
                    .textFieldStyle(.roundedBorder)
                Button("图") { showPicker = true }
                Button("发") {
                    guard let fp = peer.fingerprint else { return }
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !t.isEmpty else { return }
                    engine.sendPrivateText(t, toFingerprint: fp)
                    draft = ""
                }
                .buttonStyle(.borderedProminent)
                .tint(CQTheme.navy)
            }
            .padding()
        }
        .background(CQTheme.bg)
        .navigationTitle(peer.verified ? "\(peer.nickname)·已验证" : "\(peer.nickname)·未验证")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showPicker) {
            ImagePicker { img in
                if let fp = peer.fingerprint {
                    engine.sendPrivateImage(img, toFingerprint: fp)
                }
            }
        }
    }

    @ViewBuilder
    private func statusLabel(_ msg: ChatMessage) -> some View {
        switch msg.status {
        case .queued: Text("等待中…").font(.caption2).foregroundStyle(.orange)
        case .sent: Text("已交给附近 · \(msg.pathHint)").font(.caption2).foregroundStyle(.secondary)
        case .delivered: Text("已送达").font(.caption2).foregroundStyle(CQTheme.mint)
        case .failed: Text("失败").font(.caption2).foregroundStyle(.red)
        case .received: EmptyView()
        }
    }
}

struct MeView: View {
    @EnvironmentObject var engine: ChatEngine
    @State private var nick: String = ""
    @State private var scan = false
    @State private var wipeConfirm = false
    @State private var titleTaps = 0
    @State private var lastTap = Date.distantPast

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("昵称", text: $nick)
                        .onAppear { nick = engine.nickname }
                        .onChange(of: engine.identityEpoch) { _ in nick = engine.nickname }
                        .onSubmit { engine.setNickname(nick) }
                    Text("指纹（当面核对）")
                    Text(engine.myFingerprintHex)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .id(engine.identityEpoch)
                } header: {
                    Text("身份（仅本机）")
                } footer: {
                    Text("无账号、无数据收集。长期身份密钥只存在本机 Keychain。")
                }
                Section {
                    QRCodeView(payload: engine.qrPayload)
                        .frame(height: 200)
                        .id("qr-\(engine.identityEpoch)")
                    Text("扫码后将绑定为已验证身份")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("扫对方二维码") { scan = true }
                } header: {
                    Text("当面核对")
                }
                Section {
                    Text("公开消息：公频广播，附近可见。\n私聊：Noise 端到端加密会话。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("消息类型")
                }
                Section {
                    Button("紧急清除…", role: .destructive) {
                        wipeConfirm = true
                    }
                    Text("连点标题三次也可触发。确认后清除本机全部身份密钥、会话和消息并更换新密钥，不可恢复。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("紧急清除")
                }
                Section {
                    Button("关闭附近模式", role: .destructive) {
                        engine.setNearbyMode(false)
                    }
                }
            }
            .navigationTitle("我")
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Text("我")
                        .font(.headline)
                        .onTapGesture { registerTitleTap() }
                }
            }
            .confirmationDialog(
                "将清除本机全部身份密钥、会话和消息，不可恢复",
                isPresented: $wipeConfirm,
                titleVisibility: .visible
            ) {
                Button("确认清除并更换密钥", role: .destructive) {
                    engine.emergencyWipe()
                    nick = engine.nickname
                }
                Button("取消", role: .cancel) {}
            }
            .sheet(isPresented: $scan) {
                QRScannerView { code in
                    engine.markVerified(fromQR: code)
                    scan = false
                }
            }
        }
    }

    private func registerTitleTap() {
        let now = Date()
        if now.timeIntervalSince(lastTap) > 1.2 {
            titleTaps = 0
        }
        lastTap = now
        titleTaps += 1
        if titleTaps >= 3 {
            titleTaps = 0
            wipeConfirm = true
        }
    }
}
