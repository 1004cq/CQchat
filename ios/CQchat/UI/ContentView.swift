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
                Text("附近设备之间的加密消息。无账号，无服务器。")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 10) {
                    Label("附近的人能看到临时标识，看不到你的长期公钥", systemImage: "eye.slash")
                    Label("关闭附近模式后停止扫描与广播", systemImage: "antenna.radiowaves.left.and.right.slash")
                    Label("系统可能在后台暂停蓝牙，不保证杀进程后在线", systemImage: "exclamationmark.triangle")
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
                Text(engine.transportHint)
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
                        Text(msg.text ?? "")
                    }
                    .listRowBackground(CQTheme.bg)
                }
                .listStyle(.plain)
                HStack {
                    TextField("公频文字", text: $draft)
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
                        Text(peer.verified ? "已验证" : "未验证")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(peer.verified ? CQTheme.mint : .orange)
                    }
                }
            }
            .listStyle(.plain)
            .background(CQTheme.bg)
            .navigationTitle("附近")
            .toolbar {
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
        return "\(id) · \(peer.pathHint)"
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

    var body: some View {
        VStack(spacing: 0) {
            Text(peer.pathHint)
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.top, 4)
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

    var body: some View {
        NavigationStack {
            Form {
                Section("身份") {
                    TextField("昵称", text: $nick)
                        .onAppear { nick = engine.nickname }
                        .onSubmit { engine.setNickname(nick) }
                    Text("指纹（当面核对）")
                    Text(engine.myFingerprintHex)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                }
                Section {
                    QRCodeView(payload: engine.qrPayload)
                        .frame(height: 200)
                    Text("扫码后将绑定为已验证身份")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("扫对方二维码") { scan = true }
                } header: {
                    Text("当面核对")
                }
                Section {
                    Button("关闭附近模式", role: .destructive) {
                        engine.setNearbyMode(false)
                    }
                }
            }
            .navigationTitle("我")
            .sheet(isPresented: $scan) {
                QRScannerView { code in
                    engine.markVerified(fromQR: code)
                    scan = false
                }
            }
        }
    }
}
