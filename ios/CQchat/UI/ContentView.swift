import SwiftUI

struct ContentView: View {
    @EnvironmentObject var engine: ChatEngine
    @State private var tab = 0

    var body: some View {
        TabView(selection: $tab) {
            PublicChannelView()
                .tabItem { Label("公频", systemImage: "antenna.radiowaves.left.and.right") }
                .tag(0)
            PeerListView()
                .tabItem { Label("附近", systemImage: "person.2") }
                .tag(1)
            MeView()
                .tabItem { Label("我", systemImage: "qrcode") }
                .tag(2)
        }
    }
}

struct PublicChannelView: View {
    @EnvironmentObject var engine: ChatEngine
    @State private var draft = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                List(engine.publicMessages) { msg in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(msg.fromNickname)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(msg.text ?? "")
                    }
                }
                HStack {
                    TextField("公频消息", text: $draft)
                        .textFieldStyle(.roundedBorder)
                    Button("发送") {
                        let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !t.isEmpty else { return }
                        engine.sendPublic(t)
                        draft = ""
                    }
                }
                .padding()
            }
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
                        VStack(alignment: .leading) {
                            Text(peer.nickname)
                            Text(peer.fingerprint?.hex.prefix(12).description ?? peer.tempId.hex.prefix(8).description)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(peer.verified ? "已验证" : "未验证")
                            .font(.caption)
                            .foregroundStyle(peer.verified ? .green : .orange)
                    }
                }
            }
            .navigationTitle("附近")
        }
    }
}

struct PrivateChatView: View {
    @EnvironmentObject var engine: ChatEngine
    let peer: Peer
    @State private var draft = ""
    @State private var showPicker = false
    @State private var recorder = VoiceRecorder()
    @State private var recording = false

    var messages: [ChatMessage] {
        guard let fp = peer.fingerprint else { return [] }
        return engine.privateMessages[fp] ?? []
    }

    var body: some View {
        VStack {
            if peer.fingerprint == nil {
                Button("建立私聊（Noise XX）") {
                    engine.startPrivate(with: peer)
                }
                .padding()
            }
            List(messages) { msg in
                VStack(alignment: .leading) {
                    if msg.status == .waiting {
                        Text("等待热点…").font(.caption).foregroundStyle(.orange)
                    }
                    if let t = msg.text { Text(t) }
                    if let thumb = msg.thumbJPEG, let ui = UIImage(data: thumb) {
                        Image(uiImage: ui).resizable().scaledToFit().frame(maxHeight: 120)
                    }
                    if msg.kind == .voice {
                        Text("语音 \(msg.voiceCQOP?.count ?? 0) B")
                    }
                }
            }
            HStack {
                TextField("私聊", text: $draft)
                    .textFieldStyle(.roundedBorder)
                Button("图") { showPicker = true }
                Button(recording ? "停" : "音") {
                    if recording {
                        recording = false
                        if let data = recorder.stop(), let fp = peer.fingerprint {
                            engine.sendPrivateVoice(cqop: data, toFingerprint: fp)
                        }
                    } else {
                        try? recorder.start()
                        recording = true
                    }
                }
                Button("发") {
                    guard let fp = peer.fingerprint else { return }
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !t.isEmpty else { return }
                    engine.sendPrivateText(t, toFingerprint: fp)
                    draft = ""
                }
            }
            .padding()
        }
        .navigationTitle(peer.verified ? "\(peer.nickname)·已验证" : "\(peer.nickname)·未验证")
        .sheet(isPresented: $showPicker) {
            ImagePicker { img in
                if let fp = peer.fingerprint {
                    engine.sendPrivateImage(img, toFingerprint: fp)
                }
            }
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
                    Text("指纹")
                    Text(engine.myFingerprintHex)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                }
                Section("当面核对") {
                    QRCodeView(payload: engine.qrPayload)
                        .frame(height: 200)
                    Button("扫对方二维码") { scan = true }
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
