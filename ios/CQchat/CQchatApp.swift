import SwiftUI

@main
struct CQchatApp: App {
    @StateObject private var engine: ChatEngine

    init() {
        let eng: ChatEngine
        do {
            eng = try ChatEngine()
        } catch {
            fatalError("identity: \(error)")
        }
        _engine = StateObject(wrappedValue: eng)
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(engine)
                // Nearby mode is user-gated; do not auto-start BLE on launch.
        }
    }
}
