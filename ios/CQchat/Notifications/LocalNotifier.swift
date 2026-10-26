import UserNotifications

final class LocalNotifier {
    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func message(title: String, body: String) {
        // Only while app can schedule local notifications (not after kill — system won't run us).
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let req = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(req)
    }

    func nearby(_ name: String) {
        message(title: "附近的人", body: "发现 \(name)")
    }
}
