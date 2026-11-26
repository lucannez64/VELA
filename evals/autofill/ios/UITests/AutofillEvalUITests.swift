import XCTest

/// iOS autofill eval. VELA is the AutoFill provider (Settings > Passwords >
/// Password Options); this drives the system AutoFill UI the way a user does:
///
///  - logins: tap the field, then the QuickType suggestion if VELA's identity
///    store offers one, else the key icon > VELA > Face ID > pick the login
///  - cards (iOS 18+): per field, the edit menu's AutoFill > VELA > pick the
///    matching insertable ("Eval Visa · Card number", "· Expiry", "· CVV")
///  - identity/email: VELA has no provider path for these on iOS; the run
///    records whether VELA was offered at all (it is not expected to be)
///
/// Surfaces: safari, webview (lab app WKWebView), native (lab app forms), app
/// (live apps). Configure through TEST_RUNNER_-prefixed env vars, which
/// xcodebuild passes to this process:
///   TEST_RUNNER_EVAL_SERVER   http://localhost:8080
///   TEST_RUNNER_EVAL_RUN_ID   groups results
///   TEST_RUNNER_EVAL_SURFACES safari,webview,native
///   TEST_RUNNER_EVAL_TIER     fixture | live | live-app
///   TEST_RUNNER_EVAL_ONLY     comma list of ids
///   TEST_RUNNER_EVAL_PORT     fixture HTTPS port (8443)
/// The server must run with --allow-host-actions so Face ID can be answered.
final class AutofillEvalUITests: XCTestCase {
    let env = ProcessInfo.processInfo.environment
    lazy var server = env["EVAL_SERVER"] ?? "http://localhost:8080"
    lazy var runId = env["EVAL_RUN_ID"] ?? "ios-\(Int(Date().timeIntervalSince1970))"
    lazy var surfaces = (env["EVAL_SURFACES"] ?? "safari,webview,native").split(separator: ",").map(String.init)
    lazy var tier = env["EVAL_TIER"] ?? "fixture"
    lazy var only: Set<String>? = env["EVAL_ONLY"].map { Set($0.split(separator: ",").map(String.init)) }
    lazy var port = env["EVAL_PORT"] ?? "8443"

    let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

    override func setUp() { continueAfterFailure = true }

    func testSweep() throws {
        for surface in surfaces {
            switch (tier, surface) {
            case ("live", "safari"): try liveSites()
            case ("live-app", _): try liveApps()
            case (_, "native"): for s in try scenarios("native") { runScenario(surface: surface, s, native: true) }
            default: for s in try scenarios("fixture") { runScenario(surface: surface, s, native: false) }
            }
        }
    }

    // MARK: Scenarios

    func scenarios(_ tier: String) throws -> [[String: Any]] {
        let arr = try JSONSerialization.jsonObject(with: get("/__eval/scenarios?tier=\(tier)&scheme=https&port=\(port)")) as? [[String: Any]] ?? []
        return arr.filter { only == nil || only!.contains($0["id"] as? String ?? "") }
    }

    func runScenario(surface: String, _ sc: [String: Any], native: Bool) {
        let id = sc["id"] as! String
        let kind = sc["kind"] as? String ?? "login"
        let run = "\(runId).ios-\(surface).provider.\(id)"
        let choose = sc["choose"] as? [String: Any]
        var offered: Bool?
        var taps = 0
        var failure: String?
        let t0 = Date()
        let app: XCUIApplication = (surface == "safari") ? safari : XCUIApplication(bundleIdentifier: "dev.vela.autofilleval.lab")
        do {
            try launch(surface: surface, sc: sc, run: run, native: native)
            guard waitForReport(run: run, page: id, timeout: 20) else { throw EvalError("page never reported (hosts / CA / network?)") }
            Thread.sleep(forTimeInterval: 0.8 + ((sc["settleMs"] as? Double) ?? 0) / 1000)
            for step in sc["steps"] as? [[String: Any]] ?? [] {
                if let ms = step["wait"] as? Double { Thread.sleep(forTimeInterval: ms / 1000); continue }
                if let key = step["click"] as? String { try tapField(app, run: run, main: id, key: key, native: native); taps += 1; continue }
                if let key = step["generate"] as? String {
                    try tapField(app, run: run, main: id, key: key, native: native); taps += 1
                    // iOS's own strong-password suggestion is not VELA; VELA has
                    // no generator in the AutoFill UI. Record whether VELA showed.
                    offered = false
                    continue
                }
                guard let key = step["fill"] as? String else { continue }
                if kind == "card" {
                    let expect = sc["expect"] as? [String: Any] ?? [:]
                    for (fieldKey, ref) in expect {
                        guard let ref = ref as? String, let label = insertLabel(ref) else { continue }
                        try tapField(app, run: run, main: id, key: fieldKey, native: native); taps += 1
                        let r = insertText(app, label: label)
                        taps += r.taps
                        offered = (offered ?? false) || r.offered
                    }
                } else {
                    try tapField(app, run: run, main: id, key: key, native: native); taps += 1
                    let r = pickCredential(app, choose: choose)
                    taps += r.taps
                    offered = (offered ?? false) || r.offered
                }
                Thread.sleep(forTimeInterval: 0.5)
            }
            Thread.sleep(forTimeInterval: 1.5)
        } catch {
            failure = (error as? EvalError)?.message ?? error.localizedDescription
        }
        let score = post("/__eval/result", [
            "runId": runId, "run": run, "tier": native ? "native" : "fixture", "scenarioId": id,
            "surface": "ios-\(surface)", "platform": "ios", "client": surface == "safari" ? "safari" : "dev.vela.autofilleval.lab",
            "mode": "provider", "offered": offered as Any? ?? NSNull(), "interactions": taps,
            "durationMs": Int(Date().timeIntervalSince(t0) * 1000), "error": failure as Any? ?? NSNull(),
        ])
        print("AUTOFILL_EVAL ios-\(surface) \(id) -> \(score)")
        XCUIDevice.shared.press(.home)
    }

    func launch(surface: String, sc: [String: Any], run: String, native: Bool) throws {
        let lab = XCUIApplication(bundleIdentifier: "dev.vela.autofilleval.lab")
        if native {
            lab.launchEnvironment = ["EVAL_SERVER": server, "EVAL_RUN": run, "EVAL_FORM": sc["id"] as! String]
            lab.launch()
            return
        }
        let url = withRun(sc["url"] as! String, run)
        if surface == "webview" {
            lab.launchEnvironment = ["EVAL_SERVER": server, "EVAL_RUN": run, "EVAL_URL": url]
            lab.launch()
        } else {
            XCUIDevice.shared.system.open(URL(string: url)!)
            _ = safari.wait(for: .runningForeground, timeout: 10)
        }
    }

    /// Tap by accessibility id in the lab app; by the beacon's rectangle (CSS
    /// px, scaled into the web view's frame) on web pages.
    func tapField(_ app: XCUIApplication, run: String, main: String, key: String, native: Bool) throws {
        if native {
            let el = app.descendants(matching: .any).matching(identifier: key).firstMatch
            guard el.waitForExistence(timeout: 5) else { throw EvalError("no field \(key)") }
            el.tap()
            return
        }
        let pages = try JSONSerialization.jsonObject(with: get("/__eval/state?run=\(enc(run))")) as? [String: Any] ?? [:]
        let pageKey = key.contains("#") ? String(key.split(separator: "#")[0]) : main
        let fieldKey = key.contains("#") ? String(key.split(separator: "#")[1]) : key
        guard let snap = pages[pageKey] as? [String: Any],
              let field = (snap["fields"] as? [String: Any])?[fieldKey] as? [String: Any],
              let r = field["rect"] as? [String: Double],
              let mainSnap = pages[main] as? [String: Any],
              let vp = mainSnap["viewport"] as? [String: Double] else { throw EvalError("no rect for \(key)") }
        var cx = r["x"]! + r["w"]! / 2, cy = r["y"]! + r["h"]! / 2
        if pageKey != main {
            let path = String(pageKey.split(separator: ":")[0])
            let frames = mainSnap["frames"] as? [[String: Any]] ?? []
            guard let fr = frames.first(where: { ($0["src"] as? String ?? "").contains("/\(path).html") }),
                  let fRect = fr["rect"] as? [String: Double] else { throw EvalError("iframe for \(pageKey) not found") }
            cx += fRect["x"]!; cy += fRect["y"]!
        }
        let web = app.webViews.firstMatch
        guard web.waitForExistence(timeout: 5) else { throw EvalError("no web view") }
        let frame = web.frame
        let scale = Double(frame.width) / (vp["innerWidth"] ?? Double(frame.width))
        let point = CGVector(dx: Double(frame.minX) + cx * scale, dy: Double(frame.minY) + cy * scale)
        app.coordinate(withNormalizedOffset: .zero).withOffset(point).tap()
    }

    /// QuickType suggestion first; otherwise key icon > (provider list) > VELA.
    func pickCredential(_ app: XCUIApplication, choose: [String: Any]?) -> (offered: Bool, taps: Int) {
        var taps = 0
        let wanted = [choose?["text"] as? String, choose?["name"] as? String].compactMap { $0 }.filter { !$0.isEmpty }
        // 1) A one-tap QuickType suggestion naming the account.
        for w in wanted {
            let chip = app.keyboards.buttons.containing(NSPredicate(format: "label CONTAINS[c] %@", w)).firstMatch
            if chip.waitForExistence(timeout: 2) { chip.tap(); return (true, 1) }
        }
        // 2) The key icon / "Passwords" button on the QuickType bar.
        let key = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'Password' OR identifier CONTAINS[c] 'password'")).firstMatch
        guard key.waitForExistence(timeout: 3) else { return (false, taps) }
        key.tap(); taps += 1
        // 3) With several providers, iOS asks which one.
        let vela = anyApp(label: "VELA", timeout: 4)
        if let vela, !vela.label.contains("–") { vela.tap(); taps += 1 }
        // 4) VELA unlocks with Face ID before listing anything.
        answerBiometric()
        for w in wanted {
            if let row = anyApp(label: w, timeout: 8) { row.tap(); taps += 1; return (true, taps) }
        }
        return (vela != nil, taps)
    }

    /// iOS 18 text insertion: edit menu > AutoFill > VELA > insertable.
    func insertText(_ app: XCUIApplication, label: String) -> (offered: Bool, taps: Int) {
        var taps = 0
        Thread.sleep(forTimeInterval: 0.5)
        let field = app.descendants(matching: .any).matching(NSPredicate(format: "hasKeyboardFocus == true")).firstMatch
        if field.exists { field.press(forDuration: 0.8); taps += 1 }
        guard let autofill = anyApp(label: "AutoFill", timeout: 3) else { return (false, taps) }
        autofill.tap(); taps += 1
        guard let vela = anyApp(label: "VELA", timeout: 3) else { return (false, taps) }
        vela.tap(); taps += 1
        answerBiometric()
        guard let row = anyApp(label: label, timeout: 8) else { return (true, taps) }
        row.tap(); taps += 1
        return (true, taps)
    }

    func insertLabel(_ ref: String) -> String? {
        if ref.hasSuffix(".number") || ref.contains(".number[") { return "Card number" }
        if ref.hasSuffix(".exp") { return "Expiry" }
        if ref.hasSuffix(".cvv") { return "CVV" }
        if ref.hasSuffix(".cardholderName") { return "Cardholder" }
        return nil // split month/year selects: no insertable matches
    }

    /// Search the foreground app, then SpringBoard (system sheets).
    func anyApp(label: String, timeout: TimeInterval) -> XCUIElement? {
        let pred = NSPredicate(format: "label CONTAINS[c] %@", label)
        let deadline = Date().addingTimeInterval(timeout)
        let apps = [safari, XCUIApplication(bundleIdentifier: "dev.vela.autofilleval.lab"), springboard]
        repeat {
            for a in apps where a.state == .runningForeground || a == springboard {
                let el = a.descendants(matching: .any).matching(pred).firstMatch
                if el.exists && el.isHittable { return el }
            }
            Thread.sleep(forTimeInterval: 0.3)
        } while Date() < deadline
        return nil
    }

    func answerBiometric() {
        Thread.sleep(forTimeInterval: 1.2)
        _ = post("/__eval/host/ios-biometric-match", [:])
        Thread.sleep(forTimeInterval: 1.0)
    }

    // MARK: Live tiers (oracle scoring)

    func liveSites() throws {
        let sites = try JSONSerialization.jsonObject(with: get("/__eval/scenarios?tier=live")) as? [[String: Any]] ?? []
        for site in sites where only == nil || only!.contains(site["id"] as! String) {
            let t0 = Date()
            var reachable = true, offered: Bool? = nil
            XCUIDevice.shared.system.open(URL(string: site["url"] as! String)!)
            Thread.sleep(forTimeInterval: 7)
            let fields = safari.webViews.textFields.allElementsBoundByIndex + safari.webViews.secureTextFields.allElementsBoundByIndex
            if let anchor = fields.first(where: { $0.isHittable }) {
                anchor.tap()
                offered = pickCredential(safari, choose: ["text": "vela.eval@example.org"]).offered
                Thread.sleep(forTimeInterval: 1.5)
            } else { reachable = false }
            _ = post("/__eval/result", [
                "runId": runId, "tier": "live", "scenarioId": site["id"]!, "surface": "ios-safari", "platform": "ios", "client": "safari",
                "mode": "provider", "offered": offered as Any? ?? NSNull(), "reachable": reachable, "frames": [["fields": readFields(safari)]],
                "durationMs": Int(Date().timeIntervalSince(t0) * 1000),
            ])
        }
    }

    func liveApps() throws {
        let apps = try JSONSerialization.jsonObject(with: get("/__eval/scenarios?tier=live-app")) as? [[String: Any]] ?? []
        for entry in apps where only == nil || only!.contains(entry["id"] as! String) {
            let app = XCUIApplication(bundleIdentifier: entry["ios"] as! String)
            let t0 = Date()
            app.launch()
            guard app.wait(for: .runningForeground, timeout: 10) else { continue } // not installed
            for text in entry["toLogin"] as? [String] ?? [] {
                let b = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] %@", text)).firstMatch
                if b.waitForExistence(timeout: 6) { b.tap(); Thread.sleep(forTimeInterval: 2) }
            }
            let fields = app.textFields.allElementsBoundByIndex + app.secureTextFields.allElementsBoundByIndex
            var offered: Bool? = nil, reachable = true
            if let anchor = fields.first(where: { $0.isHittable }) {
                anchor.tap()
                offered = pickCredential(app, choose: ["text": "vela.eval@example.org"]).offered
                Thread.sleep(forTimeInterval: 1.5)
            } else { reachable = false }
            _ = post("/__eval/result", [
                "runId": runId, "tier": "live-app", "scenarioId": entry["id"]!, "surface": "ios-app", "platform": "ios", "client": entry["ios"]!,
                "mode": "provider", "offered": offered as Any? ?? NSNull(), "reachable": reachable, "frames": [["fields": readFields(app)]],
                "durationMs": Int(Date().timeIntervalSince(t0) * 1000),
            ])
            app.terminate()
        }
    }

    /// Accessibility values; secure fields read back as bullets, which count as
    /// the live password when the length matches (nothing else could be there).
    func readFields(_ app: XCUIApplication) -> [[String: Any]] {
        let live = "Live-Eval-Only-9g}pw"
        var out: [[String: Any]] = []
        for f in app.textFields.allElementsBoundByIndex where f.exists {
            out.append(["value": (f.value as? String).flatMap { $0 == f.placeholderValue ? "" : $0 } ?? "", "type": "text", "name": f.identifier, "placeholder": f.placeholderValue ?? "", "visible": true, "frame": "main"])
        }
        for f in app.secureTextFields.allElementsBoundByIndex where f.exists {
            let v = f.value as? String ?? ""
            out.append(["value": v.count == live.count && v.allSatisfy({ $0 == "•" }) ? live : "", "type": "password", "name": f.identifier, "visible": true, "frame": "main"])
        }
        return out
    }

    // MARK: Plumbing

    func waitForReport(run: String, page: String, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if let d = try? get("/__eval/state?run=\(enc(run))&page=\(enc(page))"), d.first == UInt8(ascii: "{") { return true }
            Thread.sleep(forTimeInterval: 0.4)
        } while Date() < deadline
        return false
    }

    func withRun(_ url: String, _ run: String) -> String { url + (url.contains("?") ? "&" : "?") + "run=" + enc(run) }
    func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&=+#"))) ?? s }

    func get(_ path: String) throws -> Data {
        var result: Result<Data, Error> = .failure(EvalError("timeout"))
        let sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: URL(string: server + path)!) { d, _, e in
            result = d.map { .success($0) } ?? .failure(e ?? EvalError("no data")); sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 15)
        return try result.get()
    }

    @discardableResult
    func post(_ path: String, _ body: [String: Any]) -> String {
        var req = URLRequest(url: URL(string: server + path)!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        var text = ""
        let sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { d, _, _ in text = d.flatMap { String(data: $0, encoding: .utf8) } ?? ""; sem.signal() }.resume()
        _ = sem.wait(timeout: .now() + 30)
        return text
    }
}

struct EvalError: Error { let message: String; init(_ m: String) { message = m } }
