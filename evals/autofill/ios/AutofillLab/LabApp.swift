import SwiftUI
import UIKit
import WebKit

/// Autofill Lab: renders one native form from corpus/native-forms.json, or a
/// fixture page in a WKWebView, and reports field values to the eval server.
///
/// Launch environment: EVAL_SERVER (http://localhost:8080), EVAL_RUN,
/// EVAL_FORM (native form id) or EVAL_URL (web page).
@main
struct LabApp: App {
    var body: some Scene {
        WindowGroup { RootView() }
    }
}

enum Eval {
    static let env = ProcessInfo.processInfo.environment
    static let server = env["EVAL_SERVER"] ?? "http://localhost:8080"
    static let run = env["EVAL_RUN"] ?? "manual"
}

struct FieldSpec: Decodable, Identifiable {
    struct IOS: Decodable { var textContentType: String?; var keyboardType: String?; var secure: Bool? }
    let id: String
    let label: String?
    let placeholder: String?
    let ios: IOS?
}

struct FormSpec: Decodable { let id: String; let kind: String; let fields: [FieldSpec] }

struct RootView: View {
    @State private var form: FormSpec?
    @State private var status = "Loading…"

    var body: some View {
        Group {
            if let url = Eval.env["EVAL_URL"].flatMap(URL.init(string:)) {
                WebLab(url: url).ignoresSafeArea(edges: .bottom)
            } else if let form {
                NativeForm(form: form)
            } else {
                Text(status).padding()
            }
        }
        .task { await load() }
    }

    private func load() async {
        guard Eval.env["EVAL_URL"] == nil else { return }
        do {
            let (data, _) = try await URLSession.shared.data(from: URL(string: "\(Eval.server)/__eval/scenarios?tier=native")!)
            let forms = try JSONDecoder().decode([FormSpec].self, from: data)
            form = forms.first { $0.id == Eval.env["EVAL_FORM"] }
            if form == nil { status = "Set EVAL_FORM to one of: " + forms.map(\.id).joined(separator: ", ") }
        } catch {
            status = "Cannot reach \(Eval.server): \(error.localizedDescription)"
        }
    }
}

/// UITextField per spec, so textContentType/keyboardType/secure are the real
/// UIKit properties iOS's AutoFill heuristics read.
struct NativeForm: UIViewControllerRepresentable {
    let form: FormSpec
    func makeUIViewController(context: Context) -> FormController { FormController(form: form) }
    func updateUIViewController(_ vc: FormController, context: Context) {}
}

final class FormController: UIViewController {
    let form: FormSpec
    private var fields: [(String, UITextField)] = []
    private var history: [String: Set<String>] = [:]
    private var timer: Timer?
    private var lastSig = ""

    init(form: FormSpec) { self.form = form; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 24),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
        ])
        for spec in form.fields {
            if let label = spec.label, !label.isEmpty {
                let l = UILabel(); l.text = label; stack.addArrangedSubview(l)
            }
            let tf = UITextField()
            tf.borderStyle = .roundedRect
            tf.placeholder = spec.placeholder
            tf.accessibilityIdentifier = spec.id
            tf.autocapitalizationType = .none
            tf.autocorrectionType = .no
            if let t = spec.ios?.textContentType { tf.textContentType = UITextContentType(rawValue: t) }
            switch spec.ios?.keyboardType {
            case "emailAddress": tf.keyboardType = .emailAddress
            case "numberPad": tf.keyboardType = .numberPad
            default: break
            }
            tf.isSecureTextEntry = spec.ios?.secure ?? false
            stack.addArrangedSubview(tf)
            fields.append((spec.id, tf))
        }
        let button = UIButton(type: .system); button.setTitle("Continue", for: .normal)
        stack.addArrangedSubview(button)
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in self?.report() }
    }

    private func report() {
        var out: [String: Any] = [:]
        for (id, tf) in fields {
            let value = tf.text ?? ""
            if !value.isEmpty { history[id, default: []].insert(value) }
            let r = tf.convert(tf.bounds, to: nil)
            out[id] = [
                "value": value, "tag": "input", "type": tf.isSecureTextEntry ? "password" : "text",
                "name": id, "id": id, "autocomplete": tf.textContentType?.rawValue ?? "",
                "placeholder": tf.placeholder ?? "", "visible": !tf.isHidden,
                "rect": ["x": r.minX, "y": r.minY, "w": r.width, "h": r.height],
            ]
        }
        let body: [String: Any] = [
            "run": Eval.run, "page": form.id, "url": "app://lab/\(form.id)", "ts": Date().timeIntervalSince1970 * 1000,
            "fields": out, "history": history.mapValues { Array($0) }, "frames": [], "screenCoords": true,
            "viewport": ["innerWidth": 0, "devicePixelRatio": 1],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: body) else { return }
        let sig = String(describing: out.mapValues { ($0 as? [String: Any])?["value"] ?? "" })
        guard sig != lastSig else { return }
        lastSig = sig
        var req = URLRequest(url: URL(string: "\(Eval.server)/__eval/report")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = data
        URLSession.shared.dataTask(with: req).resume()
    }
}

/// A fixture page in WKWebView: AutoFill inside an app's embedded web view.
struct WebLab: UIViewRepresentable {
    let url: URL
    func makeUIView(context: Context) -> WKWebView {
        let web = WKWebView(frame: .zero)
        web.isInspectable = true
        web.load(URLRequest(url: url))
        return web
    }
    func updateUIView(_ web: WKWebView, context: Context) {}
}
