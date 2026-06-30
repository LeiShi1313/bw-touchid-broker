import AppKit
import Foundation
import Security
import SwiftUI

@main
struct BWBrokerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var controller = BrokerController.shared

    var body: some Scene {
        MenuBarExtra {
            BrokerStatusView(controller: controller)
        } label: {
            Label("BW Broker", systemImage: controller.menuBarSymbol)
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            BrokerController.shared.startBrokerIfEnabled()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        BrokerController.shared.stopBroker()
    }
}

@MainActor
final class BrokerController: ObservableObject {
    static let shared = BrokerController()

    enum BrokerState: String {
        case stopped = "Stopped"
        case starting = "Starting"
        case running = "Running"
        case failed = "Failed"
    }

    @Published private(set) var state: BrokerState = .stopped
    @Published private(set) var brokerURL: String = "Not configured"
    @Published private(set) var catalogSummary: String = "Catalog not found"
    @Published private(set) var clients: [BrokerClient] = []
    @Published private(set) var lastStatus: String = "Ready"
    @Published private(set) var output: String = ""
    @Published var bindHost: String = "127.0.0.1"
    @Published var bindPort: String = "27443"
    @Published var publicURL: String = "https://127.0.0.1:27443"
    @Published var newClientID: String = ""
    @Published var newClientAllowedSecrets: String = "*"
    @Published var newClientTrusted: Bool = false
    @Published private(set) var newClientConfigJSON: String = ""
    @Published var startAtLaunch: Bool = true {
        didSet {
            UserDefaults.standard.set(startAtLaunch, forKey: Self.startAtLaunchKey)
        }
    }

    private static let startAtLaunchKey = "startAtLaunch"
    let homeURL: URL
    private var brokerProcess: Process?

    private init() {
        if UserDefaults.standard.object(forKey: Self.startAtLaunchKey) != nil {
            startAtLaunch = UserDefaults.standard.bool(forKey: Self.startAtLaunchKey)
        }
        if let value = ProcessInfo.processInfo.environment["BW_BROKER_HOME"], !value.isEmpty {
            homeURL = URL(fileURLWithPath: value, isDirectory: true)
        } else {
            homeURL = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".bw-broker", isDirectory: true)
        }
        refreshConfiguration()
    }

    func startBrokerIfEnabled() {
        guard startAtLaunch else {
            lastStatus = "Ready. Start at Launch is off."
            return
        }
        startBroker()
    }

    var isRunning: Bool {
        brokerProcess?.isRunning == true
    }

    var menuBarSymbol: String {
        switch state {
        case .running:
            "lock.shield.fill"
        case .starting:
            "hourglass"
        case .failed:
            "exclamationmark.triangle.fill"
        case .stopped:
            "lock.shield"
        }
    }

    func refreshConfiguration() {
        loadNetworkSettings()
        catalogSummary = readCatalogSummary()
        clients = readClients()
        if let process = brokerProcess, process.isRunning {
            state = .running
        } else if state != .failed {
            state = .stopped
        }
    }

    func saveNetworkSettings() {
        guard !isRunning else {
            lastStatus = "Stop the broker before changing bind settings."
            return
        }
        guard !bindHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            lastStatus = "Bind host is required."
            return
        }
        guard let port = UInt16(bindPort.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            lastStatus = "Port must be between 0 and 65535."
            return
        }
        guard let url = URL(string: publicURL), let scheme = url.scheme, ["https", "http"].contains(scheme) else {
            lastStatus = "Public URL must start with https:// or http://."
            return
        }

        let configURL = homeURL.appendingPathComponent("config.json")
        do {
            var json = try readConfigJSON()
            var server = json["server"] as? [String: Any] ?? [:]
            server["host"] = bindHost.trimmingCharacters(in: .whitespacesAndNewlines)
            server["port"] = Int(port)
            server["public_url"] = publicURL.trimmingCharacters(in: .whitespacesAndNewlines)
            json["server"] = server

            try writeConfigJSON(json, to: configURL)

            loadNetworkSettings()
            lastStatus = "Saved network settings. Start the broker to use them."
        } catch {
            lastStatus = "Failed to save network settings: \(error.localizedDescription)"
        }
    }

    func addClient() {
        let clientID = newClientID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clientID.isEmpty else {
            lastStatus = "Client id is required."
            return
        }
        let allowedSecrets = parseAllowedSecrets(newClientAllowedSecrets)
        do {
            let secret = try generateClientSecret()
            var config = try readConfigJSON()
            var signing = config["signing"] as? [String: Any] ?? [:]
            var existingClients = signing["clients"] as? [[String: Any]] ?? []
            if existingClients.contains(where: { ($0["id"] as? String) == clientID }) {
                lastStatus = "Client already exists: \(clientID)"
                return
            }
            let approval = newClientTrusted ? "trusted" : "prompt"
            let newClient: [String: Any] = [
                "id": clientID,
                "secret": secret,
                "approval": approval,
                "allowed_secrets": allowedSecrets,
            ]
            existingClients.append(newClient)
            signing["clients"] = existingClients
            config["signing"] = signing
            try writeConfigJSON(config, to: homeURL.appendingPathComponent("config.json"))

            let clientConfig = [
                "broker_url": publicURL,
                "client_id": clientID,
                "client_secret": secret,
                "approval": approval,
                "allowed_secrets": allowedSecrets,
            ] as [String: Any]
            let clientConfigData = try JSONSerialization.data(
                withJSONObject: clientConfig,
                options: [.prettyPrinted, .sortedKeys]
            )
            newClientConfigJSON = String(data: clientConfigData, encoding: .utf8) ?? ""
            newClientID = ""
            newClientAllowedSecrets = "*"
            newClientTrusted = false
            clients = readClients()
            restartBrokerAfterConfigChange("Added client \(clientID).")
        } catch {
            lastStatus = "Failed to add client: \(error.localizedDescription)"
        }
    }

    func setClientTrusted(_ clientID: String, trusted: Bool) {
        do {
            var config = try readConfigJSON()
            guard var signing = config["signing"] as? [String: Any],
                  var existingClients = signing["clients"] as? [[String: Any]]
            else {
                lastStatus = "Config has no signing clients."
                return
            }
            guard let index = existingClients.firstIndex(where: { ($0["id"] as? String) == clientID }) else {
                lastStatus = "Unknown client: \(clientID)"
                return
            }
            existingClients[index]["approval"] = trusted ? "trusted" : "prompt"
            signing["clients"] = existingClients
            config["signing"] = signing
            try writeConfigJSON(config, to: homeURL.appendingPathComponent("config.json"))
            clients = readClients()
            restartBrokerAfterConfigChange(
                trusted ? "Trusted client \(clientID)." : "Require approval for \(clientID)."
            )
        } catch {
            lastStatus = "Failed to update client: \(error.localizedDescription)"
        }
    }

    func clientTrustBinding(_ clientID: String) -> Binding<Bool> {
        Binding(
            get: {
                self.clients.first(where: { $0.id == clientID })?.trusted ?? false
            },
            set: { trusted in
                self.setClientTrusted(clientID, trusted: trusted)
            }
        )
    }

    func copyNewClientConfig() {
        guard !newClientConfigJSON.isEmpty else {
            lastStatus = "No new client config to copy."
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(newClientConfigJSON, forType: .string)
        lastStatus = "Copied new client config."
    }

    func clearNewClientConfig() {
        newClientConfigJSON = ""
    }

    func useLocalhostBinding() {
        bindHost = "127.0.0.1"
        bindPort = bindPort.isEmpty ? "27443" : bindPort
        publicURL = "https://127.0.0.1:\(bindPort)"
    }

    func useAllInterfacesBinding() {
        bindHost = "0.0.0.0"
        bindPort = bindPort.isEmpty ? "27443" : bindPort
        if publicURL.contains("127.0.0.1") || publicURL.contains("0.0.0.0") {
            publicURL = "https://<your-lan-or-tailscale-ip>:\(bindPort)"
        }
    }

    func startBroker() {
        refreshConfiguration()
        guard brokerProcess?.isRunning != true else {
            lastStatus = "Broker is already running."
            return
        }
        guard let brokerURL = resolveBrokerExecutable() else {
            state = .failed
            lastStatus = "Could not find bw-broker. Build the app bundle or set BW_BROKER_BINARY."
            return
        }

        state = .starting
        appendOutput("Starting broker with \(brokerURL.path)\n")

        let process = Process()
        process.executableURL = brokerURL
        process.arguments = ["serve"]
        process.environment = mergedEnvironment()

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        capture(stdout, prefix: "")
        capture(stderr, prefix: "")

        process.terminationHandler = { [weak self] terminatedProcess in
            DispatchQueue.main.async {
                self?.brokerDidExit(status: terminatedProcess.terminationStatus)
            }
        }

        do {
            try process.run()
            brokerProcess = process
            state = .running
            lastStatus = "Broker is running."
        } catch {
            state = .failed
            lastStatus = "Failed to start broker: \(error.localizedDescription)"
            appendOutput("\(lastStatus)\n")
        }
    }

    func stopBroker() {
        guard let process = brokerProcess else {
            state = .stopped
            lastStatus = "Broker is stopped."
            return
        }
        if process.isRunning {
            process.terminate()
            lastStatus = "Stopping broker..."
        } else {
            brokerProcess = nil
            state = .stopped
            lastStatus = "Broker is stopped."
        }
    }

    func runBootstrap() {
        runBrokerCommand(["bootstrap"], label: "Bootstrap")
    }

    func buildCatalog() {
        runBrokerCommand(["build-catalog", "--sync"], label: "Build catalog")
    }

    func selfTestKeychain() {
        runBrokerCommand(["self-test-keychain"], label: "Keychain self-test")
    }

    func openBrokerHome() {
        NSWorkspace.shared.open(homeURL)
    }

    func copyBrokerURL() {
        guard brokerURL != "Not configured" else {
            lastStatus = "Broker URL is not configured."
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(brokerURL, forType: .string)
        lastStatus = "Copied broker URL."
    }

    func clearOutput() {
        output = ""
    }

    private func runBrokerCommand(_ arguments: [String], label: String) {
        guard let brokerURL = resolveBrokerExecutable() else {
            state = .failed
            lastStatus = "Could not find bw-broker. Build the app bundle or set BW_BROKER_BINARY."
            return
        }
        lastStatus = "\(label) running..."
        appendOutput("$ bw-broker \(arguments.joined(separator: " "))\n")

        let environment = mergedEnvironment()
        Task.detached {
            let result = await CommandRunner.run(
                executableURL: brokerURL,
                arguments: arguments,
                environment: environment
            )
            await MainActor.run {
                self.appendOutput(result.output)
                if result.exitCode == 0 {
                    self.lastStatus = "\(label) succeeded."
                    self.refreshConfiguration()
                } else {
                    self.lastStatus = "\(label) failed with exit \(result.exitCode)."
                    self.state = self.isRunning ? .running : .failed
                }
            }
        }
    }

    private func brokerDidExit(status: Int32) {
        brokerProcess = nil
        if status == 0 || status == 15 {
            state = .stopped
            lastStatus = "Broker stopped."
        } else {
            state = .failed
            lastStatus = "Broker exited with status \(status)."
        }
        appendOutput("Broker exited with status \(status).\n")
    }

    private func capture(_ pipe: Pipe, prefix: String) {
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else {
                return
            }
            DispatchQueue.main.async {
                self?.appendOutput(prefix + text)
            }
        }
    }

    private func appendOutput(_ text: String) {
        output += text
        if output.count > 12_000 {
            output.removeFirst(output.count - 12_000)
        }
    }

    private func mergedEnvironment() -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["BW_BROKER_HOME"] = homeURL.path
        return environment
    }

    private func readBrokerURL() -> String? {
        guard let server = readConfigSection("server") else {
            return nil
        }
        return server["public_url"] as? String
    }

    private func loadNetworkSettings() {
        guard let server = readConfigSection("server") else {
            brokerURL = "Not configured"
            return
        }
        bindHost = server["host"] as? String ?? "127.0.0.1"
        if let port = server["port"] as? Int {
            bindPort = "\(port)"
        } else {
            bindPort = "27443"
        }
        publicURL = server["public_url"] as? String ?? "https://\(bindHost):\(bindPort)"
        brokerURL = publicURL
    }

    private func readClients() -> [BrokerClient] {
        guard let signing = readConfigSection("signing"),
              let rawClients = signing["clients"] as? [[String: Any]]
        else {
            return []
        }
        return rawClients.compactMap { rawClient in
            guard let id = rawClient["id"] as? String else {
                return nil
            }
            let approval = rawClient["approval"] as? String ?? "prompt"
            let allowedSecrets = rawClient["allowed_secrets"] as? [String] ?? []
            return BrokerClient(
                id: id,
                trusted: approval == "trusted",
                allowedSecrets: allowedSecrets.isEmpty ? ["*"] : allowedSecrets
            )
        }
        .sorted { $0.id < $1.id }
    }

    private func readConfigJSON() throws -> [String: Any] {
        let configURL = homeURL.appendingPathComponent("config.json")
        let data = try Data(contentsOf: configURL)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw BrokerAppError.invalidConfig
        }
        return json
    }

    private func writeConfigJSON(_ json: [String: Any], to configURL: URL) throws {
        let updated = try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys])
        try (updated + Data("\n".utf8)).write(to: configURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    }

    private func parseAllowedSecrets(_ value: String) -> [String] {
        let parsed = value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return parsed.isEmpty ? ["*"] : parsed
    }

    private func generateClientSecret() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            throw BrokerAppError.randomFailure(status)
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func restartBrokerAfterConfigChange(_ message: String) {
        let shouldRestart = isRunning
        if shouldRestart {
            stopBroker()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                self.startBroker()
                self.lastStatus = "\(message) Restarted broker."
            }
        } else {
            lastStatus = "\(message) Start the broker to use it."
        }
    }

    private func readCatalogSummary() -> String {
        let catalogURL = homeURL.appendingPathComponent("catalog.json")
        guard
            let data = try? Data(contentsOf: catalogURL),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let secrets = json["secrets"] as? [String: Any]
        else {
            return "Catalog not found"
        }
        let count = secrets.count
        return "\(count) \(count == 1 ? "entry" : "entries")"
    }

    private func readConfigSection(_ name: String) -> [String: Any]? {
        let configURL = homeURL.appendingPathComponent("config.json")
        guard
            let data = try? Data(contentsOf: configURL),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return json[name] as? [String: Any]
    }

    private func resolveBrokerExecutable() -> URL? {
        let fileManager = FileManager.default
        let environment = ProcessInfo.processInfo.environment
        if let path = environment["BW_BROKER_BINARY"], fileManager.isExecutableFile(atPath: path) {
            return URL(fileURLWithPath: path)
        }
        if let bundled = Bundle.main.url(forResource: "bw-broker", withExtension: nil),
           fileManager.isExecutableFile(atPath: bundled.path)
        {
            return bundled
        }

        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let candidates = [
            repoRoot.appendingPathComponent("target/release/bw-broker"),
            repoRoot.appendingPathComponent("target/debug/bw-broker"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("target/release/bw-broker"),
        ]
        return candidates.first { fileManager.isExecutableFile(atPath: $0.path) }
    }
}

struct BrokerClient: Identifiable, Equatable {
    let id: String
    let trusted: Bool
    let allowedSecrets: [String]
}

enum BrokerAppError: LocalizedError {
    case invalidConfig
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidConfig:
            "Config file is not a JSON object."
        case .randomFailure(let status):
            "Secure random generation failed with status \(status)."
        }
    }
}

struct CommandResult: Sendable {
    let exitCode: Int32
    let output: String
}

enum CommandRunner {
    static func run(
        executableURL: URL,
        arguments: [String],
        environment: [String: String]
    ) async -> CommandResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = executableURL
                process.arguments = arguments
                process.environment = environment

                let stdout = Pipe()
                let stderr = Pipe()
                process.standardOutput = stdout
                process.standardError = stderr

                do {
                    try process.run()
                    process.waitUntilExit()
                    let output = readPipe(stdout) + readPipe(stderr)
                    continuation.resume(
                        returning: CommandResult(exitCode: process.terminationStatus, output: output)
                    )
                } catch {
                    continuation.resume(
                        returning: CommandResult(exitCode: 127, output: "\(error.localizedDescription)\n")
                    )
                }
            }
        }
    }

    private static func readPipe(_ pipe: Pipe) -> String {
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}

struct BrokerStatusView: View {
    @ObservedObject var controller: BrokerController

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: controller.menuBarSymbol)
                    .font(.title2)
                    .foregroundStyle(statusColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text("BW Broker")
                        .font(.headline)
                    Text(controller.state.rawValue)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
                GridRow {
                    Text("URL")
                        .foregroundStyle(.secondary)
                    Text(controller.brokerURL)
                        .textSelection(.enabled)
                }
                GridRow {
                    Text("Home")
                        .foregroundStyle(.secondary)
                    Text(controller.homeURL.path)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                GridRow {
                    Text("Catalog")
                        .foregroundStyle(.secondary)
                    Text(controller.catalogSummary)
                }
            }
            .font(.caption)

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Network")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                    GridRow {
                        Text("Bind")
                            .foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            TextField("127.0.0.1", text: $controller.bindHost)
                                .textFieldStyle(.roundedBorder)
                                .disabled(controller.isRunning)
                            Text(":")
                                .foregroundStyle(.secondary)
                            TextField("27443", text: $controller.bindPort)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 72)
                                .disabled(controller.isRunning)
                        }
                    }
                    GridRow {
                        Text("Public URL")
                            .foregroundStyle(.secondary)
                        TextField("https://host:27443", text: $controller.publicURL)
                            .textFieldStyle(.roundedBorder)
                            .disabled(controller.isRunning)
                    }
                }

                HStack {
                    Button("Localhost") {
                        controller.useLocalhostBinding()
                    }
                    .disabled(controller.isRunning)

                    Button("0.0.0.0") {
                        controller.useAllInterfacesBinding()
                    }
                    .disabled(controller.isRunning)

                    Spacer()

                    Button("Save") {
                        controller.saveNetworkSettings()
                    }
                    .disabled(controller.isRunning)
                }

                Text(controller.isRunning ? "Stop the broker before changing bind settings." : "Use 0.0.0.0 only behind a trusted network, VPN, tunnel, or firewall.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Divider()

            HStack {
                Toggle("Start at Launch", isOn: $controller.startAtLaunch)

                Spacer()

                Button(controller.isRunning ? "Stop" : "Start") {
                    controller.isRunning ? controller.stopBroker() : controller.startBroker()
                }
                .keyboardShortcut(.defaultAction)

                Button("Build Catalog") {
                    controller.buildCatalog()
                }

                Button("Bootstrap") {
                    controller.runBootstrap()
                }
            }

            HStack {
                Button("Self-Test Keychain") {
                    controller.selfTestKeychain()
                }

                Button("Copy URL") {
                    controller.copyBrokerURL()
                }

                Button("Open Home") {
                    controller.openBrokerHome()
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Clients")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if controller.clients.isEmpty {
                    Text("No clients configured.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(controller.clients) { client in
                        VStack(alignment: .leading, spacing: 6) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(client.id)
                                    .font(.caption)
                                    .textSelection(.enabled)
                                Text("Allowed: \(client.allowedSecrets.joined(separator: ", "))")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }

                            HStack {
                                Label(
                                    client.trusted ? "Approval: Trusted" : "Approval: Prompt",
                                    systemImage: client.trusted ? "checkmark.shield.fill" : "hand.raised.fill"
                                )
                                .font(.caption)
                                .foregroundStyle(client.trusted ? .green : .orange)

                                Spacer()

                                Picker("Approval", selection: controller.clientTrustBinding(client.id)) {
                                    Text("Prompt").tag(false)
                                    Text("Trusted").tag(true)
                                }
                                .pickerStyle(.segmented)
                                .labelsHidden()
                                .frame(width: 170)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }

                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                    GridRow {
                        Text("New")
                            .foregroundStyle(.secondary)
                        TextField("client-id", text: $controller.newClientID)
                            .textFieldStyle(.roundedBorder)
                    }
                    GridRow {
                        Text("Allowed")
                            .foregroundStyle(.secondary)
                        TextField("* or secret_a,secret_b", text: $controller.newClientAllowedSecrets)
                            .textFieldStyle(.roundedBorder)
                    }
                }

                HStack {
                    Toggle("Trusted", isOn: $controller.newClientTrusted)
                    Spacer()
                    Button("Add Client") {
                        controller.addClient()
                    }
                }

                if !controller.newClientConfigJSON.isEmpty {
                    Text("New client secret is shown once.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ScrollView {
                        Text(controller.newClientConfigJSON)
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .frame(maxHeight: 90)
                    HStack {
                        Button("Copy New Config") {
                            controller.copyNewClientConfig()
                        }
                        Button("Hide") {
                            controller.clearNewClientConfig()
                        }
                    }
                }
            }

            Text(controller.lastStatus)
                .font(.caption)
                .foregroundStyle(.secondary)

            Divider()

            HStack {
                Text("Output")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Clear") {
                    controller.clearOutput()
                }
                .font(.caption)
            }

            ScrollView {
                Text(controller.output.isEmpty ? "No output yet." : controller.output)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(minHeight: 120, maxHeight: 180)

            Divider()

            HStack {
                Button("Refresh") {
                    controller.refreshConfiguration()
                }
                Spacer()
                Button("Quit") {
                    NSApp.terminate(nil)
                }
            }
        }
        .padding(16)
        .frame(width: 440)
    }

    private var statusColor: Color {
        switch controller.state {
        case .running:
            .green
        case .starting:
            .orange
        case .failed:
            .red
        case .stopped:
            .secondary
        }
    }
}
