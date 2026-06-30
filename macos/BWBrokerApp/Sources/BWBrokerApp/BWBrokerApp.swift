import AppKit
import Foundation
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
    @Published private(set) var lastStatus: String = "Ready"
    @Published private(set) var output: String = ""

    let homeURL: URL
    private var brokerProcess: Process?

    private init() {
        if let value = ProcessInfo.processInfo.environment["BW_BROKER_HOME"], !value.isEmpty {
            homeURL = URL(fileURLWithPath: value, isDirectory: true)
        } else {
            homeURL = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".bw-broker", isDirectory: true)
        }
        refreshConfiguration()
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
        brokerURL = readBrokerURL() ?? "Not configured"
        catalogSummary = readCatalogSummary()
        if let process = brokerProcess, process.isRunning {
            state = .running
        } else if state != .failed {
            state = .stopped
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

            HStack {
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
