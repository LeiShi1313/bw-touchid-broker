import Foundation
import LocalAuthentication
import Security

enum TouchIDSecretError: Error, CustomStringConvertible {
    case usage
    case missingValue(String)
    case keychain(OSStatus)
    case authentication(String)
    case invalidSecret

    var description: String {
        switch self {
        case .usage:
            return """
            Usage:
              bw-broker-keychain store --service SERVICE --account ACCOUNT
              bw-broker-keychain read --service SERVICE --account ACCOUNT [--reason TEXT]
              bw-broker-keychain exists --service SERVICE --account ACCOUNT
              bw-broker-keychain delete --service SERVICE --account ACCOUNT

            The store command reads the secret bytes from stdin.
            """
        case .missingValue(let name):
            return "Missing required value for \(name)"
        case .keychain(let status):
            if let message = SecCopyErrorMessageString(status, nil) as String? {
                return "Keychain error \(status): \(message)"
            }
            return "Keychain error \(status)"
        case .authentication(let message):
            return "Authentication failed: \(message)"
        case .invalidSecret:
            return "Secret stdin was empty"
        }
    }
}

struct Args {
    let command: String
    let service: String
    let account: String
    let reason: String?
}

func parseArgs() throws -> Args {
    let raw = CommandLine.arguments
    guard raw.count >= 2 else { throw TouchIDSecretError.usage }
    let command = raw[1]
    var service: String?
    var account: String?
    var reason: String?
    var i = 2

    while i < raw.count {
        let arg = raw[i]
        switch arg {
        case "--service":
            i += 1
            guard i < raw.count else { throw TouchIDSecretError.missingValue("--service") }
            service = raw[i]
        case "--account":
            i += 1
            guard i < raw.count else { throw TouchIDSecretError.missingValue("--account") }
            account = raw[i]
        case "--reason":
            i += 1
            guard i < raw.count else { throw TouchIDSecretError.missingValue("--reason") }
            reason = raw[i]
        default:
            throw TouchIDSecretError.usage
        }
        i += 1
    }

    guard let service = service, !service.isEmpty else { throw TouchIDSecretError.missingValue("--service") }
    guard let account = account, !account.isEmpty else { throw TouchIDSecretError.missingValue("--account") }
    guard ["store", "read", "exists", "delete"].contains(command) else { throw TouchIDSecretError.usage }

    return Args(command: command, service: service, account: account, reason: reason)
}

func baseQuery(service: String, account: String) -> [String: Any] {
    return [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account
    ]
}

func store(service: String, account: String) throws {
    let secretData = FileHandle.standardInput.readDataToEndOfFile()
    guard !secretData.isEmpty else { throw TouchIDSecretError.invalidSecret }

    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.userPresence],
        &accessError
    ) else {
        if let error = accessError?.takeRetainedValue() {
            fputs("Access control error: \(error)\n", stderr)
        }
        throw TouchIDSecretError.keychain(errSecParam)
    }

    let deleteStatus = SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
    if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
        throw TouchIDSecretError.keychain(deleteStatus)
    }

    var query = baseQuery(service: service, account: account)
    query[kSecValueData as String] = secretData
    query[kSecAttrAccessControl as String] = access

    let addStatus = SecItemAdd(query as CFDictionary, nil)
    if addStatus == errSecSuccess {
        return
    }

    // Some macOS command-line contexts reject SecAccessControl-backed generic
    // password items with errSecMissingEntitlement. Keep the secret in the
    // local login Keychain and enforce user presence explicitly on read.
    guard addStatus == errSecMissingEntitlement else {
        throw TouchIDSecretError.keychain(addStatus)
    }

    var fallbackQuery = baseQuery(service: service, account: account)
    fallbackQuery[kSecValueData as String] = secretData
    fallbackQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let fallbackStatus = SecItemAdd(fallbackQuery as CFDictionary, nil)
    guard fallbackStatus == errSecSuccess else { throw TouchIDSecretError.keychain(fallbackStatus) }
}

func read(service: String, account: String, reason: String?) throws {
    var query = baseQuery(service: service, account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let context = LAContext()
    context.localizedReason = reason ?? "Authenticate to read the broker secret"
    try authenticate(context: context, reason: context.localizedReason)
    query[kSecUseAuthenticationContext as String] = context

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else { throw TouchIDSecretError.keychain(status) }
    guard let data = result as? Data else { throw TouchIDSecretError.keychain(errSecInternalError) }
    FileHandle.standardOutput.write(data)
}

func authenticate(context: LAContext, reason: String) throws {
    var evaluationError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
        throw TouchIDSecretError.authentication(evaluationError?.localizedDescription ?? "device owner authentication is unavailable")
    }

    let semaphore = DispatchSemaphore(value: 0)
    var succeeded = false
    var failureMessage: String?
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
        succeeded = success
        failureMessage = error?.localizedDescription
        semaphore.signal()
    }
    semaphore.wait()

    guard succeeded else {
        throw TouchIDSecretError.authentication(failureMessage ?? "user did not authenticate")
    }
}

func exists(service: String, account: String) throws {
    var query = baseQuery(service: service, account: account)
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecSuccess {
        print("yes")
    } else if status == errSecItemNotFound {
        print("no")
        Foundation.exit(1)
    } else {
        throw TouchIDSecretError.keychain(status)
    }
}

func delete(service: String, account: String) throws {
    let status = SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
        return
    }
    throw TouchIDSecretError.keychain(status)
}

do {
    let args = try parseArgs()
    switch args.command {
    case "store":
        try store(service: args.service, account: args.account)
    case "read":
        try read(service: args.service, account: args.account, reason: args.reason)
    case "exists":
        try exists(service: args.service, account: args.account)
    case "delete":
        try delete(service: args.service, account: args.account)
    default:
        throw TouchIDSecretError.usage
    }
} catch let error as TouchIDSecretError {
    fputs("\(error.description)\n", stderr)
    Foundation.exit(2)
} catch {
    fputs("\(error)\n", stderr)
    Foundation.exit(2)
}
