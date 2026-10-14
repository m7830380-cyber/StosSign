//
//  Authentication.swift
//  StosSign
//
//  Created by Stossy11 on 18/12/2025.
//

import Foundation
import StosSign_API
import StosSign_Common
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public typealias AppleAPISession = StosSign_API.AppleAPISession
public typealias AppleAPIError = StosSign_API.AppleAPIError

// The login flow below mirrors nab138/isideload (the library behind iloader v2.3.7):
// a state machine over GrandSlam responses, URLs resolved from the URL bag, anisette
// refreshed once it is older than 60 seconds, and Status.hsc handled (409 = Apple already
// pushed the 2FA prompt, 434 = anisette resync required).
public final class Authentication {
    public init() { }

    public static let dateFormatter = ISO8601DateFormatter()

    public typealias AnisetteDataProvider = () async throws -> AnisetteData
    public typealias AnisetteResyncHandler = (_ sim: String) async throws -> AnisetteData
    public typealias VerificationHandler = (@escaping (String?) -> Void) async -> Void

    public static let defaultGsServiceURL = "https://gsa.apple.com/grandslam/GsService2"
    static let defaultTrustedDeviceURL = "https://gsa.apple.com/auth/verify/trusteddevice"
    static let defaultValidateCodeURL = "https://gsa.apple.com/grandslam/GsService2/validate"
    static let urlBagURL = URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup")!
    // Sending the android client info gets us the wrong url bag, so we lie for this request
    static let urlBagClientInfo = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    static let userAgent = "akd/1.0 CFNetwork/808.1.4"
    static let maxLoginAttempts = 15
    static let maxRateLimitRetries = 10
    static let anisetteLifetime: TimeInterval = 60

    private enum LoginState {
        case loggedIn
        case needsDevice2FA
        case needsDevice2FAVerification
        case needsSMS2FA
        case needsSMS2FAVerification
        case needsLogin
    }

    private final class LoginSession {
        let appleID: String
        let password: String
        let anisetteProvider: AnisetteDataProvider?
        let anisetteResync: AnisetteResyncHandler?
        var anisetteData: AnisetteData
        var anisetteFetchedAt = Date()
        var urlBag: [String: Any] = [:]

        var context: GSAContext?
        var spd: [String: Any] = [:]
        var dsid = ""
        var idmsToken = ""
        var phoneNumberID = 1
        var phoneNumbersFetched = false

        init(appleID: String, password: String, anisetteData: AnisetteData, anisetteProvider: AnisetteDataProvider?, anisetteResync: AnisetteResyncHandler?) {
            self.appleID = appleID
            self.password = password
            self.anisetteData = anisetteData
            self.anisetteProvider = anisetteProvider
            self.anisetteResync = anisetteResync
        }

        // One-time passwords go stale; isideload regenerates anisette after 60 seconds.
        func currentAnisette() async throws -> AnisetteData {
            if let anisetteProvider = anisetteProvider,
               Date().timeIntervalSince(anisetteFetchedAt) > Authentication.anisetteLifetime {
                anisetteData = try await anisetteProvider()
                anisetteFetchedAt = Date()
            }
            return anisetteData
        }

        func replaceAnisette(_ data: AnisetteData) {
            anisetteData = data
            anisetteFetchedAt = Date()
        }

        func url(_ key: String, fallback: String) -> URL {
            if let string = urlBag[key] as? String, let url = URL(string: string) {
                return url
            }
            return URL(string: fallback)!
        }
    }

    public static func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        verificationHandler: VerificationHandler? = nil,
        anisetteDataProvider: AnisetteDataProvider? = nil,
        anisetteResyncHandler: AnisetteResyncHandler? = nil
    ) async throws -> (Account, AppleAPISession) {
        let session = LoginSession(
            appleID: unsanitizedAppleID.lowercased(),
            password: password,
            anisetteData: anisetteData,
            anisetteProvider: anisetteDataProvider,
            anisetteResync: anisetteResyncHandler
        )
        session.urlBag = (try? await fetchURLBag()) ?? [:]

        var state = try await login(session)
        var attempts = 0

        while true {
            attempts += 1
            if attempts > maxLoginAttempts {
                throw AppleAPIError.customError(code: -1, message: "Couldn't sign in after \(maxLoginAttempts) attempts")
            }

            switch state {
            case .loggedIn:
                return try await finishLogin(session)

            case .needsDevice2FA:
                try await sendTrustedDeviceTwoFactorCode(session)
                state = .needsDevice2FAVerification

            case .needsDevice2FAVerification:
                let code = try await requestVerificationCode(verificationHandler)
                state = try await verifyTrustedDeviceTwoFactorCode(code, session: session)

            case .needsSMS2FA:
                state = try await sendSMSTwoFactorCode(session)

            case .needsSMS2FAVerification:
                let code = try await requestVerificationCode(verificationHandler)
                state = try await verifySMSTwoFactorCode(code, session: session)

            case .needsLogin:
                state = try await login(session)
            }
        }
    }

    public static func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        verificationHandler: ((@escaping (String?) -> Void) -> Void)? = nil,
        completionHandler: @escaping (Account?, AppleAPISession?, Error?) -> Void
    ) {
        Task {
            do {
                let success = try await authenticate(
                    appleID: unsanitizedAppleID,
                    password: password,
                    anisetteData: anisetteData,
                    verificationHandler: { veri in verificationHandler?(veri) }
                )

                completionHandler(success.0, success.1, nil)
            } catch {
                completionHandler(nil, nil, error)
            }
        }
    }

    // MARK: - Login steps

    private static func login(_ session: LoginSession) async throws -> LoginState {
        let gsServiceURL = session.url("gsService", fallback: defaultGsServiceURL)
        var anisetteData = try await session.currentAnisette()
        var clientDictionary = clientProvidedData(anisetteData)

        let context = GSAContext(username: session.appleID, password: session.password)
        guard let publicKey = context.start() else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        func initialParameters(_ cpd: [String: Any]) -> [String: Any] {
            [
                "A2k": publicKey,
                "cpd": cpd,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": session.appleID
            ]
        }

        var responseDictionary = try await sendGrandSlamRequest(
            url: gsServiceURL,
            parameters: initialParameters(clientDictionary),
            anisetteData: anisetteData
        )

        if let sim = resyncSIM(responseDictionary), let anisetteResync = session.anisetteResync {
            anisetteData = try await anisetteResync(sim)
            session.replaceAnisette(anisetteData)
            clientDictionary = clientProvidedData(anisetteData)
            responseDictionary = try await sendGrandSlamRequest(
                url: gsServiceURL,
                parameters: initialParameters(clientDictionary),
                anisetteData: anisetteData
            )
        }
        try checkGrandSlamError(responseDictionary)

        guard let c = responseDictionary["c"] as? String,
              let salt = responseDictionary["s"] as? Data,
              let iterations = integerValue(responseDictionary["i"]),
              let serverPublicKey = responseDictionary["B"] as? Data
        else {
            throw URLError(.badServerResponse)
        }

        let sp = responseDictionary["sp"] as? String
        guard sp == "s2k" || sp == "s2k_fo" else {
            throw AppleAPIError.customError(code: -1, message: "Unsupported SRP protocol selected: \(sp ?? "none")")
        }

        context.salt = salt
        context.serverPublicKey = serverPublicKey

        guard let verificationMessage = context.makeVerificationMessage(
            iterations: iterations,
            isHexadecimal: sp == "s2k_fo"
        ) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        let verificationParameters: [String: Any] = [
            "c": c,
            "cpd": clientDictionary,
            "M1": verificationMessage,
            "o": "complete",
            "u": session.appleID
        ]

        let verificationResponse = try await sendGrandSlamRequest(
            url: gsServiceURL,
            parameters: verificationParameters,
            anisetteData: anisetteData
        )
        try checkGrandSlamError(verificationResponse)

        guard let serverVerificationMessage = verificationResponse["M2"] as? Data,
              let serverDictionary = verificationResponse["spd"] as? Data,
              let statusDictionary = verificationResponse["Status"] as? [String: Any]
        else {
            throw URLError(.badServerResponse)
        }

        guard context.verifyServerVerificationMessage(serverVerificationMessage) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        guard let decryptedData = serverDictionary.decryptedCBC(context: context) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        guard let decryptedDictionary = try PropertyListSerialization.propertyList(
            from: decryptedData,
            format: nil
        ) as? [String: Any],
              let dsid = decryptedDictionary["adsid"] as? String,
              let idmsToken = decryptedDictionary["GsIdmsToken"] as? String
        else {
            throw URLError(.badServerResponse)
        }

        context.dsid = dsid
        session.context = context
        session.spd = decryptedDictionary
        session.dsid = dsid
        session.idmsToken = idmsToken

        if let authType = statusDictionary["au"] as? String {
            switch authType {
            case "trustedDeviceSecondaryAuth":
                return .needsDevice2FA
            case "secondaryAuth":
                return .needsSMS2FA
            case "repair":
                // Just means that 2FA isn't set up on this account
                return .loggedIn
            default:
                let tokens = decryptedDictionary["t"] as? [String: Any]
                let pet = tokens?["com.apple.gs.idms.pet"] as? [String: Any]
                guard pet?["token"] is String else {
                    throw AppleAPIError.customError(code: -1, message: "Additional authentication required: \(authType)")
                }
                return .loggedIn
            }
        }

        // Apple now pushes the trusted-device prompt on its own during sign in and reports
        // it with hsc 409 and no "au". Treating that as signed in sends the apptokens request
        // before 2FA completes, which Apple rejects with -22411.
        if integerValue(statusDictionary["hsc"]) == 409 {
            await updateTrustedPhoneNumber(session)
            return .needsDevice2FAVerification
        }

        return .loggedIn
    }

    private static func finishLogin(_ session: LoginSession) async throws -> (Account, AppleAPISession) {
        guard let context = session.context,
              let sessionKey = session.spd["sk"] as? Data,
              let c = session.spd["c"] as? Data
        else {
            throw URLError(.badServerResponse)
        }

        context.sessionKey = sessionKey

        let app = "com.apple.gs.xcode.auth"
        guard let checksum = context.makeChecksum(appName: app) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        let anisetteData = try await session.currentAnisette()

        let tokenParameters: [String: Any] = [
            "app": [app],
            "c": c,
            "checksum": checksum,
            "cpd": clientProvidedData(anisetteData),
            "o": "apptokens",
            "t": session.idmsToken,
            "u": session.dsid
        ]

        let token = try await fetchAuthToken(
            app: app,
            parameters: tokenParameters,
            context: context,
            anisetteData: anisetteData,
            url: session.url("gsService", fallback: defaultGsServiceURL)
        )

        let apiSession = AppleAPISession(
            dsid: session.dsid,
            authToken: token,
            anisetteData: anisetteData
        )

        let account = try await AppleAPI.shared.fetchAccount(session: apiSession)
        return (account, apiSession)
    }

    private static func requestVerificationCode(_ verificationHandler: VerificationHandler?) async throws -> String {
        guard let verificationHandler = verificationHandler else {
            throw AppleAPIError.requiresTwoFactorAuthentication
        }

        let verificationCode: String? = await withCheckedContinuation { continuation in
            Task {
                await verificationHandler { code in
                    continuation.resume(returning: code)
                }
            }
        }

        guard let code = verificationCode else {
            throw AppleAPIError.requiresTwoFactorAuthentication
        }

        return code.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Trusted device 2FA

    private static func sendTrustedDeviceTwoFactorCode(_ session: LoginSession) async throws {
        await updateTrustedPhoneNumber(session)

        let anisetteData = try await session.currentAnisette()
        let request = makeTwoFactorCodeRequest(
            url: session.url("trustedDeviceSecondaryAuth", fallback: defaultTrustedDeviceURL),
            dsid: session.dsid,
            idmsToken: session.idmsToken,
            anisetteData: anisetteData
        )

        let (data, response) = try await AppleAPI.shared.session.data(for: request)
        try checkHTTPStatus(response, data: data, action: "Trusted device 2FA request")
    }

    private static func verifyTrustedDeviceTwoFactorCode(_ code: String, session: LoginSession) async throws -> LoginState {
        let anisetteData = try await session.currentAnisette()
        var request = makeTwoFactorCodeRequest(
            url: session.url("validateCode", fallback: defaultValidateCodeURL),
            dsid: session.dsid,
            idmsToken: session.idmsToken,
            anisetteData: anisetteData
        )
        request.setValue(code, forHTTPHeaderField: "security-code")

        let (data, response) = try await AppleAPI.shared.session.data(for: request)

        if let responseDictionary = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] {
            do {
                try checkGrandSlamError(responseDictionary)
            } catch AppleAPIError.customError(code: -21669, message: _) {
                // Incorrect verification code, let the user try again
                return .needsDevice2FAVerification
            }
        }

        try checkHTTPStatus(response, data: data, action: "Trusted device 2FA code submission")

        // Trusted device 2FA completed, need to login again
        return .needsLogin
    }

    // MARK: - SMS 2FA

    private static func updateTrustedPhoneNumber(_ session: LoginSession) async {
        guard !session.phoneNumbersFetched,
              let anisetteData = try? await session.currentAnisette()
        else {
            return
        }

        let request = makeTwoFactorCodeRequest(
            url: URL(string: "https://gsa.apple.com/auth")!,
            dsid: session.dsid,
            idmsToken: session.idmsToken,
            anisetteData: anisetteData,
            json: true
        )

        guard let result = try? await AppleAPI.shared.session.data(for: request),
              let json = (try? JSONSerialization.jsonObject(with: result.0)) as? [String: Any],
              let numbers = json["trustedPhoneNumbers"] as? [[String: Any]],
              let id = numbers.compactMap({ integerValue($0["id"]) }).first
        else {
            // Doesn't need to be fatal for users who have trusted devices
            return
        }

        session.phoneNumberID = id
        session.phoneNumbersFetched = true
    }

    private static func sendSMSTwoFactorCode(_ session: LoginSession) async throws -> LoginState {
        await updateTrustedPhoneNumber(session)

        let anisetteData = try await session.currentAnisette()
        var request = makeTwoFactorCodeRequest(
            url: URL(string: "https://gsa.apple.com/auth/verify/phone")!,
            dsid: session.dsid,
            idmsToken: session.idmsToken,
            anisetteData: anisetteData,
            json: true
        )
        request.httpMethod = "PUT"
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "phoneNumber": ["id": session.phoneNumberID],
            "mode": "sms"
        ] as [String: Any])

        let (data, response) = try await AppleAPI.shared.session.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0

        if (200..<300).contains(statusCode) {
            return .needsSMS2FAVerification
        }

        if let error = smsServiceError(data) {
            // Apple refused to send a new SMS, but the last code sent is still valid
            if error.code == "-22979" || error.code == "-22981" {
                return .needsSMS2FAVerification
            }
            throw AppleAPIError.customError(code: Int(error.code) ?? -1, message: "\(error.title) - \(error.message) (\(error.code))")
        }

        // 412 with an SMS verification challenge means a code is already active
        if statusCode == 412,
           let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           json["mode"] as? String == "sms" {
            return .needsSMS2FAVerification
        }

        throw AppleAPIError.customError(code: statusCode, message: "SMS 2FA request failed with HTTP status \(statusCode): \(String(data: data, encoding: .utf8) ?? "")")
    }

    private static func verifySMSTwoFactorCode(_ code: String, session: LoginSession) async throws -> LoginState {
        let anisetteData = try await session.currentAnisette()
        var request = makeTwoFactorCodeRequest(
            url: URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode")!,
            dsid: session.dsid,
            idmsToken: session.idmsToken,
            anisetteData: anisetteData,
            json: true
        )
        request.httpMethod = "POST"
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "securityCode": ["code": code],
            "phoneNumber": ["id": session.phoneNumberID],
            "mode": "sms"
        ] as [String: Any])

        let (data, response) = try await AppleAPI.shared.session.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0

        guard (200..<300).contains(statusCode) else {
            if let error = smsServiceError(data) {
                if error.code == "-21669" {
                    // Incorrect verification code, let the user try again
                    return .needsSMS2FAVerification
                }
                throw AppleAPIError.customError(code: Int(error.code) ?? -1, message: "\(error.title) - \(error.message) (\(error.code))")
            }
            throw AppleAPIError.customError(code: statusCode, message: "SMS 2FA code submission failed with HTTP status \(statusCode): \(String(data: data, encoding: .utf8) ?? "")")
        }

        // SMS 2FA completed, need to login again
        return .needsLogin
    }

    private static func smsServiceError(_ data: Data) -> (code: String, title: String, message: String)? {
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let errors = json["serviceErrors"] as? [[String: Any]],
              let first = errors.first
        else {
            return nil
        }

        let code = (first["code"] as? String) ?? integerValue(first["code"]).map { String($0) } ?? "unknown"
        return (
            code,
            first["title"] as? String ?? "No title provided",
            first["message"] as? String ?? "No message provided"
        )
    }

    // MARK: - GrandSlam requests

    static func grandSlamHeaders(clientInfo: String, json: Bool = false) -> [String: String] {
        [
            "Content-Type": json ? "application/json" : "text/x-xml-plist",
            "Accept": json ? "application/json" : "text/x-xml-plist",
            "X-Mme-Client-Info": clientInfo,
            "User-Agent": userAgent,
            "X-Xcode-Version": "27.0 (27A5218g)",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "Connection": "close"
        ]
    }

    static func clientProvidedData(_ anisetteData: AnisetteData) -> [String: Any] {
        [
            "bootstrap": "true",
            "icscrec": "true",
            "loc": "en_US",
            "pbe": "false",
            "prkgen": "true",
            "svct": "iCloud",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-M": anisetteData.machineID
        ]
    }

    public static func fetchURLBag() async throws -> [String: Any] {
        var request = URLRequest(url: urlBagURL)
        grandSlamHeaders(clientInfo: urlBagClientInfo).forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        let (data, _) = try await AppleAPI.shared.session.data(for: request)

        guard let dictionary = try PropertyListSerialization.propertyList(
            from: data,
            format: nil
        ) as? [String: Any],
              let urls = dictionary["urls"] as? [String: Any]
        else {
            throw URLError(.badServerResponse)
        }

        return urls
    }

    // Returns the "Response" dictionary without checking Status, so callers can look at
    // hsc (e.g. 434 resync) before treating ec as an error.
    static func sendGrandSlamRequest(
        url requestURL: URL,
        parameters requestParameters: [String: Any],
        anisetteData: AnisetteData
    ) async throws -> [String: Any] {
        let parameters: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": requestParameters
        ]

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.httpBody = try PropertyListSerialization.data(
            fromPropertyList: parameters,
            format: .xml,
            options: 0
        )
        grandSlamHeaders(clientInfo: anisetteData.deviceDescription).forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        var retries = maxRateLimitRetries
        while true {
            let (data, response) = try await AppleAPI.shared.session.data(for: request)

            if (response as? HTTPURLResponse)?.statusCode == 429 && retries > 0 {
                retries -= 1
                try await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }
            try checkHTTPStatus(response, data: data, action: "GrandSlam request")

            guard let responseDictionary = try PropertyListSerialization.propertyList(
                from: data,
                format: nil
            ) as? [String: Any],
                  let dictionary = responseDictionary["Response"] as? [String: Any]
            else {
                throw URLError(.badServerResponse)
            }

            return dictionary
        }
    }

    public static func sendAuthenticationRequest(
        parameters requestParameters: [String: Any],
        anisetteData: AnisetteData,
        url requestURL: URL = URL(string: defaultGsServiceURL)!
    ) async throws -> [String: Any] {
        let dictionary = try await sendGrandSlamRequest(
            url: requestURL,
            parameters: requestParameters,
            anisetteData: anisetteData
        )
        try checkGrandSlamError(dictionary)
        return dictionary
    }

    static func checkGrandSlamError(_ dictionary: [String: Any]) throws {
        let status = dictionary["Status"] as? [String: Any] ?? dictionary

        let errorCode = integerValue(status["ec"]) ?? 0
        guard errorCode == 0 else {
            switch errorCode {
            case -20101, -22406:
                throw AppleAPIError.incorrectCredentials
            case -22421:
                throw AppleAPIError.invalidAnisetteData
            case -20209:
                throw AppleAPIError.accountLocked
            default:
                let errorDescription = status["em"] as? String ?? "Unknown error"
                throw AppleAPIError.customError(code: errorCode, message: "\(errorDescription) (\(errorCode))")
            }
        }
    }

    static func checkHTTPStatus(_ response: URLResponse, data: Data, action: String) throws {
        guard let statusCode = (response as? HTTPURLResponse)?.statusCode,
              !(200..<300).contains(statusCode)
        else {
            return
        }

        let body = String(data: data, encoding: .utf8) ?? ""
        throw AppleAPIError.customError(code: statusCode, message: "\(action) failed with HTTP status \(statusCode) \(body)")
    }

    /// Base64 `X-Apple-I-MD-DATA` from a response demanding an anisette resync (`Status.hsc == 434`).
    static func resyncSIM(_ dictionary: [String: Any]) -> String? {
        guard let status = dictionary["Status"] as? [String: Any],
              integerValue(status["hsc"]) == 434
        else {
            return nil
        }

        switch status["X-Apple-I-MD-DATA"] {
        case let data as Data:
            return data.base64EncodedString()
        case let string as String:
            return string
        default:
            return nil
        }
    }

    static func integerValue(_ value: Any?) -> Int? {
        switch value {
        case let int as Int:
            return int
        case let number as NSNumber:
            return number.intValue
        case let string as String:
            return Int(string)
        default:
            return nil
        }
    }

    public static func makeTwoFactorCodeRequest(
        url: URL,
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData,
        json: Bool = false
    ) -> URLRequest {
        let identityToken = "\(dsid):\(idmsToken)"
        let encodedIdentityToken = identityToken.data(using: .utf8)?.base64EncodedString() ?? ""

        var httpHeaders = grandSlamHeaders(clientInfo: anisetteData.deviceDescription, json: json)
        httpHeaders["X-Mme-Device-Id"] = anisetteData.deviceUniqueIdentifier
        httpHeaders["X-Apple-I-MD"] = anisetteData.oneTimePassword
        httpHeaders["X-Apple-I-MD-M"] = anisetteData.machineID
        httpHeaders["X-Apple-Identity-Token"] = encodedIdentityToken
        httpHeaders["X-Apple-I-MD-RINFO"] = "\(anisetteData.routingInfo)"

        var request = URLRequest(url: url)
        httpHeaders.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        return request
    }

    public static func fetchAuthToken(
        app: String,
        parameters: [String: Any],
        context: GSAContext,
        anisetteData: AnisetteData,
        url: URL = URL(string: defaultGsServiceURL)!
    ) async throws -> String {
        let responseDictionary = try await sendAuthenticationRequest(
            parameters: parameters,
            anisetteData: anisetteData,
            url: url
        )

        guard let encryptedToken = responseDictionary["et"] as? Data else {
            throw URLError(.badServerResponse)
        }

        guard let token = encryptedToken.decryptedGCM(context: context) else {
            throw AppleAPIError.authenticationHandshakeFailed
        }

        guard let tokensDictionary = try PropertyListSerialization.propertyList(
            from: token,
            format: nil
        ) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }

        if let statusCode = integerValue(tokensDictionary["status-code"]), statusCode != 200 {
            throw AppleAPIError.customError(code: statusCode, message: "App token request failed with status code \(statusCode)")
        }

        guard let appTokens = tokensDictionary["t"] as? [String: Any],
              let tokens = appTokens[app] as? [String: Any],
              let authToken = tokens["token"] as? String
        else {
            throw URLError(.badServerResponse)
        }

        return authToken
    }
}
