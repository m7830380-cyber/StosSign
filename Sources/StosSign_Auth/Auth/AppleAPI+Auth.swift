//
//  AppleAPI+Authentication.swift
//  StosSign
//
//  Created by Stossy11 on 06/12/2025.
//

import Foundation
import StosSign_API
import StosSign_Common

extension AppleAPI {
    public func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        anisetteDataProvider: Authentication.AnisetteDataProvider? = nil,
        anisetteResyncHandler: Authentication.AnisetteResyncHandler? = nil,
        verificationHandler: Authentication.VerificationHandler? = nil
    ) async throws -> (Account, AppleAPISession) {
        try await Authentication.authenticate(
            appleID: unsanitizedAppleID,
            password: password,
            anisetteData: anisetteData,
            verificationHandler: verificationHandler,
            anisetteDataProvider: anisetteDataProvider,
            anisetteResyncHandler: anisetteResyncHandler
        )
    }
}
