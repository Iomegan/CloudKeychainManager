#  CloudKeychainManager

Thread-safe Keychain manager for storing secrets across apps using iCloud Keychain. Make sure to add the `keychain-access-groups` with `$(AppIdentifierPrefix)com.example.App-Name` to your Capabilities in Xcode to allows your application to share secrets from its keychain with other applications made by your team.

Initalize with `CloudKeychainManager.initializeShared(keychainGroup: "XYZ123456Z.com.example.App-Name", loggingSubsystem: "com.example.App-Name")` before using the shared instance.


`$(AppIdentifierPrefix)` is usually your Team ID. You can find your team details in the Membership tab of the Apple Developer portal at <https://developer.apple.com./>
