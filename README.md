#  CloudKeychainManager

Thread-safe Keychain manager for storing secrets across apps using iCloud Keychain. Make sure to add the `keychain-access-groups` with `$(AppIdentifierPrefix)com.example.App-Name` to your Capabilities in Xcode to allows your application to share secrets from its keychain with other applications made by your team.
