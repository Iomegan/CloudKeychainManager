//
//  KeychainManager.swift
//  Rocket Typist
//
//  Created by Daniel Witt on 07.08.24.
//

import Foundation
import os.log

/// Thread-safe Keychain manager for storing secrets across apps and iCloud Keychain
public actor CloudKeychainManager {
    // MARK: - Properties
    
    nonisolated let logger: Logger
    static let shared = CloudKeychainManager()
    
    /// Example: "XYZ123456Z.com.example.com.App-Name"
    var keychainGroup: String?
    
    /// Example: "com.example.com.App-Name"
    var subsystem: String?
    
    // MARK: - Init
    
    init() {
        logger = Logger(subsystem: subsystem ?? "com.example.com.App-Name", category: "security")
    }
    
    // MARK: - Store
    
    func store(_ key: String, account: String, name: String) -> Bool {
        guard let keychainGroup else {
            logger.error("Error #4hhrwf - no keychainGroup has been set")
            return false
        }
        
        guard let keyData = key.data(using: .utf8) else { return false }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: name,
            kSecAttrAccessGroup as String: keychainGroup,
            kSecAttrSynchronizable as String: kCFBooleanTrue!
        ]
        
        // Check if the item exists
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            // Update existing item
            let attributesToUpdate: [String: Any] = [kSecValueData as String: keyData]
            let updateStatus = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
            if updateStatus != errSecSuccess {
                logger.error("Error updating key in keychain: \(updateStatus)")
            }
            return updateStatus == errSecSuccess
        } else if status == errSecItemNotFound {
            // Add new item
            var addQuery = query
            addQuery[kSecValueData as String] = keyData
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                logger.error("Error adding key to keychain: \(addStatus)")
            }
            return addStatus == errSecSuccess
        } else {
            logger.error("Error searching for key in keychain: \(status)")
            return false
        }
    }
    
    // MARK: - Retrieve
    
    func retrieve(account: String) -> String? {
        guard let keychainGroup else {
            logger.error("Error #hjktr - no keychainGroup has been set")
            return nil
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrAccessGroup as String: keychainGroup,
            kSecAttrSynchronizable as String: kCFBooleanTrue!
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status != errSecSuccess {
            if status == errSecItemNotFound {
#if DEBUG
                print("Key not found in keychain")
#endif
            } else {
#if DEBUG
                print("Error retrieving key from keychain: \(status)")
#endif
            }
            return nil
        }
        
        guard let stringData = item as? Data else { return nil }
        return String(data: stringData, encoding: .utf8)
    }
    
    // MARK: - Delete
    
    func delete(account: String, name: String) -> Bool {
        guard let keychainGroup else {
            logger.error("Error #r8fkb - no keychainGroup has been set")
            return false
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: name,
            kSecAttrAccessGroup as String: keychainGroup,
            kSecAttrSynchronizable as String: kCFBooleanTrue!
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess {
            print("Key successfully deleted from keychain")
            return true
        } else if status == errSecItemNotFound {
            logger.error("Deleting key failed because the key was not found in keychain")
        } else {
            logger.error("Error deleting key from keychain: \(status)")
        }
        return false
    }
}
