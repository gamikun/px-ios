//
//  ESCManager.swift
//  MercadoPagoSDK
//
//  Created by Eden Torres on 5/23/17.
//  Copyright © 2017 MercadoPago. All rights reserved.
//

import Foundation
open class ESCManager: NSObject {

    static let keychainOptions = KeychainItemOptions(itemClass: .GenericPassword, itemAccessibility: .WhenPasscodeSetThisDeviceOnly)

    /// Returns a saved encrypted cvv.
    ///
    /// - Parameter cardId: The cardId to lookup data for.
    /// - Returns: The String associated with the cardId if it exists. If no data exists, returns an empty string.
    public static func getESC(cardId: String) -> String {
        if cardId != "" {
            return MPXKeychainWrapper.standardKeychainAccess().string(forKey: ESCManager.getKey(id: cardId), withOptions: ESCManager.keychainOptions) ?? ""
        }
        return ""
    }

    /// Return all cardIds that have an encrypted cvv associated with.
    ///
    /// - Returns: A list with all the card Ids saved
    public static func getSavedCardIds() -> [String] {

        guard var keys = MPXKeychainWrapper.standardKeychainAccess().keyStrings(withOptions: ESCManager.keychainOptions) else {
            return [""]
        }
        for (index, key) in keys.enumerated() {
            if let range = key.range(of: ESCManager.getKey(id: "")) {
                keys[index] = key.substring(from: range.upperBound)
            }
        }
        return  keys
    }

    /// Saves an encrypted cvv. If an empty string is passed as an esc, the data gets deleted.
    ///
    /// - Parameters:
    ///   - cardId: The key to save the encrypted cvv under.
    ///   - esc: The encrypted cvv value to save.
    /// - Returns: true if value could be saved.
    public static func saveESC(cardId: String, esc: String) -> Bool {
        if cardId != "" {
            if esc == "" {
                deleteESC(cardId: cardId)
            } else {
                MPXKeychainWrapper.standardKeychainAccess().setString(esc, forKey: ESCManager.getKey(id: cardId), withOptions: ESCManager.keychainOptions)
                return true
            }
        }
        return false
    }

    /// Deletes an encrypted cvv
    ///
    /// - Parameter cardId: The cardId value to remove data for.
    public static func deleteESC(cardId: String) {
        MPXKeychainWrapper.standardKeychainAccess().removeObject(forKey: ESCManager.getKey(id: cardId), withOptions: ESCManager.keychainOptions)
    }

    /// Deletes all encrypted cvv saved
    public static func deleteAllESC() {
        MPXKeychainWrapper.standardKeychainAccess().removeAllKeys()
    }

    public static func getKey(id: String) -> String {
        return "mp_card_id_\(id)"
    }
}
