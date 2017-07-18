//
//  KeychainWrapper.swift
//  KeychainWrapper
//
//  Created by Jason Rendel on 9/23/14.
//  Copyright (c) 2014 Jason Rendel. All rights reserved.
//
//    The MIT License (MIT)
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE.

import Foundation

private let SecMatchLimit: String! = kSecMatchLimit as String
private let SecReturnData: String! = kSecReturnData as String
private let SecReturnAtributtes: String! = kSecReturnAttributes as String
private let SecReturnPersistentRef: String! = kSecReturnPersistentRef as String
private let SecValueData: String! = kSecValueData as String
private let SecAttrAccessible: String! = kSecAttrAccessible as String
private let SecClass: String! = kSecClass as String
private let SecAttrService: String! = kSecAttrService as String
private let SecAttrGeneric: String! = kSecAttrGeneric as String
private let SecAttrAccount: String! = kSecAttrAccount as String
private let SecAttrAccessGroup: String! = kSecAttrAccessGroup as String

private let sharedKeychainWrapper = MPXKeychainWrapper()

/// KeychainWrapper is a class to help make Keychain access in Swift more straightforward. It is designed to make accessing the Keychain services more like using NSUserDefaults, which is much more familiar to people.
public class MPXKeychainWrapper {

    /// ServiceName is used for the kSecAttrService property to uniquely identify this keychain accessor. If no service name is specified, KeychainWrapper will default to using the bundleIdentifier.
    fileprivate (set) public var serviceName: String

    /// AccessGroup is used for the kSecAttrAccessGroup property to identify which Keychain Access Group this entry belongs to. This allows you to use the KeychainWrapper with shared keychain access between different applications.
    fileprivate (set) public var accessGroup: String?

    private static let defaultServiceName: String = {
        let bundle = Bundle.main.bundleIdentifier == nil ? "ESCManager" : Bundle.main.bundleIdentifier! + "ESCManager"
        return (bundle)
    }()

    fileprivate convenience init() {
        self.init(serviceName: MPXKeychainWrapper.defaultServiceName)
    }

    /// Create a custom instance of KeychainWrapper with a custom Service Name and optional custom access group.
    ///
    /// - parameter serviceName: The ServiceName for this instance. Used to uniquely identify all keys stored using this keychain wrapper instance.
    /// - parameter accessGroup: Optional unique AccessGroup for this instance. Use a matching AccessGroup between applications to allow shared keychain access.
    public init(serviceName: String, accessGroup: String? = nil) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }

    /// Standard access keychain
    public class func standardKeychainAccess() -> MPXKeychainWrapper {
        return sharedKeychainWrapper
    }


    /// Returns a string value for a specified key.
    ///
    /// - parameter keyName: The key to lookup data for.
    /// - parameter withOptions: Optional KeychainItemOptions to use when retrieving the keychain item.
    /// - returns: The String associated with the key if it exists. If no data exists, or the data found cannot be encoded as a string, returns nil.
    public func string(forKey keyName: String, withOptions options: KeychainItemOptions? = nil) -> String? {
        guard let keychainData = self.data(forKey: keyName, withOptions: options) else {
            return nil
        }

        return String(data: keychainData as Data, encoding: .utf8) as String?
    }

    /// Returns keys saved with the specified options.
    ///
    /// - parameter keyName: The key to lookup data for.
    /// - parameter withOptions: Optional KeychainItemOptions to use when retrieving the keychain item.
    /// - returns: A list with all the keys saved. If no data exists, or the data found cannot be encoded as a string, returns nil.
    public func keyStrings(withOptions options: KeychainItemOptions? = nil) -> [String]? {
        guard let keychainData = self.data(withOptions: options) else {
            return nil
        }

        var array: [String] = []

        for data in keychainData {
            guard let dic = data as? NSDictionary else {
                break
            }

            guard let data =  dic[SecAttrAccount] as? Data else {
                break
            }

            if let key = String(data: data, encoding: .utf8) as String? {
                array.append(key)
            }
        }
        return array
    }


    /// Returns a Data object for a specified key.
    ///
    /// - parameter keyName: The key to lookup data for.
    /// - parameter withOptions: Optional KeychainItemOptions to use when retrieving the keychain item.
    /// - returns: The Data object associated with the key if it exists. If no data exists, returns nil.
    public func data(forKey keyName: String, withOptions options: KeychainItemOptions? = nil) -> Data? {
        var keychainQueryDictionary = self.setupKeychainQueryDictionary(forKey: keyName, withOptions: options)
        var result: AnyObject?

        // Limit search results to one
        keychainQueryDictionary[SecMatchLimit] = kSecMatchLimitOne

        // Specify we want Data/CFData returned
        keychainQueryDictionary[SecReturnData] = kCFBooleanTrue

        // Search
        let status = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(keychainQueryDictionary as CFDictionary, UnsafeMutablePointer($0))
        }

        return status == noErr ? result as? Data : nil
    }

    public func data(withOptions options: KeychainItemOptions? = nil) -> NSArray? {
        var keychainQueryDictionary = self.setupKeychainQueryDictionary(withOptions: options)
        var result: AnyObject?

        // Limit search results to one
        keychainQueryDictionary[SecMatchLimit] = kSecMatchLimitAll

        // Specify we want Data/CFData returned
        //keychainQueryDictionary[SecReturnData] = kCFBooleanTrue
        keychainQueryDictionary[SecReturnAtributtes] = kCFBooleanTrue
        keychainQueryDictionary[SecClass] = kSecClassGenericPassword

        // Search
        let status = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(keychainQueryDictionary as CFDictionary, UnsafeMutablePointer($0))
        }

        return status == noErr ? result as? NSArray : nil
    }


    // MARK: Public Setters

    /// Save a String value to the keychain associated with a specified key. If a String value already exists for the given keyname, the string will be overwritten with the new value.
    ///
    /// - parameter value: The String value to save.
    /// - parameter forKey: The key to save the String under.
    /// - parameter withOptions: Optional KeychainItemOptions to use when setting the keychain item.
    /// - returns: True if the save was successful, false otherwise.
    @discardableResult public func setString(_ value: String, forKey keyName: String, withOptions options: KeychainItemOptions? = nil) -> Bool {
        if let data = value.data(using: .utf8) {
            return self.setData(data as Data, forKey: keyName, withOptions: options)
        } else {
            return false
        }
    }


    /// Save a Data object to the keychain associated with a specified key. If data already exists for the given keyname, the data will be overwritten with the new value.
    ///
    /// - parameter value: The Data object to save.
    /// - parameter forKey: The key to save the object under.
    /// - parameter withOptions: Optional KeychainItemOptions to use when setting the keychain item.
    /// - returns: True if the save was successful, false otherwise.
    @discardableResult public func setData(_ value: Data, forKey keyName: String, withOptions options: KeychainItemOptions? = nil) -> Bool {
        var keychainQueryDictionary: [String:Any] = self.setupKeychainQueryDictionary(forKey: keyName, withOptions: options)

        keychainQueryDictionary[SecValueData] = value

        let status: OSStatus = SecItemAdd(keychainQueryDictionary as CFDictionary, nil)

        if status == errSecSuccess {
            return true
        } else if status == errSecDuplicateItem {
            return self.updateData(value, forKey: keyName, withOptions: options)
        } else {
            return false
        }
    }

    /// Remove an object associated with a specified key.
    ///
    /// - parameter keyName: The key value to remove data for.
    /// - parameter withOptions: Optional KeychainItemOptions to use when looking up the keychain item.
    /// - returns: True if successful, false otherwise.
    @discardableResult public func removeObject(forKey keyName: String, withOptions options: KeychainItemOptions? = nil) -> Bool {
        let keychainQueryDictionary: [String:Any] = self.setupKeychainQueryDictionary(forKey: keyName, withOptions: options)

        // Delete
        let status: OSStatus = SecItemDelete(keychainQueryDictionary as CFDictionary)

        if status == errSecSuccess {
            return true
        } else {
            return false
        }
    }

    /// Remove all keychain data added through KeychainWrapper. This will only delete items matching the currnt ServiceName and AccessGroup if one is set.
    public func removeAllKeys() -> Bool {
        //let keychainQueryDictionary = self.setupKeychainQueryDictionary(forKey: keyName)

        //        // Setup dictionary to access keychain and specify we are using a generic password (rather than a certificate, internet password, etc)
        var keychainQueryDictionary: [String:Any] = [SecClass: kSecClassGenericPassword]

        // Uniquely identify this keychain accessor
        keychainQueryDictionary[SecAttrService] = self.serviceName

        // Set the keychain access group if defined
        if let accessGroup = self.accessGroup {
            keychainQueryDictionary[SecAttrAccessGroup] = accessGroup
        }

        let status: OSStatus = SecItemDelete(keychainQueryDictionary as CFDictionary)

        if status == errSecSuccess {
            return true
        } else {
            return false
        }
    }

    /// Update existing data associated with a specified key name. The existing data will be overwritten by the new data
    private func updateData(_ value: Data, forKey keyName: String, withOptions options: KeychainItemOptions? = nil) -> Bool {
        let keychainQueryDictionary: [String:Any] = self.setupKeychainQueryDictionary(forKey: keyName, withOptions: options)
        let updateDictionary = [SecValueData: value]

        // Update
        let status: OSStatus = SecItemUpdate(keychainQueryDictionary as CFDictionary, updateDictionary as CFDictionary)

        if status == errSecSuccess {
            return true
        } else {
            return false
        }
    }

    /// Setup the keychain query dictionary used to access the keychain on iOS for a specified key name. Takes into account the Service Name and Access Group if one is set.
    ///
    /// - parameter keyName: The key this query is for
    /// - parameter withOptions: The KeychainItemOptions to use when setting the keychain item.
    /// - returns: A dictionary with all the needed properties setup to access the keychain on iOS
    private func setupKeychainQueryDictionary(forKey keyName: String? = nil, withOptions options: KeychainItemOptions? = nil) -> [String:Any] {
        var keychainQueryDictionary = [String: Any]()

        if let options = options {
            keychainQueryDictionary[SecClass] = options.itemClass.keychainAttrValue
            keychainQueryDictionary[SecAttrAccessible] = options.itemAccessibility.keychainAttrValue
        } else {
            // Setup default access as generic password (rather than a certificate, internet password, etc)
            keychainQueryDictionary[SecClass] = KeychainItemClass.GenericPassword.keychainAttrValue

            // Protect the keychain entry so it's only valid when the device is unlocked
            keychainQueryDictionary[SecAttrAccessible] = KeychainItemAccessibility.WhenUnlocked.keychainAttrValue
        }

        // Uniquely identify this keychain accessor
        keychainQueryDictionary[SecAttrService] = self.serviceName

        // Set the keychain access group if defined
        if let accessGroup = self.accessGroup {
            keychainQueryDictionary[SecAttrAccessGroup] = accessGroup
        }

        // Uniquely identify the account who will be accessing the keychain
        if let key = keyName {
            let encodedIdentifier = key.data(using: .utf8)

            keychainQueryDictionary[SecAttrGeneric] = encodedIdentifier

            keychainQueryDictionary[SecAttrAccount] = encodedIdentifier
        }

        return keychainQueryDictionary
    }
}
public struct KeychainItemOptions {
    let itemClass: KeychainItemClass
    let itemAccessibility: KeychainItemAccessibility

    init(itemClass: KeychainItemClass = .GenericPassword,
         itemAccessibility: KeychainItemAccessibility = .WhenUnlocked) {
        self.itemClass = itemClass
        self.itemAccessibility = itemAccessibility
    }
}

protocol KeychainAttrRepresentable {
    var keychainAttrValue: CFString { get }
}

// MARK: - KeychainItemClass

/**
 Item class code of a Keychain item.
 */
public enum KeychainItemClass {
    /**
     Generic password item.

     The following attribute types (Attribute Item Keys and Values) can be used with an item of this type:
     - kSecAttrAccessible
     - kSecAttrAccessGroup
     - kSecAttrCreationDate
     - kSecAttrModificationDate
     - kSecAttrDescription
     - kSecAttrComment
     - kSecAttrCreator
     - kSecAttrType
     - kSecAttrLabel
     - kSecAttrIsInvisible
     - kSecAttrIsNegative
     - kSecAttrAccount
     - kSecAttrService
     - kSecAttrGeneric
     */
    @available(iOS 2, *)
    case GenericPassword

    /**
     Internet password item.

     The following attribute types (Attribute Item Keys and Values) can be used with an item of this type:
     - kSecAttrAccessible
     - kSecAttrAccessGroup
     - kSecAttrCreationDate
     - kSecAttrModificationDate
     - kSecAttrDescription
     - kSecAttrComment
     - kSecAttrCreator
     - kSecAttrType
     - kSecAttrLabel
     - kSecAttrIsInvisible
     - kSecAttrIsNegative
     - kSecAttrAccount
     - kSecAttrSecurityDomain
     - kSecAttrServer
     - kSecAttrProtocol
     - kSecAttrAuthenticationType
     - kSecAttrPort
     - kSecAttrPath
     */
    @available(iOS 2, *)
    case InternetPassword

    /**
     Certificate item.

     The following attribute types (Attribute Item Keys and Values) can be used with an item of this type:
     - kSecAttrAccessible
     - kSecAttrAccessGroup
     - kSecAttrCertificateType
     - kSecAttrCertificateEncoding
     - kSecAttrLabel
     - kSecAttrSubject
     - kSecAttrIssuer
     - kSecAttrSerialNumber
     - kSecAttrSubjectKeyID
     - kSecAttrPublicKeyHash
     */
    @available(iOS 2, *)
    case Certificate

    /**
     Cryptographic key item.

     The following attribute types (Attribute Item Keys and Values) can be used with an item of this type:
     - kSecAttrAccessible
     - kSecAttrAccessGroup
     - kSecAttrKeyClass
     - kSecAttrLabel
     - kSecAttrApplicationLabel
     - kSecAttrIsPermanent
     - kSecAttrApplicationTag
     - kSecAttrKeyType
     - kSecAttrKeySizeInBits
     - kSecAttrEffectiveKeySize
     - kSecAttrCanEncrypt
     - kSecAttrCanDecrypt
     - kSecAttrCanDerive
     - kSecAttrCanSign
     - kSecAttrCanVerify
     - kSecAttrCanWrap
     - kSecAttrCanUnwrap
     */
    @available(iOS 2, *)
    case Key

    /**
     An identity is a certificate together with its associated private key. Because an identity is the combination of a private key and a certificate, this class shares attributes of both kSecClassKey and kSecClassCertificate.
     */
    @available(iOS 2, *)
    case Identity
}

private let keychainItemClassLookup: [KeychainItemClass:CFString] = [
    .GenericPassword: kSecClassGenericPassword,
    .InternetPassword: kSecClassInternetPassword,
    .Certificate: kSecClassCertificate,
    .Key: kSecClassKey,
    .Identity: kSecClassIdentity
]

extension KeychainItemClass : KeychainAttrRepresentable {
    internal var keychainAttrValue: CFString {
        return keychainItemClassLookup[self]!
    }
}

// MARK: - KeychainItemAccessibility
public enum KeychainItemAccessibility {
    /**
     The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.

     After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to be accessed by background applications. Items with this attribute migrate to a new device when using encrypted backups.
     */
    @available(iOS 4, *)
    case AfterFirstUnlock

    /**
     The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user.

     After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to be accessed by background applications. Items with this attribute do not migrate to a new device. Thus, after restoring from a backup of a different device, these items will not be present.
     */
    @available(iOS 4, *)
    case AfterFirstUnlockThisDeviceOnly

    /**
     The data in the keychain item can always be accessed regardless of whether the device is locked.

     This is not recommended for application use. Items with this attribute migrate to a new device when using encrypted backups.
     */
    @available(iOS 4, *)
    case Always

    /**
     The data in the keychain can only be accessed when the device is unlocked. Only available if a passcode is set on the device.

     This is recommended for items that only need to be accessible while the application is in the foreground. Items with this attribute never migrate to a new device. After a backup is restored to a new device, these items are missing. No items can be stored in this class on devices without a passcode. Disabling the device passcode causes all items in this class to be deleted.
     */
    @available(iOS 8, *)
    case WhenPasscodeSetThisDeviceOnly

    /**
     The data in the keychain item can always be accessed regardless of whether the device is locked.

     This is not recommended for application use. Items with this attribute do not migrate to a new device. Thus, after restoring from a backup of a different device, these items will not be present.
     */
    @available(iOS 4, *)
    case AlwaysThisDeviceOnly

    /**
     The data in the keychain item can be accessed only while the device is unlocked by the user.

     This is recommended for items that need to be accessible only while the application is in the foreground. Items with this attribute migrate to a new device when using encrypted backups.

     This is the default value for keychain items added without explicitly setting an accessibility constant.
     */
    @available(iOS 4, *)
    case WhenUnlocked

    /**
     The data in the keychain item can be accessed only while the device is unlocked by the user.

     This is recommended for items that need to be accessible only while the application is in the foreground. Items with this attribute do not migrate to a new device. Thus, after restoring from a backup of a different device, these items will not be present.
     */
    @available(iOS 4, *)
    case WhenUnlockedThisDeviceOnly
}

private let keychainItemAccessibilityLookup: [KeychainItemAccessibility:CFString] = {
    var lookup: [KeychainItemAccessibility:CFString] = [
        .AfterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock,
        .AfterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        .Always: kSecAttrAccessibleAlways,
        .AlwaysThisDeviceOnly: kSecAttrAccessibleAlwaysThisDeviceOnly,
        .WhenUnlocked: kSecAttrAccessibleWhenUnlocked,
        .WhenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    
    lookup[.WhenPasscodeSetThisDeviceOnly] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    
    return lookup
}()

extension KeychainItemAccessibility : KeychainAttrRepresentable {
    internal var keychainAttrValue: CFString {
        return keychainItemAccessibilityLookup[self]!
    }
}

