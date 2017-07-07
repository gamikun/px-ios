//
//  TrackingUtil.swift
//  MercadoPagoSDK
//
//  Created by Eden Torres on 7/7/17.
//  Copyright © 2017 MercadoPago. All rights reserved.
//

import Foundation

open class TackingUtil: NSObject {

    //Screen IDs
    open static let SCREEN_ID_CHECKOUT = "/checkout_off/init"
    open static let SCREEN_ID_PAYMENT_VAULT = "/checkout_off/payment_option"
    open static let SCREEN_ID_REVIEW_AND_CONFIRM = "/checkout_off/review"
    open static let SCREEN_ID_PAYMENT_RESULT_APPROVED = "/checkout_off/congrats/approved"
    open static let SCREEN_ID_PAYMENT_RESULT_PENDING = "/checkout_off/congrats/pending"
    open static let SCREEN_ID_PAYMENT_RESULT_REJECTED = "/checkout_off/congrats/rejected"
    open static let SCREEN_ID_PAYMENT_RESULT_INSTRUCTIONS = "/checkout_off/congrats/instructions"
    open static let SCREEN_ID_BANK_DEALS = "/checkout_off/bank_deals"
    open static let SCREEN_ID_CARD_FORM = "/checkout_off/card/"
    open static let SCREEN_ID_ERROR = "/checkout_off/failure"
    open static let SCREEN_ID_PAYMENT_TYPES = "/checkout_off/card/payment_types"

    //Screen Names
    open static let SCREEN_NAME_CHECKOUT = "Init checkout"
    open static let SCREEN_NAME_PAYMENT_VAULT = "PAYMENT_METHOD_SEARCH"
    open static let SCREEN_NAME_REVIEW_AND_CONFIRM = "REVIEW_AND_CONFIRM"
    open static let SCREEN_NAME_PAYMENT_RESULT_APPROVED = "RESULT"
    open static let SCREEN_NAME_PAYMENT_RESULT_PENDING = "RESULT"
    open static let SCREEN_NAME_PAYMENT_RESULT_REJECTED = "RESULT"
    open static let SCREEN_NAME_PAYMENT_RESULT_CALL_FOR_AUTH = "CALL_FOR_AUTHORIZE"
    open static let SCREEN_NAME_PAYMENT_RESULT_INSTRUCTIONS = "INSTRUCTIONS"
    open static let SCREEN_NAME_BANK_DEALS = "BANK_DEALS"
    open static let SCREEN_NAME_CARD_FORM = "CARD_VAULT"
    open static let SCREEN_NAME_CARD_FORM_NUMBER = "CARD_NUMBER"
    open static let SCREEN_NAME_CARD_FORM_NAME = "CARD_HOLDER_NAME"
    open static let SCREEN_NAME_CARD_FORM_EXPIRY = "CARD_EXPIRY_DATE"
    open static let SCREEN_NAME_CARD_FORM_CVV = "CARD_SECURITY_CODE"
    open static let SCREEN_NAME_CARD_FORM_IDENTIFICATION_NUMBER = "IDENTIFICATION_NUMBER"
    open static let SCREEN_NAME_CARD_FORM_ISSUERS = "CARD_ISSUERS"
    open static let SCREEN_NAME_CARD_FORM_INSTALLMENTS = "CARD_INSTALLMENTS"
    open static let SCREEN_NAME_ERROR = "Error View"
    open static let SCREEN_NAME_PAYMENT_TYPES = "CARD_PAYMENT_TYPES"
    open static let SCREEN_NAME_SECURITY_CODE = "SECURITY_CODE_CARD"

    //Sufix
    open static let CARD_NUMBER = "/number"
    open static let CARD_HOLDER_NAME = "/name"
    open static let CARD_EXPIRATION_DATE = "/expiration"
    open static let CARD_SECURITY_CODE = "/cvv"
    open static let CARD_IDENTIFICATION = "/identification"
    open static let CARD_ISSUER = "/issuer"
    open static let CARD_INSTALLMENTS = "/installments"
    open static let CARD_SECURITY_CODE_VIEW = "/security_code"

    //Additional Info Keys
    open static let ADDITIONAL_PAYMENT_METHOD_ID = "payment_method"
    open static let ADDITIONAL_PAYMENT_TYPE_ID = "payment_type"
    open static let ADDITIONAL_ISSUER_ID = "issuer"
    open static let ADDITIONAL_SHIPPING_INFO = "has_shipping"
    open static let ADDITIONAL_PAYMENT_STATUS = "payment_status"
    open static let ADDITIONAL_PAYMENT_ID = "payment_id"
    open static let ADDITIONAL_PAYMENT_STATUS_DETAIL = "payment_status_detail"
    open static let ADDITIONAL_PAYMENT_IS_EXPRESS = "is_express"
    open static let ADDITIONAL_MERCADO_PAGO_ERROR = "mercado_pago_error"

    //Default values
    open static let HAS_SHIPPING_DEFAULT_VALUE = "false"
    open static let IS_EXPRESS_DEFAULT_VALUE = "false"

}
