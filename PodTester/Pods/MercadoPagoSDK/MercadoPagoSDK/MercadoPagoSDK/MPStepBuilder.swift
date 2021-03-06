//
//  MPStepBuilder.swift
//  MercadoPagoSDK
//
//  Created by Demian Tejo on 1/7/16.
//  Copyright © 2016 MercadoPago. All rights reserved.
//

import Foundation
import UIKit

open class MPStepBuilder: NSObject {

    @objc
    public enum CongratsState: Int {
        case ok = 0
        case cancel_SELECT_OTHER = 1
        case cancel_RETRY = 2
        case cancel_RECOVER = 3
        case call_FOR_AUTH = 4
    }

//    open class func startCustomerCardsStep(_ cards: [Card],
//                                           callback: @escaping (_ selectedCard: Card?) -> Void) -> CustomerCardsViewController {
//        
//        
//        MercadoPagoContext.initFlavor2()
//        return CustomerCardsViewController(cards: cards, callback: callback)
//    }
//    
//    open class func startNewCardStep(_ paymentMethod: PaymentMethod, requireSecurityCode: Bool = true,
//                                     
//                                     callback: @escaping (_ cardToken: CardToken) -> Void) -> NewCardViewController {
//        MercadoPagoContext.initFlavor2()
//        return NewCardViewController(paymentMethod: paymentMethod, requireSecurityCode: requireSecurityCode, callback: callback)
//        
//    }

    open class func startPromosStep(promos: [Promo]? = nil,
        _ callback: (() -> (Void))? = nil) -> PromoViewController {
        MercadoPagoContext.initFlavor2()
        return PromoViewController(promos : promos, callback : callback)
    }

    fileprivate class func verifyPaymentMethods(paymentMethods: [PaymentMethod], cardToken: CardToken, amount: Double, cardInformation: CardInformation?, callback: @escaping ((_ paymentMethod: PaymentMethod, _ token: Token?, _ issuer: Issuer?) -> Void), ccf: MercadoPagoUIViewController, callbackCancel: (() -> Void)?) -> Bool {
//        if paymentMethods.count == 2 {
//            if paymentMethods[0].paymentTypeId == PaymentTypeId.CREDIT_CARD.rawValue || paymentMethods[1].paymentTypeId == PaymentTypeId.CREDIT_CARD.rawValue {
//                if paymentMethods[0].paymentTypeId == PaymentTypeId.DEBIT_CARD.rawValue || paymentMethods[1].paymentTypeId == PaymentTypeId.DEBIT_CARD.rawValue{
//                    let creditDebitForm = startCreditDebitForm(paymentMethods, issuer: nil, token: cardToken, amount: amount, callback: { (selectedPaymentMethod) in
//                        self.getIssuers(selectedPaymentMethod as! PaymentMethod, cardToken: cardToken, customerCard: cardInformation, ccf: ccf, callback: callback, callbackCancel: callbackCancel)
//                    })
//                    creditDebitForm.callbackCancel = callbackCancel
//                    ccf.navigationController!.pushViewController(creditDebitForm, animated: false)
//                    return true
//                }
//            }
//        }
        return false
    }

    open class func startCreditCardForm(_ paymentSettings: PaymentPreference? = nil, amount: Double, cardInformation: CardInformation? = nil, paymentMethods: [PaymentMethod]? = nil, token: Token? = nil, callback : @escaping ((_ paymentMethod: PaymentMethod, _ token: Token?, _ issuer: Issuer?) -> Void), callbackCancel: (() -> Void)?) -> UINavigationController {
        MercadoPagoContext.initFlavor2()
        var navigation: UINavigationController?

        var ccf: CardFormViewController = CardFormViewController()

        //C4A

        ccf = CardFormViewController(paymentSettings : paymentSettings, amount: amount, token: token, cardInformation: cardInformation, paymentMethods : paymentMethods, callback : { (paymentMethod, cardToken) -> Void in

            if (token != nil) { // flujo token recuperable C4A
                MPServicesBuilder.cloneToken(token!, securityCode:(cardToken?.securityCode)!, baseURL: MercadoPagoCheckoutViewModel.servicePreference.getGatewayURL(), success: { (token) in
                    callback(paymentMethod[0], token, nil)
                    }, failure: { (_) in

                })
                return
            }

            if(paymentMethod[0].isIdentificationRequired()) {
                let identificationForm = MPStepBuilder.startIdentificationForm({ (identification) -> Void in
                    cardToken?.cardholder?.identification = identification

                    if !verifyPaymentMethods(paymentMethods: paymentMethod, cardToken: cardToken!, amount: amount, cardInformation: cardInformation, callback: callback, ccf: ccf, callbackCancel: callbackCancel) {
                        self.getIssuers(paymentMethod[0], cardToken: cardToken!, customerCard: cardInformation, ccf: ccf, callback: callback)
                    }

                    })

                identificationForm.callbackCancel = callbackCancel

                ccf.navigationController!.pushViewController(identificationForm, animated: false)

            } else {

                if !verifyPaymentMethods(paymentMethods: paymentMethod, cardToken: cardToken!, amount: amount, cardInformation: cardInformation, callback: callback, ccf: ccf, callbackCancel: callbackCancel) {
                    self.getIssuers(paymentMethod[0], cardToken: cardToken!, customerCard: cardInformation, ccf: ccf, callback: callback)
                }
            }
            }, callbackCancel: callbackCancel)

        navigation = MPFlowController.createNavigationControllerWith(ccf)

        return navigation!

    }

    open class func startCreditDebitForm(_ paymentMethod: [PaymentMethod], issuer: Issuer?, token: CardToken?, amount: Double, paymentPreference: PaymentPreference? = nil,
                                         callback : @escaping ((_ paymentMethod: NSObject?) -> Void),
                                         callbackCancel: (() -> Void)? = nil) -> UINavigationController {

//        MercadoPagoContext.initFlavor2()
//        return AdditionalStepViewController(paymentMethods: paymentMethod, issuer: issuer, token: token, amount: amount, paymentPreference: paymentPreference, installment : nil, callback: callback)
        return UINavigationController()
    }

    open class func startPayerCostForm(_ paymentMethod: PaymentMethod, issuer: Issuer?, token: Token?, amount: Double, paymentPreference: PaymentPreference? = nil, installment: Installment? = nil,
                                       callback : @escaping ((_ payerCost: PayerCost?) -> Void),
                                       callbackCancel: (() -> Void)? = nil) -> UINavigationController {

        MercadoPagoContext.initFlavor2()
//        let call : (_ payerCost: NSObject?) -> Void = {(payerCost: NSObject?) in
//            callback(payerCost as? PayerCost)
//        }
//        return AdditionalStepViewController(paymentMethods: [paymentMethod], issuer: issuer, token: token, amount: amount, paymentPreference: paymentPreference, installment: installment, callback: call)
        return UINavigationController()
    }

    public class func startPayerCostForm(cardInformation: CardInformation, amount: Double, paymentPreference: PaymentPreference? = nil, installment: Installment? = nil,
                                       callback : @escaping ((_ payerCost: NSObject?) -> Void),
                                       callbackCancel: (() -> Void)? = nil) -> UINavigationController {

//        MercadoPagoContext.initFlavor2()
//        return AdditionalStepViewController(cardInformation: cardInformation, amount: amount, paymentPreference: paymentPreference, installment: installment, callback: callback)
        return UINavigationController()
    }

    open class func startIdentificationForm(

        _ callback : @escaping ((_ identification: Identification?) -> Void)) -> IdentificationViewController {

        MercadoPagoContext.initFlavor2()
        return IdentificationViewController(callback: callback, errorExitCallback: nil)
    }

//    open class func startIssuersStep(_ paymentMethod: PaymentMethod,
//                                     callback: @escaping (_ issuer: Issuer) -> Void) -> IssuersViewController {
////        let call : (_ issuer: NSObject) -> Void = {(issuer: NSObject) in
////            callback(issuer as! Issuer)
////        }
////        MercadoPagoContext.initFlavor2()
////        return IssuersViewController(paymentMethod: paymentMethod, callback: call)
//        return IssuersViewController()
//    }
    open class func startIssuerForm(_ paymentMethod: PaymentMethod, cardToken: CardToken, issuerList: [Issuer]? = nil,
                                    callback : @escaping ((_ issuer: NSObject?) -> Void)) -> UINavigationController {

//        MercadoPagoContext.initFlavor2()
//        return AdditionalStepViewController(paymentMethods: [paymentMethod], issuer: nil, token: cardToken, amount: nil, paymentPreference: nil, installment : nil, callback: callback)
        return UINavigationController()

    }

    open class func startErrorViewController(_ error: MPSDKError,
                                             callback: (() -> Void)? = nil,
                                             callbackCancel: (() -> Void)? = nil) -> ErrorViewController {
        MercadoPagoContext.initFlavor2()
        return ErrorViewController(error: error, callback: callback, callbackCancel: callbackCancel)
    }

    open class func startDetailDiscountDetailStep(coupon: DiscountCoupon) -> CouponDetailViewController {
        MercadoPagoContext.initFlavor2()
        return CouponDetailViewController(coupon: coupon)
    }
    fileprivate class func getIssuers(_ paymentMethod: PaymentMethod, cardToken: CardToken, customerCard: CardInformation? = nil, ccf: MercadoPagoUIViewController,
                                      callback : @escaping (_ paymentMethod: PaymentMethod, _ token: Token, _ issuer: Issuer?) -> Void ,
                                      callbackCancel: (() -> Void)? = nil) {
//        MercadoPagoContext.initFlavor2()
//
//        
//        if !cardToken.isCustomerPaymentMethod() {
//            MPServicesBuilder.getIssuers(paymentMethod,bin: cardToken.getBin(), success: { (issuers) -> Void in
//
//                    if(issuers.count > 1){
//                        let issuerForm = MPStepBuilder.startIssuerForm(paymentMethod, cardToken: cardToken, issuerList: issuers, callback: { (issuer) -> Void in
//                            if let nav = ccf.navigationController {
//                                
//                            }
//                            
//                            self.createNewCardToken(cardToken, paymentMethod: paymentMethod, issuer: issuer as? Issuer, ccf : ccf, callback: callback, callbackCancel: callbackCancel)
//                        })
//                        issuerForm.callbackCancel = { Void -> Void in
//                            ccf.navigationController!.dismiss(animated: true, completion: {})
//                        }
//                        
//                    ccf.navigationController!.pushViewController(issuerForm, animated: false)
//                } else {
//                    self.createNewCardToken(cardToken, paymentMethod: paymentMethod, issuer: issuers[0], ccf: ccf, callback: callback, callbackCancel: callbackCancel)
//                }
//                }, failure: { (error) -> Void in
//                    if let nav = ccf.navigationController {
//                        nav.hideLoading()
//                    }
//                    
//                    let errorVC = MPStepBuilder.startErrorViewController(MPSDKError.convertFrom(error), callback: { (Void) in
//                        self.getIssuers(paymentMethod, cardToken: cardToken, ccf: ccf, callback: callback)
//                        }, callbackCancel: {
//                            ccf.navigationController?.dismiss(animated: true, completion: {})
//                    })
//                    ccf.navigationController?.present(errorVC, animated: true, completion: {})
//            })
//        } else {
//            self.createNewCardToken(cardToken, paymentMethod: paymentMethod, issuer: customerCard?.getIssuer(), customerCard: customerCard, ccf: ccf, callback: callback, callbackCancel: callbackCancel)
//        }
    }

}
