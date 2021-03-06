//
//  AdditionalStepViewModel.swift
//  MercadoPagoSDK
//
//  Created by AUGUSTO COLLERONE ALFONSO on 3/3/17.
//  Copyright © 2017 MercadoPago. All rights reserved.
//

import Foundation
import UIKit

open class AdditionalStepViewModel: NSObject {

    var bundle: Bundle? = MercadoPago.getBundle()
    open var discount: DiscountCoupon?
    public var screenName: String
    public var screenTitle: String
    open var amount: Double
    open var token: CardInformationForm?
    open var paymentMethods: [PaymentMethod]
    open var cardSectionView: Updatable?
    open var cardSectionVisible: Bool
    open var totalRowVisible: Bool
    open var dataSource: [Cellable]
    open var defaultTitleCellHeight: CGFloat = 70
    open var defaultRowCellHeight: CGFloat = 80
    open var callback: ((_ result: NSObject?) -> Void)?

    init(screenName: String, screenTitle: String, cardSectionVisible: Bool, cardSectionView: Updatable? = nil, totalRowVisible: Bool, amount: Double, token: CardInformationForm?, paymentMethods: [PaymentMethod], dataSource: [Cellable] ) {
        self.screenName = screenName
        self.screenTitle = screenTitle
        self.amount = amount
        self.token = token
        self.paymentMethods = paymentMethods
        self.cardSectionVisible = cardSectionVisible
        self.cardSectionView = cardSectionView
        self.totalRowVisible = totalRowVisible
        self.dataSource = dataSource
    }

    func showCardSection() -> Bool {
        return cardSectionVisible
    }

    func showDiscountSection() -> Bool {
        return false
    }

    func showTotalRow() -> Bool {
        return totalRowVisible
    }

    func showAmountDetailRow() -> Bool {
        return showTotalRow() || showDiscountSection()
    }

    func getScreenName() -> String {
        return screenName
    }

    func getTitle() -> String {
        return screenTitle
    }

    func numberOfCellsInBody() -> Int {
        if self.showAmountDetailRow() {
            return dataSource.count + 1
        } else {
            return dataSource.count
        }

    }

    func getCardSectionView() -> Updatable? {
        return cardSectionView
    }

    func getTitleCellHeight() -> CGFloat {
        return defaultTitleCellHeight
    }

    func getCardSectionCellHeight() -> CGFloat {
        return UIScreen.main.bounds.width*0.50
    }

    func getBodyCellHeight(row: Int) -> CGFloat {
        if showTotalRow() || showDiscountSection() {
            if row == 0 {
                if showDiscountSection() {
                  return 84
                } else {
                   return 42
                }
            } else {
                return 60
            }
        } else {
            return defaultRowCellHeight
        }
    }
}

class IssuerAdditionalStepViewModel: AdditionalStepViewModel {

    let cardViewRect = CGRect(x: 0, y: 0, width: 100, height: 30)

    init(amount: Double, token: CardInformationForm?, paymentMethods: [PaymentMethod], dataSource: [Cellable] ) {
        super.init(screenName: "ISSUER", screenTitle: "¿Quién emitió tu tarjeta?".localized, cardSectionVisible: true, cardSectionView: CardFrontView(frame: self.cardViewRect), totalRowVisible: false, amount: amount, token: token, paymentMethods: paymentMethods, dataSource: dataSource)
        self.screenName = screenName
        self.screenTitle = screenTitle
        self.amount = amount
        self.token = token
        self.paymentMethods = paymentMethods
        self.cardSectionVisible = cardSectionVisible
        self.cardSectionView = cardSectionView
        self.totalRowVisible = totalRowVisible
        self.dataSource = dataSource
    }

}

class PayerCostAdditionalStepViewModel: AdditionalStepViewModel {

    let cardViewRect = CGRect(x: 0, y: 0, width: 100, height: 30)

    init(amount: Double, token: CardInformationForm?, paymentMethods: [PaymentMethod], dataSource: [Cellable], discount: DiscountCoupon? = nil ) {
        super.init(screenName: "PAYER_COST", screenTitle: "¿En cuántas cuotas?".localized, cardSectionVisible: true, cardSectionView: CardFrontView(frame: self.cardViewRect), totalRowVisible: true, amount: amount, token: token, paymentMethods: paymentMethods, dataSource: dataSource)
        self.screenName = screenName
        self.screenTitle = screenTitle
        self.amount = amount
        self.token = token
        self.discount = discount
        self.paymentMethods = paymentMethods
        self.cardSectionVisible = cardSectionVisible
        self.cardSectionView = cardSectionView
        self.totalRowVisible = totalRowVisible
        self.dataSource = dataSource
    }
     override func showDiscountSection() -> Bool {
        return (discount != nil)
    }

}

class CardTypeAdditionalStepViewModel: AdditionalStepViewModel {

    let cardViewRect = CGRect(x: 0, y: 0, width: 100, height: 30)

    init(amount: Double, token: CardInformationForm?, paymentMethods: [PaymentMethod], dataSource: [Cellable] ) {
        super.init(screenName: "CARD_TYPE", screenTitle: "¿Qué tipo de tarjeta es?".localized, cardSectionVisible: true, cardSectionView:CardFrontView(frame: self.cardViewRect), totalRowVisible: false, amount: amount, token: token, paymentMethods: paymentMethods, dataSource: dataSource)
        self.screenName = screenName
        self.screenTitle = screenTitle
        self.amount = amount
        self.token = token
        self.paymentMethods = paymentMethods
        self.cardSectionVisible = cardSectionVisible
        self.cardSectionView = cardSectionView
        self.totalRowVisible = totalRowVisible
        self.dataSource = dataSource
    }

}
