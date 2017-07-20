//
//  NextStepHelper.swift
//  MercadoPagoSDK
//
//  Created by Demian Tejo on 2/3/17.
//  Copyright © 2017 MercadoPago. All rights reserved.
//

import Foundation
#if MPESC_ENABLE
    import ESCManager
#endif

extension MercadoPagoCheckoutViewModel {

    func needSearch() -> Bool {
        return search == nil
    }
    func isPaymentTypeSelected() -> Bool {

        let hasPaymentWithInvalidESC = paymentData.hasPaymentMethod() && !paymentData.hasToken() && paymentResult != nil && paymentResult?.status == PaymentStatus.INVALID_ESC.rawValue

        if (self.paymentData.isComplete() || hasPaymentWithInvalidESC) && (self.search != nil) {
            if self.paymentOptionSelected == nil {
                self.setPaymentOptionSelected()
            }
            return true
        }

        guard let selectedType = self.paymentOptionSelected else {
                return false
        }
        return !selectedType.hasChildren()
    }
    func needCompleteCard() -> Bool {
        guard let selectedType = self.paymentOptionSelected else {
            return false
        }
        if selectedType.isCustomerPaymentMethod() {
            return false
        }
        if !selectedType.isCard() {
            return false
        }
        return self.cardToken == nil && self.paymentData.paymentMethod == nil
    }

    func showConfirm() -> Bool {
        return self.paymentData.isComplete()
    }

    func showCongrats() -> Bool {
        return self.payment != nil
    }
    func needGetIdentification() -> Bool {
        guard let pm = self.paymentData.paymentMethod, let option = self.paymentOptionSelected else {
            return false
        }

        if !self.paymentData.paymentMethod.isOnlinePaymentMethod() && (self.paymentData.paymentMethod.isIdentificationRequired() || self.paymentData.paymentMethod.isIdentificationTypeRequired()) && (String.isNullOrEmpty(self.paymentData.payer.identification?.number) || String.isNullOrEmpty(self.paymentData.payer.identification?.type)) {

            return true
        }

        guard let holder = self.cardToken?.cardholder else {
            return false
        }

        if let identification = holder.identification {
            if String.isNullOrEmpty(identification.number) && pm.isIdentificationRequired() && !option.isCustomerPaymentMethod() {
                return true
            }
        }
        return false

    }

    func needGetEntityTypes() -> Bool {
        guard let _ = self.paymentOptionSelected else {
            return false
        }
        guard let pm = self.paymentData.paymentMethod else {
            return false
        }
        if paymentData.payer.entityType == nil && pm.isEntityTypeRequired() {
            return true
        }
        return false
    }

    func needGetFinancialInstitutions() -> Bool {
        guard let _ = self.paymentOptionSelected else {
            return false
        }
        guard let pm = self.paymentData.paymentMethod else {
            return false
        }

        if paymentData.transactionDetails?.financialInstitution == nil && !Array.isNullOrEmpty(pm.financialInstitutions) {
           return true
        }

        return false
    }

    func needGetIssuers() -> Bool {
        guard let selectedType = self.paymentOptionSelected else {
            return false
        }
        guard let pm = self.paymentData.paymentMethod else {
            return false
        }
        if selectedType.isCustomerPaymentMethod() {
            return false
        }
        if !paymentData.hasIssuer() && pm.isCard() && Array.isNullOrEmpty(issuers) {
            return true
        }
        return false
    }

    func needIssuerSelectionScreen() -> Bool {
        guard let selectedType = self.paymentOptionSelected else {
            return false
        }
        guard let pm = self.paymentData.paymentMethod else {
            return false
        }
        if selectedType.isCustomerPaymentMethod() {
            return false
        }
        if paymentData.issuer == nil  && pm.isCard() && !Array.isNullOrEmpty(issuers) {
            return true
        }
        return false
    }

    func needSelectCreditDebit() -> Bool {
        if self.paymentMethods != nil && self.paymentMethods?.count == 2 {//&&
            //((self.paymentMethods![0].paymentTypeId == PaymentTypeId.CREDIT_CARD && self.paymentMethods![1].paymentTypeId == PaymentTypeId.CREDIT_CARD) ||
            //    (self.paymentMethods![1].paymentTypeId == PaymentTypeId.CREDIT_CARD && self.paymentMethods![0].paymentTypeId == PaymentTypeId.CREDIT_CARD))) {

            self.paymentData.paymentMethod = self.paymentMethods?[0]

            return false
        }
        return false
    }

    func needChosePayerCost() -> Bool {
        guard let pm = self.paymentData.paymentMethod else {
            return false
        }
        if pm.isCreditCard() && !paymentData.hasPayerCost() && payerCosts == nil {
            return true
        }
        return false
    }

    func needPayerCostSelectionScreen() -> Bool {
        guard let pm = self.paymentData.paymentMethod else {
            return false
        }
        if pm.isCreditCard() && !paymentData.hasPayerCost() && payerCosts != nil {
            return true
        }
        return false
    }

    func needSecurityCode() -> Bool {
        guard let pmSelected = self.paymentOptionSelected else {
            return false
        }
        let hasInstallmentsIfNeeded = paymentData.hasPayerCost() || !self.paymentData.paymentMethod.isCreditCard()
        let isCustomerCard = pmSelected.isCustomerPaymentMethod() && pmSelected.getId() != PaymentTypeId.ACCOUNT_MONEY.rawValue

        if  isCustomerCard && !paymentData.hasToken() && hasInstallmentsIfNeeded && !hasSavedESC() {
            return true
        }

        return false
    }

    func needCreateToken() -> Bool {

        guard let pm = self.paymentData.paymentMethod else {
            return false
        }
        //Note: this is being used only for new cards, saved cards tokenization is
        //made in MercadoPagoCheckout#collectSecurityCode().

        let hasInstallmentsIfNeeded = self.paymentData.payerCost != nil || !self.paymentData.paymentMethod.isCreditCard()

        let newCard = !paymentData.hasToken() && pm.isCard() && self.cardToken != nil
        let savedCardWithESC = !paymentData.hasToken() && pm.isCard() && hasSavedESC() && hasInstallmentsIfNeeded

        return newCard || savedCardWithESC
    }

    func needReviewAndConfirm() -> Bool {

        guard let _ = self.paymentOptionSelected else {
            return false
        }

        if paymentResult != nil {
            return false
        }

        if self.isCheckoutComplete() {
            return false
        }

        if self.initWithPaymentData && paymentData.isComplete() {
            initWithPaymentData = false
            return true
        }

        if paymentData.isComplete() {
            return MercadoPagoCheckoutViewModel.flowPreference.isReviewAndConfirmScreenEnable()
        }
        return false
    }

    func shouldShowCongrats() -> Bool {
        if let paymentResult = self.paymentResult {
            if  paymentResult.status == PaymentStatus.INVALID_ESC.rawValue {
                return false
            }
        }
        if self.payment != nil || self.paymentResult != nil {
            self.setIsCheckoutComplete(isCheckoutComplete: true)
            return self.shouldDisplayPaymentResult()
        }
        return false
    }

    func shouldExitCheckout() -> Bool {
        return self.isCheckoutComplete()
    }

    func needToSearchDirectDiscount() -> Bool {
        return MercadoPagoCheckoutViewModel.flowPreference.isDiscountEnable() && self.checkoutPreference != nil && !self.directDiscountSearched && self.paymentData.discount == nil && self.paymentResult == nil && !paymentData.isComplete()
    }

    func needToCreatePayment() -> Bool {
        if paymentData.isComplete() && MercadoPagoCheckoutViewModel.paymentDataConfirmCallback == nil && MercadoPagoCheckoutViewModel.paymentDataCallback == nil {
            return readyToPay
        }
        return false
    }

    func setPaymentOptionSelected() {
        let paymentMethodWithESC = paymentData.hasPaymentMethod() && savedESCCardToken != nil
        if (self.paymentData.hasCustomerPaymentOption() || paymentMethodWithESC) && self.customPaymentOptions != nil {
            // Account_money o customer cards
            let customOption = Utils.findCardInformationIn(customOptions: self.customPaymentOptions!, paymentData: self.paymentData, savedESCCardToken: savedESCCardToken)
            self.paymentOptionSelected = customOption as? PaymentMethodOption
        } else if !self.paymentData.paymentMethod.isOnlinePaymentMethod() {
            // Medios off
            if let paymentTypeId = PaymentTypeId(rawValue : paymentData.paymentMethod.paymentTypeId) {
                self.paymentOptionSelected = Utils.findPaymentMethodSearchItemInGroups(self.search!, paymentMethodId: paymentData.paymentMethod._id, paymentTypeId: paymentTypeId)
            }
        } else {
            // Tarjetas, efectivo, crédito, debito
            if let paymentTypeId = PaymentTypeId(rawValue : paymentData.paymentMethod.paymentTypeId) {
                self.paymentOptionSelected = Utils.findPaymentMethodTypeId(self.search!.groups, paymentTypeId: paymentTypeId)
            }
        }
    }

    func needValidatePreference() -> Bool {
        return !self.needLoadPreference && !self.preferenceValidated
    }

    func hasSavedESC() -> Bool {
        guard let pmSelected = self.paymentOptionSelected else {
            return false
        }

        if let card = pmSelected as? CardInformation {
            return card.getESC() == nil ? false : true
        }
        return false
    }
}
