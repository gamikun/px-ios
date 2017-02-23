//
//  PaymentResultScreenPreference.swift
//  MercadoPagoSDK
//
//  Created by Eden Torres on 2/14/17.
//  Copyright © 2017 MercadoPago. All rights reserved.
//

import Foundation

open class PaymentResultScreenPreference: NSObject {
    
    var approvedTitle = "¡Listo, se acreditó tu pago!".localized
    var approvedSubtitle = ""
    var approvedSecondaryExitButtonText = ""
    var approvedSecondaryExitButtonCallback: ((PaymentResult) -> Void)?
    
    var pendingTitle = "Estamos procesando el pago".localized
    var pendingSubtitle = ""
    var pendingContentTitle = "¿Qué puedo hacer?".localized
    var pendingContentText = ""
    var pendingIconName = "iconoAcreditado"
    var pendingIconBundle = MercadoPago.getBundle()!
    var hidePendingSecondaryButton = false
    var hidePendingContentText = false
    var pendingSecondaryExitButtonText = "Pagar con otro medio".localized
    var pendingSecondaryExitButtonCallback: ((PaymentResult) -> Void)?
    
    var rejectedTitle = "Uy, no pudimos procesar el pago".localized
    var rejectedSubtitle = ""
    var rejectedIconSubtext = "Algo salió mal… ".localized
    var rejectedIconName = "congrats_iconoTcError"
    var rejectedIconBundle = MercadoPago.getBundle()!
    var rejectedContentTitle = "¿Qué puedo hacer?".localized
    var rejectedContentText = ""
    var hideRejectedSecondaryButton = false
    var hideRejectedContentText = false
    var hideRejectedContentTitle = false
    var rejectedSecondaryExitButtonText = "Pagar con otro medio".localized
    var rejectedSecondaryExitButtonCallback: ((PaymentResult) -> Void)?

    var exitButtonTitle = "Continuar".localized

    
    var hideChangePaymentMethodCell = false
    var hideAmount = false
    var hidePaymentId = false
    var hidePaymentMethod = false
    
    internal static var pendingAdditionalInfoCells = [MPCustomCell]()
    internal static var approvedAdditionalInfoCells = [MPCustomCell]()
    
    // Sets de Approved
    
    open func setApprovedTitle(title: String) {
        self.approvedTitle = title
    }
    
    open func setApprovedSubtitle(subtitle: String) {
        self.approvedSubtitle = subtitle
    }
    
    open func setApprovedSecondaryExitButton(callback: ((PaymentResult) -> Void)? ,text: String) {
        self.approvedSecondaryExitButtonText = text
        self.approvedSecondaryExitButtonCallback = callback
    }
    
    // Sets de Pending
    
    open func setPendingTitle(title: String) {
        self.pendingTitle = title
    }
    
    open func setPendingSubtitle(subtitle: String) {
        self.pendingSubtitle = subtitle
    }
    
    open func setPendingHeaderIcon(name: String, bundle: Bundle) {
        self.pendingIconName = name
        self.pendingIconBundle = bundle
    }
    
    open func setPendingContentText(text: String) {
        self.pendingContentText = text
    }
    
    open func setPendingContentTitle(title: String) {
        self.pendingContentTitle = title
    }
    
    open func disablePendingSecondaryExitButton() {
        self.hidePendingSecondaryButton = true
    }
    
    open func disablePendingContentText() {
        self.hidePendingContentText = true
    }
    
    open func setPendingSecondaryExitButton(callback: ((PaymentResult) -> Void)? ,text: String) {
        self.pendingSecondaryExitButtonText = text
        self.pendingSecondaryExitButtonCallback = callback
    }
    
    
    // Sets de rejected
    
    open func setRejectedTitle(title: String) {
        self.rejectedTitle = title
    }
    
    open func setRejectedSubtitle(subtitle: String) {
        self.rejectedSubtitle = subtitle
    }

    open func setRejectedHeaderIcon(name: String, bundle: Bundle) {
        self.rejectedIconName = name
        self.rejectedIconBundle = bundle
    }
    
    open func setRejectedContentText(text: String) {
        self.rejectedContentText = text
    }
    
    open func setRejectedContentTitle(title: String) {
        self.rejectedContentTitle = title
    }
    
    open func setRejectedIconSubtext(text: String) {
        self.rejectedIconSubtext = text
    }
    
    open func disableRejectdSecondaryExitButton() {
        self.hideRejectedSecondaryButton = true
    }
    
    open func disableRejectedContentText() {
        self.hideRejectedContentText = true
    }
    
    open func disableRejectedContentTitle() {
        self.hideRejectedContentTitle = true
    }
    
    open func setRejectedSecondaryExitButton(callback: ((PaymentResult) -> Void)? ,text: String) {
        self.rejectedSecondaryExitButtonText = text
        self.rejectedSecondaryExitButtonCallback = callback
    }
    
    open func setExitButtonTitle(title: String) {
        self.exitButtonTitle = title
    }
    
    // Disables
    
    open func disableChangePaymentMethodOptionCell() {
        self.hideChangePaymentMethodCell = true
    }
    
    open func disableApprovedAmount() {
        self.hideAmount = true
    }
    
    open func disableApprovedReceipt() {
        self.hidePaymentId = true
    }
    
    open func disableApprovedPaymentMethodInfo() {
        self.hidePaymentMethod = true
    }
    
    open func enableAmount() {
        self.hideAmount = false
    }
    
    open func enableApprovedReceipt(){
        self.hidePaymentId = true
    }
    
    open func enableChangePaymentMethodOptionCell(){
        self.hideChangePaymentMethodCell = false
    }
    
    open func enablePaymentContentText() {
        self.hidePendingContentText = false
    }
    
    open func enableApprovedPaymentMethodInfo() {
        self.hidePaymentMethod = false
    }
    
    //Custom Rows
    
    open static func addCustomPendingCell(customCell : MPCustomCell) {
        PaymentResultScreenPreference.pendingAdditionalInfoCells.append(customCell)
    }
    
    open static func addCustomApprovedCell(customCell : MPCustomCell) {
        PaymentResultScreenPreference.approvedAdditionalInfoCells.append(customCell)
    }
    
    open static func clear() {
        PaymentResultScreenPreference.approvedAdditionalInfoCells = [MPCustomCell]()
        PaymentResultScreenPreference.pendingAdditionalInfoCells = [MPCustomCell]()
    }
    
    //Approved
    
    open func getApprovedTitle() -> String {
        return approvedTitle
    }
    
    open func getApprovedSubtitle() -> String {
        return approvedSubtitle
    }
    
    open func getApprovedSecondaryButtonText() -> String {
        return approvedSecondaryExitButtonText
    }
    open func getApprovedSecondaryButtonCallback() -> ((PaymentResult) -> Void)? {
        return approvedSecondaryExitButtonCallback
    }
    
    //Pending
    
    open func getPendingTitle() -> String {
        return pendingTitle
    }
    
    open func getPendingSubtitle() -> String {
        return pendingSubtitle
    }
    
    open func getHeaderPendingIcon() -> UIImage? {
        return MercadoPago.getImage(pendingIconName, bundle: pendingIconBundle)
    }
    
    open func getPendingContetTitle() -> String {
        return pendingContentTitle
    }
    
    open func getPendingContentText() -> String {
        return pendingContentText
    }
    
    open func getPendingSecondaryButtonText() -> String {
        return pendingSecondaryExitButtonText
    }
    
    open func getPendingSecondaryButtonCallback() -> ((PaymentResult) -> Void)? {
        return pendingSecondaryExitButtonCallback
    }
    
    open func isPendingSecondaryExitButtonDisable() -> Bool {
        return hidePendingSecondaryButton
    }
    
    open func isPendingContentTextDisable() -> Bool {
        return hidePendingContentText
    }
    
    // Rejected 
    
    open func getRejectedTitle() -> String {
        return rejectedTitle
    }
    
    open func getRejectedSubtitle() -> String {
        return rejectedSubtitle
    }
    
    open func getHeaderRejectedIcon() -> UIImage? {
        return MercadoPago.getImage(rejectedIconName, bundle: rejectedIconBundle)
    }
    
    open func getRejectedContetTitle() -> String {
        return rejectedContentTitle
    }
    
    open func getRejectedContentText() -> String {
        return rejectedContentText
    }
    
    open func getRejectedIconSubtext() -> String {
        return rejectedIconSubtext
    }
    
    open func getRejectedSecondaryButtonText() -> String {
        return rejectedSecondaryExitButtonText
    }
    open func getRejectedSecondaryButtonCallback() -> ((PaymentResult) -> Void)? {
        return rejectedSecondaryExitButtonCallback
    }
    
    open func isRejectedSecondaryExitButtonDisable() -> Bool {
        return hideRejectedSecondaryButton
    }
    
    open func isRejectedContentTextDisable() -> Bool {
        return hideRejectedContentText
    }
    
    open func isRejectedContentTitleDisable() -> Bool {
        return hideRejectedContentTitle
    }
    
    open func getExitButtonTitle() -> String {
        return exitButtonTitle
    }
    
    open func isSelectAnotherPaymentMethodDisableCell() -> Bool {
        return hideChangePaymentMethodCell
    }
    
    open func isPaymentMethodDisable() -> Bool {
        return hidePaymentMethod
    }
    
    open func isAmountDisable() -> Bool {
        return hideAmount
    }
    
    open func isPaymentIdDisable() -> Bool {
        return hidePaymentId
    }
    
}
