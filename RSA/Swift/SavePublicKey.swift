//
//  SavePublicKey.swift
//  RSA
//
//  Created by Reejo Samuel on 9/23/17.
//  Copyright © 2017 Clapp Inc. All rights reserved.
//

import UIKit

class SavePublicKey: UIViewController {
    let rsa: RSA = RSA.sharedInstance()
    
    @IBOutlet weak var publicKeyField: UITextView!
    @IBOutlet weak var resultLabel: UILabel!
    var containsOID: Bool = false
    
    @IBAction func togglePublicKeyType(_ sender: UISwitch) {
        containsOID = sender.isOn
    }
    
    @IBAction func savePublicKey(_ sender: Any) {
        guard publicKeyField.text.characters.count > 0
            else {
            resultLabel.isHidden = false
            resultLabel.text = "Public Key is empty"
            return
            
        }
        
        var result = false
        if containsOID {
            result = rsa.setPublicKeyFromJavaServer(publicKeyField.text)
        } else {
            result = rsa.setPublicKey(publicKeyField.text)
        }
        
        resultLabel.isHidden = false
        let resultText = result == true ? "Successfully" : "Failed"
        resultLabel.text = ("\(resultText) saved")
    }
}
