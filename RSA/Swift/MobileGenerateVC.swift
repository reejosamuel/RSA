//
//  MobileGenerate.swift
//  RSA
//
//  Created by Reejo Samuel on 9/22/17.
//  Copyright © 2017 Clapp Inc. All rights reserved.
//

import UIKit

class MobileGenerate: UIViewController {
    let rsa: RSA = RSA.sharedInstance()
    
    /**
    There is a no need to display private key or share with any service.
    
    The private key is stored securely in the keychain under the configured
    identifier and is used for any subsequent decryption, till the key is
    regenerated again.
    
    If you have such a requirement, it is best to re-evaluate your architecture
    **/
    
    @IBOutlet weak var publicKeyField: UITextView!
    @IBOutlet weak var javaPublicKey: UITextView!
    @IBOutlet weak var stackView: UIStackView!
    
    @IBAction func generateKeys(_ sender: Any) {
        
        rsa.generateKeyPair { [weak self] in
            // this block is called once the keys are generated
            // we can use getPublicKeyAsBase64 to fetch the public key
            // in a base64 format
            self?.publicKeyField.text = self?.rsa.getPublicKeyAsBase64()
            self?.javaPublicKey.text = self?.rsa.getPublicKeyAsBase64ForJavaServer()
        }
    }
    
    // MARK: - View Lifecycle
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.title = "Generate Keys"
        
    }
}
