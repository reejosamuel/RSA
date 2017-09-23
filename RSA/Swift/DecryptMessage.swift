//
//  DecryptMessage.swift
//  RSA
//
//  Created by Reejo Samuel on 9/23/17.
//  Copyright © 2017 Clapp Inc. All rights reserved.
//

import UIKit

class DecryptMessage: UIViewController {
    let rsa: RSA = RSA.sharedInstance()

    @IBOutlet weak var encryptedMessageField: UITextView!
    @IBOutlet weak var decryptedMessageField: UITextView!
    
    @IBAction func decryptMessage(_ sender: Any) {
        decryptedMessageField.text = rsa.decryptUsingPrivateKey(with: Data(base64Encoded: encryptedMessageField.text))
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.title = "RSA: Decrypt"
    }
}
