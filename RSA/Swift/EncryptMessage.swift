//
//  EncryptMessage.swift
//  RSA
//
//  Created by Reejo Samuel on 9/23/17.
//  Copyright © 2017 Clapp Inc. All rights reserved.
//

import UIKit

class EncryptMessage: UIViewController {
    let rsa: RSA = RSA.sharedInstance()
    
    @IBOutlet weak var messageField: UITextView!
    @IBOutlet weak var encryptedMessageField: UITextView!
    
    /// Boolean used to determine if server's public key
    /// configure should be used for encrypting
    var useServerKey: Bool = false

    @IBAction func toggleServerKey(_ sender: UISwitch) {
        useServerKey = sender.isOn
    }
    
    @IBAction func encryptMessage(_ sender: Any) {
        let messageData = messageField.text.data(using: String.Encoding.utf8)
        
        if useServerKey {
            encryptedMessageField.text = rsa.encryptUsingServerPublicKey(with: messageData)
        } else {
            encryptedMessageField.text = rsa.encryptUsingPublicKey(with: messageData)
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.title = "RSA: Encrypt"
    }
}
