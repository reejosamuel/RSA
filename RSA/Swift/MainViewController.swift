//
//  MainViewController.swift
//  RSA
//
//  Created by Reejo Samuel on 9/23/17.
//  Copyright © 2017 Clapp Inc. All rights reserved.
//

import UIKit

class MainViewController: UIViewController {
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(true)
        
        self.navigationController?.setNavigationBarHidden(true, animated: false)
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        self.navigationController?.setNavigationBarHidden(false, animated: true)
    }
}
