//
//  ViewController.h
//  RSA
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController

- (IBAction)generateKeys:(id)sender;
- (IBAction)decryptMessage:(id)sender;
- (IBAction)encryptMessage:(id)sender;
- (IBAction)setServerKey:(id)sender;


@property (strong, nonatomic) IBOutlet UITextView *mobilePublicKeyField;
@property (strong, nonatomic) IBOutlet UITextView *forMobileMessageField;
@property (strong, nonatomic) IBOutlet UITextView *serverPublicKeyField;
@property (strong, nonatomic) IBOutlet UITextView *forServerMessageField;
- (IBAction)setJavaSwitch:(id)sender;
@property (strong, nonatomic) IBOutlet UITextField *messageToEncrypt;
@end
