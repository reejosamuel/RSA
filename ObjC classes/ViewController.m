//
//  ViewController.m
//  RSA
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//

#import "ViewController.h"
#import "RSA.h"

@interface ViewController () {
    BOOL java;
    RSA *rsa;
}

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    java = NO;
    
    rsa = [RSA sharedInstance];
    [rsa setIdentifierForPublicKey:@"com.reejosamuel.publicKey"
                        privateKey:@"com.reejosamuel.privateKey"
                   serverPublicKey:@"com.reejosamuel.serverPublicKey"];
    
    _mobilePublicKeyField.text = [rsa getPublicKeyAsBase64ForJavaServer];
    _forServerMessageField.text = [rsa getServerPublicKey];
    
    
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
                                   initWithTarget:self
                                   action:@selector(dismissKeyboard)];
    
    [self.view addGestureRecognizer:tap];
}

-(void)dismissKeyboard {
    [self.view endEditing:YES];
}


- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)generateKeys:(id)sender {
    
    
    [rsa generateRSAKeyPair:^{
        
        _mobilePublicKeyField.text = [rsa getPublicKeyAsBase64ForJavaServer];
        NSLog(@"Key generated and public key shown");
    }];
}

- (IBAction)decryptMessage:(id)sender {
    
    _forMobileMessageField.text = [rsa decryptUsingPrivateKeyWithData:[[NSData alloc] initWithBase64EncodedString:_forMobileMessageField.text options:0]];
}

- (IBAction)encryptMessage:(id)sender {
    
    NSLog(@"message to encrypt :%@", _messageToEncrypt.text);
    _forServerMessageField.text = [rsa encryptUsingServerPublicKeyWithData:[_messageToEncrypt.text dataUsingEncoding:NSUTF8StringEncoding]];
}

- (IBAction)setJavaSwitch:(id)sender {
    if([sender isOn]){
        java = YES;
        NSLog(@"java on");
    } else {
        java = NO;
    }
}

- (IBAction)setServerKey:(id)sender {
    
    if (java) {
//        NSLog(@"Java publickey being set: %@", _serverPublicKeyField.text);
        [rsa setPublicKeyFromJavaServer:_serverPublicKeyField.text];
        _forServerMessageField.text = [rsa getServerPublicKey];
    } else {
        [rsa setPublicKey:_serverPublicKeyField.text];
    }
}
@end
