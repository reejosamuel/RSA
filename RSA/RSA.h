//
//  RSA Wrapper
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^GenerateSuccessBlock)(void);

@interface RSA : NSObject

/**
 *  Steps to Follow
 *
 *  Step 1: Start a sharedInstance
 *  Step 2: Set the Public, Private and Server Public Identifiers
 *  Step 3: Generate public/private keys for device
 *  Step 4: Set server public key
 *  Step 5: Encrypt/Decrypt using helpers
 *
 *  Note: Public, private identifiers can be any string used
 *        to uniquely identify the keys stored in keychain.
 */

+ (id)sharedInstance;
- (void)setIdentifierForPublicKey:(NSString *)pubIdentifier
                       privateKey:(NSString *)privIdentifier
                  serverPublicKey:(NSString *)servPublicIdentifier;

- (void)generateKeyPairRSACompleteBlock:(GenerateSuccessBlock)_success;


// returns Base64 encoded strings


// Encryption Method

- (NSString *)encryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)encryptUsingPrivateKeyWithData:(NSData*)data;

// Decrypt Methods

- (NSString *)decryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)decryptUsingPrivateKeyWithData:(NSData*)data;

// SET / GET Public Key

- (BOOL)setPublicKey:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyAsBase64;

- (NSString *)getServerPublicKey;

// Encrypt using Server Public Key

- (NSString *)encryptUsingServerPublicKeyWithData:(NSData *)data;

//  SET / GET Public key for Java Servers

- (BOOL)setPublicKeyFromJavaServer:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyAsBase64ForJavaServer;



@end
