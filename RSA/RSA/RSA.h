//
//  RSA Wrapper
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^RSACompletionBlock)(void);

@interface RSA : NSObject

typedef enum RSAKeySize: size_t {
    k512 = 512,
    k768 = 768,
    k1024 = 1024,
    k2048 = 2048,
} RSAKeySize;

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

+ (instancetype)sharedInstance;

- (void)setIdentifierForPublicKey:(NSString *)pubIdentifier
                       privateKey:(NSString *)privIdentifier
                  serverPublicKey:(NSString *)servPublicIdentifier;

- (void)setRSAKeySize:(RSAKeySize)keySize;

// Generation Methods

- (void)generateRSAKeyPair:(RSACompletionBlock)completion;

// Encryption Methods

- (NSString *)encryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)encryptUsingPrivateKeyWithData:(NSData *)data;
// Encrypt using Server Public Key
- (NSString *)encryptUsingServerPublicKeyWithData:(NSData *)data;


// Decrypt Methods

- (NSString *)decryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)decryptUsingPrivateKeyWithData:(NSData *)data;


// Accessors for Public Key

- (BOOL)setPublicKey:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyAsBase64;
- (NSString *)getServerPublicKey;

//  Public Key accessors for Java Servers

- (BOOL)setPublicKeyFromJavaServer:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyAsBase64ForJavaServer;

// Helpers

- (NSString *)stripPEM:(NSString *)keyString;

@end
