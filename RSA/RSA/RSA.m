//
//  RSA.m
//  RSA
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//

#import "RSA.h"

#if DEBUG
    #define LOGGING_FACILITY(X, Y)	\
    NSAssert(X, Y);

    #define LOGGING_FACILITY1(X, Y, Z)	\
    NSAssert1(X, Y, Z);
#else
    #define LOGGING_FACILITY(X, Y)	\
        if (!(X)) {			\
        NSLog(Y);		\
    }

    #define LOGGING_FACILITY1(X, Y, Z)	\
        if (!(X)) {				\
        NSLog(Y, Z);		\
    }
#endif

@interface RSA (){
@private
    NSData * publicTag;
	NSData * privateTag;
    NSData * serverPublicTag;
    NSOperationQueue * cryptoQueue;
    RSACompletionBlock _completion;
    size_t kSecAttrKeySizeInBitsLength;
}

@property (strong, nonatomic) NSString * publicIdentifier;
@property (strong, nonatomic) NSString * privateIdentifier;
@property (strong, nonatomic) NSString * serverPublicIdentifier;


@property (nonatomic,readonly) SecKeyRef publicKeyRef;
@property (nonatomic,readonly) SecKeyRef privateKeyRef;
@property (nonatomic,readonly) SecKeyRef serverPublicRef;

@property (nonatomic,readonly) NSData   * publicKeyBits;
@property (nonatomic,readonly) NSData   * privateKeyBits;

@end

@implementation RSA

@synthesize publicKeyRef, privateKeyRef, serverPublicRef;

// FIXME: Base64 encoding fix
// FIXME: storage to

#pragma mark - Instance Variables

- (id)init {
    if (self = [super init]) {
        cryptoQueue = [[NSOperationQueue alloc] init];
        kSecAttrKeySizeInBitsLength = k2048;
    }
    return self;
}

+ (instancetype)sharedInstance{
    static RSA *_rsa = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _rsa = [[self alloc] init];
    });
    return _rsa;
}

#pragma mark - Set identifier strings

- (void)setIdentifierForPublicKey:(nullable NSString *)pubIdentifier
                       privateKey:(nullable NSString *)privIdentifier
                  serverPublicKey:(nullable NSString *)servPublicIdentifier {
    
    self.publicIdentifier =
        (pubIdentifier != NULL) ? pubIdentifier : @"com.reejosamuel.rsa.pubIdentifier";
    self.privateIdentifier =
        (privIdentifier != NULL) ? privIdentifier : @"com.reejosamuel.rsa.privIdentifier";
    self.serverPublicIdentifier =
        (servPublicIdentifier != NULL) ? servPublicIdentifier : @"com.reejosamuel.rsa.servPubIdentifier";
    
    // Tag data to search for keys.
    publicTag       = [self.publicIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    privateTag      = [self.privateIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    serverPublicTag = [self.serverPublicIdentifier dataUsingEncoding:NSUTF8StringEncoding];
}

- (void)setRSAKeySize:(RSAKeySize)keySize {
    kSecAttrKeySizeInBitsLength = keySize;
}

#pragma mark - PEM helpers


- (NSString *)stripPEM:(NSString *)keyString {
    NSError *error = nil;
    NSString *pattern = @"-{5}.*-{5}\n*" ;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:NSRegularExpressionCaseInsensitive error:&error];
    return [regex stringByReplacingMatchesInString:keyString options:0 range:NSMakeRange(0, keyString.length) withTemplate:@""];
}

#pragma mark - Java Helpers

// Java helpers to remove and add extra bits needed for java based backends
// Once it’s base 64 decoded it strips the ASN.1 encoding associated with the OID
// and sequence encoding that generally prepends the RSA key data. That leaves it
// with just the large numbers that make up the public key.
// Read this for a clear understanding of ANS.1, BER AND PCKS encodings
// https://stackoverflow.com/a/29707204/1460582

- (NSString *)getKeyForJavaServer:(NSData*)keyBits {
    
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        
    };
    
    // That gives us the "BITSTRING component of a full DER
    // encoded RSA public key - We now need to build the rest
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    
    if  ([keyBits length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (int)(([keyBits length] + 1 ) / 256 ) + 2;
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [keyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [keyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:keyBits];
    
    // base64 encode encKey and return
    return [encKey base64EncodedStringWithOptions:0];
    
}

size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

- (BOOL)setPublicKeyFromJavaServer:(NSString *)keyAsBase64 {
    
    /* First decode the Base64 string */
    NSData *rawFormattedKey = [[NSData alloc] initWithBase64EncodedString:keyAsBase64 options:0];
    
    
    /* Now strip the uncessary ASN encoding guff at the start */
    unsigned char * bytes = (unsigned char *)[rawFormattedKey bytes];
    size_t bytesLen = [rawFormattedKey length];
    
    /* Strip the initial stuff */
    size_t i = 0;
    if (bytes[i++] != 0x30)
        return FALSE;
    
    /* Skip size bytes */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i] != 0x30)
        return FALSE;
    
    /* Skip OID */
    i += 15;
    
    if (i >= bytesLen - 2)
        return FALSE;
    
    if (bytes[i++] != 0x03)
        return FALSE;
    
    /* Skip length and null */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i++] != 0x00)
        return FALSE;
    
    if (i >= bytesLen)
        return FALSE;
    
    /* Here we go! */
    NSData * extractedKey = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
    
    // Base64 Encoding
    NSString *javaLessBase64String = [extractedKey base64EncodedStringWithOptions:0];
    return [self setPublicKey:javaLessBase64String];
}



#pragma mark - Key generators

- (void)generateRSAKeyPair:(RSACompletionBlock)completion {
    NSInvocationOperation * genOp = [[NSInvocationOperation alloc] initWithTarget:self selector:@selector(generateKeyPairOperation) object:nil];
    [cryptoQueue addOperation:genOp];
    
    _completion = completion;
}

- (void)generateKeyPairOperation{
    @autoreleasepool {
        // Generate the asymmetric key (public and private)
        [self generateKeyPairRSA];
        [self performSelectorOnMainThread:@selector(generateKeyPairCompleted) withObject:nil waitUntilDone:NO];
    }
}

- (void)generateKeyPairCompleted{
    if (_completion) {
        _completion();
    }
}

- (void)generateKeyPairRSA {
    OSStatus sanityCheck = noErr;
	publicKeyRef = NULL;
	privateKeyRef = NULL;
	
	// First delete current keys.
	[self deleteAsymmetricKeys];
	
	// Container dictionaries.
	NSMutableDictionary * privateKeyAttr = [NSMutableDictionary dictionaryWithCapacity:0];
	NSMutableDictionary * publicKeyAttr = [NSMutableDictionary dictionaryWithCapacity:0];
	NSMutableDictionary * keyPairAttr = [NSMutableDictionary dictionaryWithCapacity:0];
	
	// Set top level dictionary for the keypair.
	[keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:kSecAttrKeySizeInBitsLength] forKey:(__bridge id)kSecAttrKeySizeInBits];
	
	// Set the private key dictionary.
	[privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
	[privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
	// See SecKey.h to set other flag values.
	
	// Set the public key dictionary.
	[publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
	[publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	// See SecKey.h to set other flag values.
	
	// Set attributes to top level dictionary.
	[keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
	[keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
	
	// SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
	sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
	LOGGING_FACILITY( sanityCheck == noErr && publicKeyRef != NULL && privateKeyRef != NULL, @"Something went wrong with generating the key pair." );
}

#pragma mark - Deletion

- (void)deleteAsymmetricKeys {
    
	OSStatus sanityCheck = noErr;
	NSMutableDictionary * queryPublicKey        = [NSMutableDictionary dictionaryWithCapacity:0];
	NSMutableDictionary * queryPrivateKey       = [NSMutableDictionary dictionaryWithCapacity:0];
	NSMutableDictionary * queryServPublicKey    = [NSMutableDictionary dictionaryWithCapacity:0];
    
	// Set the public key query dictionary.
	[queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	
	// Set the private key query dictionary.
	[queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Set the server public key query dictionary.
	[queryServPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryServPublicKey setObject:serverPublicTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryServPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	
	// Delete the private key.
	sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);
	LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing private key, OSStatus == %ld.", (long)sanityCheck );
	
	// Delete the public key.
	sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPublicKey);
	LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing public key, OSStatus == %ld.", (long)sanityCheck );
    
    // Delete the server public key.
	sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryServPublicKey);
	LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing server public key, OSStatus == %ld.", (long)sanityCheck );

    
	if (publicKeyRef) CFRelease(publicKeyRef);
	if (privateKeyRef) CFRelease(privateKeyRef);
    if (serverPublicRef) CFRelease(serverPublicRef);
}

#pragma mark - Read Bits

- (NSData *)readKeyBits:(NSData *)tag keyType:(CFTypeRef)keyType {
    
    OSStatus sanityCheck = noErr;
	CFTypeRef  _publicKeyBitsReference = NULL;
	
	NSMutableDictionary * queryPublicKey = [NSMutableDictionary dictionaryWithCapacity:0];
    
	// Set the public key query dictionary.
	[queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPublicKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)keyType forKey:(__bridge id)kSecAttrKeyType];
	[queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
	// Get the key bits.
	sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&_publicKeyBitsReference);
    
	if (sanityCheck != noErr) {
		_publicKeyBitsReference = NULL;
	}
    
    publicKeyRef = (SecKeyRef)_publicKeyBitsReference;
    
	return (__bridge NSData*)_publicKeyBitsReference;

}

- (NSData *)publicKeyBits {
    return [self readKeyBits:publicTag keyType:kSecAttrKeyTypeRSA];
}

- (NSData *)privateKeyBits {
    return [self readKeyBits:privateTag keyType:kSecAttrKeyTypeRSA];
}

- (NSData *)serverPublicBits {
    return [self readKeyBits:serverPublicTag keyType:kSecAttrKeyTypeRSA];
}


#pragma mark - Get Refs

- (void)getKeyRefFor:(NSData *)tag {
    
    OSStatus resultCode = noErr;
    
    NSMutableDictionary * queryPublicKey = [NSMutableDictionary dictionaryWithCapacity:0];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    [queryPublicKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the key.
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyRef);
    //NSLog(@"getPublicKey: result code: %ld", resultCode);
    
    if(resultCode != noErr)
    {
        publicKeyRef = NULL;
    }
    
    queryPublicKey =nil;
}


#pragma mark - Encrypt and Decrypt

- (NSString *)rsaEncryptWithData:(NSData*)data usingPublicKey:(BOOL)usePublicKey server:(BOOL)isServer{
    
    
    if (isServer) {
        [self getKeyRefFor:serverPublicTag];
    } else {
        if (usePublicKey) {
            [self getKeyRefFor:publicTag];
        } else {
            [self getKeyRefFor:privateTag];
        }
    }
    
    SecKeyRef key = self.publicKeyRef;

    
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0*0, cipherBufferSize);
    
    NSData *plainTextBytes = data;
    size_t blockSize = cipherBufferSize - 11;
    size_t blockCount = (size_t)ceil([plainTextBytes length] / (double)blockSize);
    NSMutableData *encryptedData = [NSMutableData dataWithCapacity:0];
    
    for (int i=0; i<blockCount; i++) {
        
        int bufferSize = (int)MIN(blockSize,[plainTextBytes length] - i * blockSize);
        NSData *buffer = [plainTextBytes subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        
        OSStatus status = SecKeyEncrypt(key,
                                        kSecPaddingPKCS1,
                                        (const uint8_t *)[buffer bytes],
                                        [buffer length],
                                        cipherBuffer,
                                        &cipherBufferSize);
        
        if (status == noErr){
            NSData *encryptedBytes = [NSData dataWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            [encryptedData appendData:encryptedBytes];
            
        }else{
            
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            return nil;
        }
    }
    if (cipherBuffer) free(cipherBuffer);

    return [encryptedData base64EncodedStringWithOptions:0];
}

- (NSString *)rsaDecryptWithData:(NSData*)data usingPublicKey:(BOOL)yes{
    NSData *wrappedSymmetricKey = data;
    SecKeyRef key = yes?self.publicKeyRef:self.privateKeyRef;
    
//    key = [self getPrivateKeyRef]; // reejo remove
    
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    size_t keyBufferSize = [wrappedSymmetricKey length];
    
    NSMutableData *bits = [NSMutableData dataWithLength:keyBufferSize];
    OSStatus sanityCheck = SecKeyDecrypt(key,
                                         kSecPaddingPKCS1,
                                         (const uint8_t *) [wrappedSymmetricKey bytes],
                                         cipherBufferSize,
                                         [bits mutableBytes],
                                         &keyBufferSize);
    
    if (sanityCheck != 0) {
        NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:sanityCheck userInfo:nil];
        NSLog(@"Error: %@", [error description]);
    }
    
    NSAssert(sanityCheck == noErr, @"Error decrypting, OSStatus == %ld.", (long)sanityCheck);
    
    [bits setLength:keyBufferSize];
    
    return [[NSString alloc] initWithData:bits
                                 encoding:NSUTF8StringEncoding];
}

#pragma mark - Public Key setter

- (BOOL)setPublicKey: (NSString *)keyAsBase64 {
    
    NSData *extractedKey =
                [[NSData alloc] initWithBase64EncodedString:keyAsBase64 options:0];
    
    /* Load as a key ref */
    OSStatus error = noErr;
    CFTypeRef persistPeer = NULL;
    
    NSData * refTag = [self.serverPublicIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableDictionary * keyAttr = [[NSMutableDictionary alloc] init];
    
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    /* First we delete any current keys */
    error = SecItemDelete((__bridge CFDictionaryRef) keyAttr);
    
    [keyAttr setObject:extractedKey forKey:(__bridge id)kSecValueData];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    error = SecItemAdd((__bridge CFDictionaryRef) keyAttr, (CFTypeRef *)&persistPeer);
    
    if (persistPeer == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Problem adding public key to keychain");
        return FALSE;
    }
    
    CFRelease(persistPeer);
    
    serverPublicRef = nil;
    
    /* Now we extract the real ref */
    [keyAttr removeAllObjects];
    /*
     [keyAttr setObject:(id)persistPeer forKey:(id)kSecValuePersistentRef];
     [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
     */
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the persistent key reference.
    error = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttr, (CFTypeRef *)&serverPublicRef);
    
    if (serverPublicRef == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Error retrieving public key reference from chain");
        return FALSE;
    }
    
    return TRUE;
}


#pragma mark - Public Key getters

- (NSString *)getPublicKeyAsBase64 {
    return [[self publicKeyBits] base64EncodedStringWithOptions:0];
}

- (NSString *)getPublicKeyAsBase64ForJavaServer {
    return [self getKeyForJavaServer:[self publicKeyBits]];
}

- (NSString *)getServerPublicKey {
    return [[self serverPublicBits] base64EncodedStringWithOptions:0];
}

#pragma mark - Encrypt helpers

- (NSString *)encryptUsingServerPublicKeyWithData:(NSData *)data {
    return [self rsaEncryptWithData:data usingPublicKey:YES server:YES];
}

- (NSString *)encryptUsingPublicKeyWithData:(NSData *)data{
    return [self rsaEncryptWithData:data usingPublicKey:YES server:NO];
}

- (NSString *)encryptUsingPrivateKeyWithData:(NSData*)data{
    return [self rsaEncryptWithData:data usingPublicKey:NO server:NO];
}

#pragma mark - Decrypt helpers

- (NSString *)decryptUsingPublicKeyWithData:(NSData *)data{
    return [self rsaDecryptWithData:data usingPublicKey:YES];
}

- (NSString *)decryptUsingPrivateKeyWithData:(NSData*)data{
    return [self rsaDecryptWithData:data usingPublicKey:NO];
}

@end
