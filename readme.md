# RSA
### Simplest RSA Wrapper

---

Internet has very little to offer for RSA on iOS. Over complicated code, no documentation or using 3rd Part Frameworks when it can be done using native `Security` framework on iOS

![Screen Shot](screenshot.png)



Note: Most methods return Base64 encoded strings.
### RSA.h


```
// Start a instance using +(void)sharedInstance

// Then call this method with 3 unique string as indentifiers
// Identifier in simple words is just names to used to remember these keys in a keychain

- (void)setIdentifierForPublicKey:(NSString *)pubIdentifier
                       privateKey:(NSString *)privIdentifier
                  serverPublicKey:(NSString *)servPublicIdentifier;
```


```
// Call this to generate the a pair of public and private keys for the mobile
- (void)generateKeyPairRSACompleteBlock:(GenerateSuccessBlock)_success;
```


##### Encryption Methods
```
- (NSString *)encryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)encryptUsingPrivateKeyWithData:(NSData*)data;
```

##### Decryption Methods
```
- (NSString *)decryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)decryptUsingPrivateKeyWithData:(NSData*)data;
```

##### SET and GET Public Key
```
- (BOOL)setPublicKey:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyAsBase64;
```

##### Encrypt using Server Public Key
```
// Use setPublicKey before using this method to set the server public key
- (NSString *)encryptUsingServerPublicKeyWithData:(NSData *)data;
```

---



### Have a Java Backened ?
##### It needs small modification for working with iOS


Great many thanks to Berin for [his blog post](http://blog.wingsofhermes.org/?p=75) on getting this working. 

##### SET / GET Public key for Java Servers
```
- (BOOL)setPublicKeyFromJavaServer:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyAsBase64ForJavaServer;
```
  
  
  



## License
The MIT License (MIT)

Copyright (c) 2012 Reejo Samuel (http://reejosamuel.com/)


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.