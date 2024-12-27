//
//  ViewController.m
//  DecryptChecksum_OBJ
//
//  Created by Sharat Guduru on 12/25/24.
//

#import "ViewController.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

@interface ViewController ()
@property(nonatomic, retain) NSData *encryptedAESKey;
@property(nonatomic, retain) NSData *iv;
@end

@implementation ViewController
@synthesize encryptedAESKey, iv;
- (void)viewDidLoad {
    [super viewDidLoad];
//    [self encryption];
//    
//    sleep(10);
    self.iv = [self converTohexDataFromString:@"000102030405060708090a0b0c0d0e0f"];
    [self decryption];
}

-(void)decryption{

    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"encrypted" ofType:@"txt"];
    NSString *swiftPath = [[NSBundle mainBundle] pathForResource:@"swift" ofType:@"txt"];

    NSString *base64EncryptedJSON = [self readBase64FromFile:filePath];
    NSString *swiftString = [self readBase64FromFile:swiftPath];

    NSArray<NSString *> *components = [base64EncryptedJSON componentsSeparatedByString:@"|"];
    if (components.count != 2) {
        NSLog(@"Invalid file format. Expected <Base64-encoded-AES-key>|<Base64-encoded-encrypted-data>");
        return;
    }
    
    NSString *base64AESKey = components[0];
    NSString *base64EncryptedData = components[1];
    NSLog(@"%@", base64EncryptedData);
    NSError *error;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"[^A-Za-z0-9+/=]" options:0 error:&error];
    if (error) {
        NSLog(@"Error creating regex: %@", error.localizedDescription);
        return;
    }
    
    

    // Find matches of invalid characters
    NSArray<NSTextCheckingResult *> *matches = [regex matchesInString:base64EncryptedData options:0 range:NSMakeRange(0, base64EncryptedData.length)];
    if (matches.count > 0) {
        NSLog(@"Invalid Base64 characters found in string: %@", base64EncryptedData);
        for (NSTextCheckingResult *match in matches) {
            NSRange matchRange = match.range;
            NSString *invalidCharacter = [base64EncryptedData substringWithRange:matchRange];
            NSLog(@"Invalid character: %@", invalidCharacter);
        }
    } else {
        NSLog(@"No invalid characters found. Proceeding with decoding.");
    }
    NSString *base64EncryptedData1 = [base64EncryptedData substringToIndex:[base64EncryptedData length] - 1];//[[swiftString stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@"|" withString:@""];
    
    NSArray<NSTextCheckingResult *> *matches1 = [regex matchesInString:base64EncryptedData1 options:0 range:NSMakeRange(0, base64EncryptedData1.length)];
    if (matches1.count > 0) {
        NSLog(@"Invalid Base64 characters found in string: %@", base64EncryptedData1);
        for (NSTextCheckingResult *match in matches1) {
            NSRange matchRange = match.range;
            NSString *invalidCharacter = [base64EncryptedData1 substringWithRange:matchRange];
            NSLog(@"Invalid character: %@", invalidCharacter);
        }
    } else {
        NSLog(@"No invalid characters found. Proceeding with decoding.");
    }

//    if([[base64EncryptedData substringFromIndex:[base64EncryptedData length] - 1] isEqualToString:@"\n"]) {
//        [base64EncryptedData substringFromIndex:[base64EncryptedData length] - 1];
//    }
    
    // Step 2: Decode the Base64 strings
    NSData *aesKeyData = [[NSData alloc] initWithBase64EncodedString:base64AESKey options:0];
    NSData *encryptedJSONData = [[NSData alloc] initWithBase64EncodedString:base64EncryptedData1 options:0];//NSDataBase64DecodingIgnoreUnknownCharacters
    
    if (!aesKeyData || !encryptedJSONData) {
        NSLog(@"Failed to decode Base64 strings.");
        return;
    }

    
//    if (!base64EncryptedJSON) {
//        NSLog(@"Failed to read Base64 data from file.");
//    }
//    
//    // Decode the Base64 string to get the encrypted JSON data
//    NSData *encryptedJSONData = [self base64Decode: base64EncryptedJSON];
    
    
    // Load your RSA private key here
    // Load Private Key
    NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"certificate" ofType:@"p12"];
    NSString *password = @"visa2024";
    SecKeyRef privateKey = [self loadPrivateKeyFromP12:p12Path password:password];
    
    
    // Step 1: Decrypt the AES key using the RSA private key
    NSData *decryptedAESKey = [self decryptWithRSA:aesKeyData privateKey:privateKey];
    
    if (!decryptedAESKey) {
        NSLog(@"AES key decryption failed.");
    }
    
    NSLog(@"AES KEY::::::%@", [[NSString alloc]initWithData:decryptedAESKey encoding:NSUTF8StringEncoding]);

    // Step 2: Decrypt the JSON data using the AES key and IV
    NSData *decryptedJSONData = [self decryptWithAES:encryptedJSONData key:decryptedAESKey iv:iv];
    
    if (!decryptedJSONData) {
        NSLog(@"AES decryption failed.");
    }
    
    // Step 3: Parse the decrypted JSON data
    NSDictionary *json = [self parseJSONData:decryptedJSONData];
    
    if (!json) {
        NSLog(@"Failed to parse decrypted JSON.");
    }
    
    // Output the decrypted JSON
    NSLog(@"Decrypted JSON: %@", json);
}

- (SecKeyRef)loadPrivateKeyFromP12:(NSString *)p12Path password:(NSString *)password {
    NSData *p12Data = [NSData dataWithContentsOfFile:p12Path];
    CFArrayRef items = NULL;
    
    NSDictionary *options = @{ (__bridge id)kSecImportExportPassphrase: password };
    OSStatus status = SecPKCS12Import((__bridge CFDataRef)p12Data, (__bridge CFDictionaryRef)options, &items);
    if (status != errSecSuccess) {
        NSLog(@"Failed to load .p12 file");
        return NULL;
    }
    
    NSDictionary *identityDict = (__bridge_transfer NSDictionary *)CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identity = (__bridge SecIdentityRef)identityDict[(__bridge id)kSecImportItemIdentity];
    
    SecKeyRef privateKey;
    SecIdentityCopyPrivateKey(identity, &privateKey);
    return privateKey;
}


// Helper function to decrypt AES key with RSA private key
-(NSData *)decryptWithRSA:(NSData *)encryptedData privateKey:(SecKeyRef) privateKey {
    size_t cipherLength = encryptedData.length;
    uint8_t *plainBuffer = malloc(cipherLength);
    size_t plainLength = cipherLength;
    
    OSStatus status = SecKeyDecrypt(privateKey,
                                    kSecPaddingPKCS1,
                                    encryptedData.bytes,
                                    cipherLength,
                                    plainBuffer,
                                    &plainLength);
    
    if (status != errSecSuccess) {
        NSLog(@"RSA decryption failed");
        return nil;
    }
    
    return [NSData dataWithBytes:plainBuffer length:plainLength];
}

// Helper function to decrypt data with AES
-(NSData *)decryptWithAES:(NSData *)data key:(NSData *)key iv:(NSData *)iv {
    size_t dataOutAvailable = data.length + kCCBlockSizeAES128;
    uint8_t *dataOut = malloc(dataOutAvailable);
    
    size_t dataOutMoved = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          key.bytes,
                                          kCCKeySizeAES128,
                                          iv.bytes,
                                          data.bytes,
                                          data.length,
                                          dataOut,
                                          dataOutAvailable,
                                          &dataOutMoved);
    
    if (cryptStatus != kCCSuccess) {
        NSLog(@"AES decryption failed");
        return nil;
    }
    
    return [NSData dataWithBytes:dataOut length:dataOutMoved];
}

// Function to decode Base64 encoded string to NSData
-(NSData *)base64Decode:(NSString *)base64String {
    return [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

// Function to parse JSON data
-(NSDictionary *)parseJSONData:(NSData *)data {
    NSError *error = nil;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    
    if (error) {
        NSLog(@"Error parsing JSON: %@", error.localizedDescription);
        return nil;
    }
    
    return json;
}

// Function to read Base64 data from a file
-(NSString *)readBase64FromFile:(NSString *)filePath {
    NSError *error = nil;
    NSString *base64String = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:&error];
    
    if (error) {
        NSLog(@"Error reading file: %@", error.localizedDescription);
        return nil;
    }
    
    return base64String;
}






















-(void)encryption{
    // Sample JSON data to encrypt
//    NSDictionary *json = @{@"name": @"John Doereddy", @"age": @36};
    NSError *error = nil;
//    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&error];
    NSString *inputJsonFile = [[NSBundle mainBundle] pathForResource:@"input" ofType:@"json"];
    NSData *jsonData = [NSData dataWithContentsOfFile:inputJsonFile options:NSDataReadingMappedIfSafe error:&error];

    if (error) {
        NSLog(@"Error serializing JSON: %@", error.localizedDescription);
    }
    
    // Generate AES key (128-bit)
    NSMutableData *aesKey = [self converTohexDataFromString:@"2b7e151628aed2a6abf7158809cf4f3c"];
//    [NSMutableData dataWithLength:kCCKeySizeAES128];
//    int result = SecRandomCopyBytes(kSecRandomDefault, aesKey.length, aesKey.mutableBytes);
//    if (result != 0) {
//        NSLog(@"Error generating AES key");
//    }
    
    // Generate random IV for AES
//    NSMutableData *iv = [NSMutableData dataWithLength:kCCBlockSizeAES128];
//    result = SecRandomCopyBytes(kSecRandomDefault, iv.length, iv.mutableBytes);
//    if (result != 0) {
//        NSLog(@"Error generating IV");
//    }
    self.iv = [self converTohexDataFromString:@"000102030405060708090a0b0c0d0e0f"];//iv;
    
    // RSA Encryption: Encrypt the AES key with the public key
    NSString *pubkeyPath = [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"pem"];
    SecKeyRef publicKey = [self loadRSAPublicKeyFromFile: pubkeyPath];
    encryptedAESKey = [self encryptWithRSA:aesKey pubKey:publicKey];
    
    // AES Encryption: Encrypt the JSON data using the AES key and IV
    NSData *encryptedJSON = [self encryptWithAES:jsonData key:aesKey iv:iv];
    
    // Convert encrypted JSON data to Base64
    NSString *base64EncryptedJSON = [self base64Encode:encryptedJSON];
    
    
    // Write Base64 encoded data to a file
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"encrypted" ofType:@"txt"];

    [self writeBase64ToFile:base64EncryptedJSON filePath:filePath];//writeBase64ToFile(base64EncryptedJSON, filePath);
    
    // Output the result
    NSLog(@"Encrypted JSON written to file: %@", filePath);
}

-(SecKeyRef) loadRSAPublicKeyFromFile:(NSString *)filePath {
    // Read the PEM file content
    NSError *error = nil;
    NSString *pemString = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:&error];
    
    if (error) {
        NSLog(@"Error reading PEM file: %@", error.localizedDescription);
        return nil;
    }
    
    // PEM format typically looks like this:
    // -----BEGIN PUBLIC KEY-----
    // <Base64 encoded data>
    // -----END PUBLIC KEY-----
    
    // Remove the header and footer
    NSString *pemBase64String = [pemString stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
    pemBase64String = [pemBase64String stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    pemBase64String = [pemBase64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    
    // Convert Base64 string to NSData
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:pemBase64String options:0];
    
    if (!keyData) {
        NSLog(@"Failed to decode Base64 public key.");
        return nil;
    }
    
    // Create a dictionary to specify the key attributes
    NSDictionary *keyAttributes = @{(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                    (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic};
    CFErrorRef cfError = NULL;

    // Create SecKeyRef from the NSData
    SecKeyRef publicKey = SecKeyCreateWithData((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)keyAttributes,&cfError);
    
    if (error) {
        NSLog(@"Error creating public key: %@", error.localizedDescription);
        return nil;
    }
    
    return publicKey;
}


-(NSData *)encryptWithRSA:(NSData *)data pubKey:(SecKeyRef) publicKey {
    size_t cipherLength = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherLength);
    
    OSStatus status = SecKeyEncrypt(publicKey,
                                    kSecPaddingPKCS1,
                                    data.bytes,
                                    data.length,
                                    cipherBuffer,
                                    &cipherLength);
    
    if (status != errSecSuccess) {
        NSLog(@"RSA encryption failed");
        return nil;
    }
    
    return [NSData dataWithBytes:cipherBuffer length:cipherLength];
}

// Helper function to encrypt data with AES
-(NSData *)encryptWithAES:(NSData *)data key: (NSData *)key iv:(NSData *)iv {
    size_t dataOutAvailable = data.length + kCCBlockSizeAES128;
    uint8_t *dataOut = malloc(dataOutAvailable);
    
    size_t dataOutMoved = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          key.bytes,
                                          kCCKeySizeAES128,
                                          iv.bytes,
                                          data.bytes,
                                          data.length,
                                          dataOut,
                                          dataOutAvailable,
                                          &dataOutMoved);
    
    if (cryptStatus != kCCSuccess) {
        NSLog(@"AES encryption failed");
        return nil;
    }
    
    return [NSData dataWithBytes:dataOut length:dataOutMoved];
}

// Function to convert NSData to Base64 encoded string
-(NSString *)base64Encode:(NSData *)data {
    return [data base64EncodedStringWithOptions:0];
}

// Function to write Base64 encoded data to a text file
-(void)writeBase64ToFile:(NSString *)base64String filePath:(NSString *)filePath {
    NSError *error = nil;
    NSString *base64EncodedString = [encryptedAESKey base64EncodedStringWithOptions:0];

    NSString *concaniate = [NSString stringWithFormat:@"%@|%@",base64EncodedString,base64String];
    NSLog(@"%@",concaniate);
    
    [concaniate writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    
    if (error) {
        NSLog(@"Error writing to file: %@", error.localizedDescription);
    } else {
        NSLog(@"Base64 encoded data written to file: %@", filePath);
    }
}

-(NSMutableData *)converTohexDataFromString:(NSString *)hardcodedKeyHex {
    NSMutableData *genratedHexKey = [NSMutableData dataWithCapacity:kCCKeySizeAES128];
    for (int i = 0; i < hardcodedKeyHex.length; i += 2) {
        unsigned int byte;
        [[NSScanner scannerWithString:[hardcodedKeyHex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
        uint8_t value = (uint8_t)byte;
        [genratedHexKey appendBytes:&value length:1];
    }
    
    NSLog(@"Hardcoded AES key: %@", genratedHexKey);
    return genratedHexKey;
}
@end
