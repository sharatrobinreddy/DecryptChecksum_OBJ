//
//  Test1ViewController.m
//  DecryptChecksum_OBJ
//
//  Created by Sharat Guduru on 12/26/24.
//

#import "Test1ViewController.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Foundation/Foundation.h>
#import "Security/Security.h"

@interface Test1ViewController ()

@end

@implementation Test1ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Load Private Key
    NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"certificate" ofType:@"p12"];
    NSString *password = @"visa2024";
    SecKeyRef privateKey = [self loadPrivateKeyFromP12:p12Path password:password];
    
    // Generate Key and IV
    
    NSData *key = [@"0123456789abcdef0123456789abcdef" dataUsingEncoding:NSUTF8StringEncoding]; // Example key (16 bytes)
    NSData *iv = [@"1234567890123456"dataUsingEncoding:NSUTF8StringEncoding];//[self generateRandomIV];
    
    // Encrypt JSON
    //    {
    //      "ios-arm64_x86_64-simulator": "e1267ba31bf2e32154720af5f5b99cf78002b72e21c1735439c882f4ba9f3848",
    //      "ios-arm64": "2982402f1dea2575aec8869a3be94dc06abaadef7a8089dfc12b0e41ced904e8"
    //    }
    
    NSDictionary *json = @{@"ios-arm64_x86_64-simulator": @"e1267ba31bf2e32154720af5f5b99cf78002b72e21c1735439c882f4ba9f3848",
                           @"ios-arm64": @"2982402f1dea2575aec8869a3be94dc06abaadef7a8089dfc12b0e41ced904e8"};
    NSData *encryptedData = [self encryptJSON:json withKey:key andIV:iv];
    
    NSError *error = nil;
    
    NSString *dataFilepath = [[NSBundle mainBundle] pathForResource:@"encrypted" ofType:@"txt"];
    NSString *base64String = [NSString stringWithContentsOfFile:dataFilepath encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"Error reading file: %@", error.localizedDescription);
    }
    
    // Step 3: Decode the Base64 string to get the encrypted data
    NSData *encryptedData1 = [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    if (!encryptedData) {
        NSLog(@"Error decoding base64 string.");
    }
    
        NSData *encryptedData2 = [NSData dataWithContentsOfFile:dataFilepath];
    
    // Decrypt JSON
    NSDictionary *decryptedJSON = [self decryptJSON:encryptedData2 withKey:key andIV:iv];
    NSLog(@"Decrypted JSON: %@", decryptedJSON);
    
    
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
//MARK: RANDOM GENE
- (NSData *)generateRandomIV {
    uint8_t buffer[kCCBlockSizeAES128];
    int result = SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, buffer);
    if (result != 0) {
        NSLog(@"Error generating IV");
        return nil;
    }
    return [NSData dataWithBytes:buffer length:sizeof(buffer)];
}
//MARK: ENCRYPTION
- (NSData *)encryptJSON:(NSDictionary *)json withKey:(NSData *)key andIV:(NSData *)iv {
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:nil];
    NSMutableData *encryptedData = [NSMutableData dataWithLength:jsonData.length + kCCBlockSizeAES128];
    
    size_t outLength;
    CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                     key.bytes, key.length, iv.bytes,
                                     jsonData.bytes, jsonData.length,
                                     encryptedData.mutableBytes, encryptedData.length, &outLength);
    
    if (status == kCCSuccess) {
        encryptedData.length = outLength;
        return encryptedData;
    } else {
        NSLog(@"Failed to encrypt JSON");
        return nil;
    }
}
//MARK: DECRYPTION
- (NSDictionary *)decryptJSON:(NSData *)encryptedData withKey:(NSData *)key andIV:(NSData *)iv {
    NSMutableData *decryptedData = [NSMutableData dataWithLength:encryptedData.length + kCCBlockSizeAES128];
    
    size_t outLength;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                     key.bytes, kCCKeySizeAES128, iv.bytes,
                                     encryptedData.bytes, encryptedData.length,
                                     decryptedData.mutableBytes, decryptedData.length, &outLength);
    
    if (status == kCCSuccess) {
        decryptedData.length = outLength;
        NSString *base64String = [decryptedData base64EncodedStringWithOptions:0];
        NSLog(@"BASE64::::%@", base64String);
        return [NSJSONSerialization JSONObjectWithData:decryptedData options:0 error:nil];
    } else {
        NSLog(@"Failed to decrypt JSON");
        return nil;
    }
}

@end

/*
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
    [self encryption];
     
     sleep(10);
     [self decryption];
 }

 -(void)decryption{

     NSString *filePath = [[NSBundle mainBundle] pathForResource:@"encrypted" ofType:@"txt"];
     NSString *swiftPath = [[NSBundle mainBundle] pathForResource:@"swift" ofType:@"txt"];

     
     self.iv = [@"000102030405060708090a0b0c0d0e0f" dataUsingEncoding:NSUTF8StringEncoding];//[self converTohexDataFromString:@"000102030405060708090a0b0c0d0e0f"];//iv;

     NSString *base64EncryptedJSON = [self readBase64FromFile:filePath];
     NSString *base64EncryptedSwiftJSON = [self readBase64FromFile:swiftPath];

     ///////////////
 //    // Step 1: Read and split the file
 //        NSError *error;
 //        NSString *fileContent = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:&error];
 //        if (error) {
 //            NSLog(@"Failed to read file: %@", error.localizedDescription);
 //            return;
 //        }
         
     // Split by the delimiter "|"
 //        NSArray<NSString *> *components = [base64EncryptedJSON componentsSeparatedByString:@"|"];
 //        if (components.count != 2) {
 //            NSLog(@"Invalid file format. Expected <Base64-encoded-AES-key>|<Base64-encoded-encrypted-data>");
 //            return;
 //        }
 //
 //        NSString *base64AESKey = components[0];
 //    NSString *base64EncryptedData = [base64EncryptedSwiftJSON stringByReplacingOccurrencesOfString:@"\n" withString:@""];//components[1];
 //
 //        // Step 2: Decode the Base64 strings
 //    NSData *aesKeyData = [[NSData alloc] initWithBase64EncodedString:base64AESKey options:0];
 //    NSData *encryptedJSONData = [[NSData alloc] initWithBase64EncodedString:base64EncryptedData options:0];
 //
 //        if (!aesKeyData || !encryptedJSONData) {
 //            NSLog(@"Failed to decode Base64 strings.");
 //            return;
 //        }
     if (!base64EncryptedJSON) {
         NSLog(@"Failed to read Base64 data from file.");
     }
     
     // Decode the Base64 string to get the encrypted JSON data
     NSData *encryptedJSONData = [self base64Decode: base64EncryptedJSON];
     
     
     // Load your RSA private key here
     // Load Private Key
     NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"certificate" ofType:@"p12"];
     NSString *password = @"visa2024";
     SecKeyRef privateKey = [self loadPrivateKeyFromP12:p12Path password:password];

     // Step 1: Decrypt the AES key using the RSA private key
     NSData *decryptedAESKey = [self decryptWithRSA:encryptedAESKey privateKey:privateKey];
     
     if (!decryptedAESKey) {
         NSLog(@"AES key decryption failed.");
     }
     NSLog(@"AES KEY::::::%@", [[NSString alloc]initWithData:decryptedAESKey encoding:NSUTF8StringEncoding]);
     
     // Step 2: Decrypt the JSON data using the AES key and IV
     NSData *decryptedJSONData = [self decryptWithAES:encryptedJSONData key:decryptedAESKey iv:iv];
     
     if (!decryptedJSONData) {
         NSLog(@"AES decryption failed.");
     }
     [self decryptAndCompareData:decryptedJSONData];
 //    NSMutableString *hexString = [NSMutableString string];
 //    for (NSInteger i = 0; i < decryptedJSONData.length; i++) {
 //        [hexString appendFormat:@"%02x", ((unsigned char *)decryptedJSONData.bytes)[i]];
 //    }
 //    NSLog(@"Decrypted Data (Hex): %@", hexString);
 //
 //    NSString *jsonString = @"{\"ios-arm64_x86_64-simulator\": \"e1267ba31bf2e32154720af5f5b99cf78002b72e21c1735439c882f4ba9f3848\", \"ios-arm64\": \"2982402f1dea2575aec8869a3be94dc06abaadef7a8089dfc12b0e41ced904e8\"}";

     // Step 3: Parse the decrypted JSON data
     NSDictionary *json = [self parseJSONData:decryptedJSONData];
     
     if (!json) {
         NSLog(@"Failed to parse decrypted JSON.");
     }
     
     // Output the decrypted JSON
     NSLog(@"Decrypted JSON: %@", json);
 }
 - (NSString *)hexStringFromData:(NSData *)data {
     NSMutableString *hexString = [NSMutableString string];
     const unsigned char *bytes = [data bytes];
     for (NSUInteger i = 0; i < data.length; i++) {
         [hexString appendFormat:@"%02x", bytes[i]];
     }
     return [hexString copy];
 }

 - (NSString *)hexStringFromString:(NSString *)string {
     NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
     return [self hexStringFromData:data];
 }
 - (void)decryptAndCompareData:(NSData *)decryptedData {

     // Convert decrypted data to hex
     NSString *decryptedHex = [self hexStringFromData:decryptedData];
     NSLog(@"Decrypted Data (Hex): %@", decryptedHex);

     // Expected decrypted string (for comparison)
     NSString *jsonString = @"{\"ios-arm64_x86_64-simulator\": \"e1267ba31bf2e32154720af5f5b99cf78002b72e21c1735439c882f4ba9f3848\", \"ios-arm64\": \"2982402f1dea2575aec8869a3be94dc06abaadef7a8089dfc12b0e41ced904e8\"}";

     NSString *expectedHex = [self hexStringFromString:jsonString];  // Replace with your expected output

     // Compare decrypted data with expected
     if ([decryptedHex isEqualToString:expectedHex]) {
         NSLog(@"Decrypted data matches expected output.");
     } else {
         NSLog(@"Decrypted data does not match expected output.");
     }
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
                                     encryptedData.length,
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
 //    if (key.length != 32) {
 //        NSLog(@"Invalid key size: Expected 32 bytes for AES-256.");
 //        return nil;
 //    }
     size_t dataOutAvailable = data.length + kCCBlockSizeAES128;
     uint8_t *dataOut = malloc(dataOutAvailable);
     
     size_t dataOutMoved = 0;
     
     CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                           kCCAlgorithmAES128,
                                           kCCOptionPKCS7Padding,
                                           key.bytes,
                                           key.length,
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
 //    NSDictionary *json = @{@"name": @"John Doe", @"age": @36};
     NSError *error = nil;
 //    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&error];
     
 //    if (error) {
 //        NSLog(@"Error serializing JSON: %@", error.localizedDescription);
 //    }
     NSString *inputJsonFile = [[NSBundle mainBundle] pathForResource:@"input" ofType:@"json"];
     NSData *jsonData = [NSData dataWithContentsOfFile:inputJsonFile options:NSDataReadingMappedIfSafe error:&error];

     
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
     [base64String writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:&error];
     
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

 */
