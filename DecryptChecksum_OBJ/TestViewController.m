//
//  TestViewController.m
//  DecryptChecksum_OBJ
//
//  Created by Sharat Guduru on 12/26/24.
//

#import "TestViewController.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Foundation/Foundation.h>
#import "Security/Security.h"

@interface TestViewController ()

@end

@implementation TestViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    // Do any additional setup after loading the view.
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"metadata_encrypted" ofType:@"txt"];
    NSLog(@"filePath---------%@", filePath);

    NSString *privateKeyPath = [[NSBundle mainBundle] pathForResource:@"private" ofType:@"pem"];
    NSLog(@"privateKeyPath---------%@", privateKeyPath);
    NSString *iv = @"1234567890123456"; // Example IV

    NSData *encryptedData = [self extractEncryptedFileFromXCFramework:filePath];
    NSString *decryptedJSON = [self decryptData:encryptedData privateKeyPath:privateKeyPath iv:iv];
    NSDictionary *resultDict = [self parseDecryptedJSON:decryptedJSON];

    NSLog(@"Decrypted JSON: %@", resultDict);

    
    
    
//
//    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
//    // The AES key and IV (should be in NSData format, either decoded from Base64 or known already)
//    NSData *aesKey = [[NSData alloc] initWithBase64EncodedString:@"jE0N8gUbCkB8QHnbuTgtcihtGUpSAvLJgEpgoC3mCy8=" options:0];
//    NSData *iv = [[NSData alloc] initWithBase64EncodedString:@"8N5zKBXSzAnm1ONMLOdnBA==" options:0];
//
//    // Decrypt the JSON data from the file
//    NSData *decryptedData = [self decryptJSONFromFile:filePath aesKey:aesKey ivdata:iv];
//    //[self decryptAES256UsingKeyAndIV:[[NSData alloc] initWithBase64EncodedString:content options:0] dc:aesKey iv:iv];
//
//    // Convert decrypted data to a string (assuming it's a valid JSON string)
//    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
//
//    if (decryptedString) {
//        NSLog(@"Decrypted JSON: %@", decryptedString);
//    } else {
//        NSLog(@"Failed to decode the decrypted data into a string.");
//    }

}

- (NSData *)extractEncryptedFileFromXCFramework:(NSString *)frameworkPath {
    NSData *encryptedData = [NSData dataWithContentsOfFile:frameworkPath];
    if (!encryptedData) {
        NSLog(@"Failed to read encrypted file");
    }
    return encryptedData;
}
- (NSString *)decryptData:(NSData *)encryptedData privateKeyPath:(NSString *)privateKeyPath iv:(NSString *)iv {
    // Decrypt IV first (if encrypted)
    NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];

    // Decrypt the encrypted JSON file using AES-256-CBC
    NSData *keyData = [self rsaDecryptKeyFromFile:privateKeyPath ivData:ivData];
    NSData *decryptedData = [self aes256DecryptData:encryptedData key:keyData iv:ivData];
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

- (NSData *)rsaDecryptKeyFromFile:(NSString *)privateKeyPath ivData:(NSData *)ivData {

    // Load private key
    SecKeyRef privateKey = [self loadPrivateKeyFromPath:privateKeyPath];
    if (!privateKey) {
        NSLog(@"Failed to load private key");
        return nil;
    }
    // Decrypt RSA encrypted IV
    size_t blockSize = SecKeyGetBlockSize(privateKey);
    uint8_t *decryptedBytes = malloc(blockSize);
    size_t decryptedLength = blockSize;

    OSStatus status = SecKeyDecrypt(privateKey, kSecPaddingPKCS1,
                                     ivData.bytes, ivData.length,
                                     decryptedBytes, &decryptedLength);

    if (status != errSecSuccess) {
        NSLog(@"Failed to decrypt: %d", (int)status);
        free(decryptedBytes);
        return nil;
    }

    NSData *decryptedData = [NSData dataWithBytes:decryptedBytes length:decryptedLength];
    free(decryptedBytes);
    return decryptedData;
}

- (SecKeyRef )loadPrivateKeyFromPath:(NSString *)path {
    // Read the private key file
    NSError *error = nil;
    NSString *keyString = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error];
    
    if (error) {
        NSLog(@"Error reading private key: %@", error.localizedDescription);
        return nil;
    }
    
    // Strip the header and footer from the PEM file
    NSString *header = @"-----BEGIN RSA PRIVATE KEY-----";
    NSString *footer = @"-----END RSA PRIVATE KEY-----";
    keyString = [keyString stringByReplacingOccurrencesOfString:header withString:@""];
    keyString = [keyString stringByReplacingOccurrencesOfString:footer withString:@""];
    keyString = [keyString stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    
    // Decode the Base64-encoded key
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!keyData) {
        NSLog(@"Error decoding Base64 private key.");
        return nil;
    }
    
//    NSData *keyData = [NSData dataWithContentsOfFile:path];
//        if (!keyData) {
//            NSLog(@"Error: Failed to read private key file.");
//            return nil;
//        }
    
    // Create a dictionary for key attributes
    CFErrorRef cfError = NULL;
    NSDictionary *keyAttributes = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
        (id)kSecAttrKeySizeInBits: @2048
    };
    
    // Create a SecKey object
    SecKeyRef privateKey = SecKeyCreateWithData((__bridge CFDataRef)keyData,
                                                (__bridge CFDictionaryRef)keyAttributes,
                                                &cfError);
    
    if (cfError) {
        NSError *conversionError = CFBridgingRelease(cfError);
        NSLog(@"Error creating SecKeyRef: %@", conversionError.localizedDescription);
        return nil;
    }
    
    return privateKey;
}


- (NSData *)aes256DecryptData:(NSData *)data key:(NSData *)key iv:(NSData *)iv {
    size_t outLength;
    NSMutableData *decryptedData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];

    CCCryptorStatus result = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                     key.bytes, kCCKeySizeAES128,
                                     iv.bytes,
                                     data.bytes, data.length,
                                     decryptedData.mutableBytes, decryptedData.length, &outLength);

    if (result == kCCSuccess) {
        decryptedData.length = outLength;
        return decryptedData;
    } else {
        NSLog(@"Failed to decrypt: %d", result);
        return nil;
    }
}
- (NSDictionary *)parseDecryptedJSON:(NSString *)jsonString {
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSDictionary *dictionary = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
    if (error) {
        NSLog(@"Failed to parse JSON: %@", error.localizedDescription);
        return nil;
    }
    return dictionary;
}





























@end

/*- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"encrypted_output" ofType:@"txt"];
    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    // The AES key and IV (should be in NSData format, either decoded from Base64 or known already)
    NSData *aesKey = [[NSData alloc] initWithBase64EncodedString:@"jE0N8gUbCkB8QHnbuTgtcihtGUpSAvLJgEpgoC3mCy8=" options:0];
    NSData *iv = [[NSData alloc] initWithBase64EncodedString:@"8N5zKBXSzAnm1ONMLOdnBA==" options:0];

    // Decrypt the JSON data from the file
    NSData *decryptedData = [self decryptJSONFromFile:filePath aesKey:aesKey ivdata:iv];
    //[self decryptAES256UsingKeyAndIV:[[NSData alloc] initWithBase64EncodedString:content options:0] dc:aesKey iv:iv];

    // Convert decrypted data to a string (assuming it's a valid JSON string)
    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    
    if (decryptedString) {
        NSLog(@"Decrypted JSON: %@", decryptedString);
    } else {
        NSLog(@"Failed to decode the decrypted data into a string.");
    }

}

- (NSData *)decryptAES256UsingKeyAndIV:(NSData *)encryptedData dc:(NSData *)key iv:(NSData *)iv {
    size_t bufferSize = encryptedData.length + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    size_t decryptedSize = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt,
                                     kCCAlgorithmAES,
                                     kCCOptionPKCS7Padding,
                                     key.bytes,
                                     kCCKeySizeAES256,
                                     iv.bytes,
                                     encryptedData.bytes,
                                     encryptedData.length,
                                     buffer,
                                     bufferSize,
                                     &decryptedSize);

    NSData *decryptedData = nil;
    if (status == kCCSuccess) {
        decryptedData = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
    } else {
        free(buffer);
        NSLog(@"Failed to decrypt JSON data: %d", status);
    }

    return decryptedData;
}

- (NSData *)decryptJSONFromFile:(NSString *)filePath aesKey:(NSData *)aesKey ivdata: (NSData *)iv {
    // Read the encrypted JSON data from the file
    NSData *encryptedJSONData = [NSData dataWithContentsOfFile:filePath];

//    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
//
//    if ([[content substringFromIndex:[content length] -1] isEqualToString:@"\n"]) {
//        content = [content substringToIndex:[content length] -1];
//    }

    // Base64 decode the encrypted JSON data (if the file contains Base64 encoded data)
    NSData *decodedEncryptedData = [[NSData alloc] initWithBase64EncodedData:encryptedJSONData options:NSDataBase64DecodingIgnoreUnknownCharacters];

    // Decrypt the Base64-decoded encrypted JSON data using AES-256-CBC
    NSData *decryptedData = [self decryptAES256UsingKeyAndIV:decodedEncryptedData dc:aesKey iv:iv];
    return decryptedData;
}



@end
*/
