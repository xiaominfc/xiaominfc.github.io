---
layout: post
title:  AES加密(兼容php，java，objective-c)
category: xiaominfc
description: AES加密(兼容php，java，objective-c)
---

这些天开发android,ios的客户端需要与服务端用php开发的api进行数据交互。为了高大上一些决定用aes加密，但是问题就来了，因为aes有好几种模式，每种模式在各种语言下都是差异化的表现方式，探索了许久终于找到合适他们三种语言的的一套方案。

php：
php的代码就比较简单，几行就搞定

~~~~php

static $iv = 'AESAPPCLIENT_KEY';//16或16的倍数长个char
//$privateKey是加密 解密需要的密钥
function aesEncode($data,$privateKey){
    $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $privateKey, $data, MCRYPT_MODE_CBC,$iv);
    return rtrim((base64_encode($encrypted)));
}
    
function aesDecode($data,$privateKey){
    $encryptedData = base64_decode($data);
    $decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $privateKey, $encryptedData, MCRYPT_MODE_CBC,$iv);
    return rtrim($decrypted);
}
~~~~

加密后末尾莫名多了些东东 就用rtrim()去掉了

java:
主要注意要补零

~~~~java

public class ToolsUtils {

private final static String IVKEY = "AESAPPCLIENT_KEY";

public static String encrypt(String data,String key) {
    try {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        int blockSize = cipher.getBlockSize();
        SecretKeySpec keyspec = new SecretKeySpec(fullZore(key,blockSize), "AES");
        IvParameterSpec ivspec = new IvParameterSpec(fullZore(IVKEY,blockSize));
        cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
        byte[] encrypted = cipher.doFinal(fullZore(data,blockSize));
        return new String(Base64.encode(encrypted, Base64.DEFAULT)).trim();
    } catch (Exception e) {
        e.printStackTrace();
        return "";
    }
}

public static String decrypt(String data,String key) {
    try {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        int blockSize = cipher.getBlockSize();
        SecretKeySpec keyspec = new SecretKeySpec(fullZore(key,blockSize), "AES");
        IvParameterSpec ivspec = new IvParameterSpec(fullZore(IVKEY,blockSize));
        cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
        byte[] decrypted = cipher.doFinal(Base64. decode(data, Base64.DEFAULT));
        return new String(decrypted).trim();
    } catch (Exception e) {
        e.printStackTrace();
        return "";
    }
}

public static byte[] fullZore(String data,int blockSize){
    byte[] dataBytes = data.getBytes();
    int plaintextLength = dataBytes.length;
    if (plaintextLength % blockSize != 0) {
        plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
    }
    byte[] plaintext = new byte[plaintextLength];
    System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
    return plaintext;
}

}
~~~~

objective-c:
也是主要注意要补零
NSData+AES.h
    
~~~~

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
@interface NSData (AES)
- (NSData *)AES128EncryptWithKey:(NSString *)key iv:(NSString *)iv;
- (NSData *)AES128DecryptWithKey:(NSString *)key iv:(NSString *)iv;
- (NSString *)base64Encoding;
+ (id)dataWithBase64EncodedString:(NSString *)string;
@end
~~~~

NSData+AES.m

~~~~objc
#import "NSData+AES.h"

static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

@implementation NSData (AES)

- (NSData *)AES128EncryptWithKey:(NSString *)key iv:(NSString *)iv
{
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));

    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];

    char ivPtr[kCCKeySizeAES128+1];
    bzero(ivPtr, sizeof(ivPtr));

    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];

    NSUInteger dataLength = [self length];
    int diff = kCCKeySizeAES128 - (dataLength % kCCKeySizeAES128);
    int newSize = 0;

    if(diff > 0)
    {
        newSize = dataLength + diff;
    }

    char dataPtr[newSize];
    memcpy(dataPtr, [self bytes], [self length]);
    for(int i = 0; i < diff; i++)
    {
        dataPtr[i + dataLength] = 0x00;
    }

    size_t bufferSize = newSize + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          0x00, //No padding
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          ivPtr,
                                          dataPtr,
                                          sizeof(dataPtr),
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if(cryptStatus == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }

    return nil;
}

- (NSData *)AES128DecryptWithKey:(NSString *)key iv:(NSString *)iv
{
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));

    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];

    char ivPtr[kCCKeySizeAES128+1];
    bzero(ivPtr, sizeof(ivPtr));

    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];

    NSUInteger dataLength = [self length];

    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x00, //No padding
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          ivPtr,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);

    if(cryptStatus == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    return nil;
}

+ (id)dataWithBase64EncodedString:(NSString *)string;
{
    if (string == nil)
        [NSException raise:NSInvalidArgumentException format:nil];
    if ([string length] == 0)
        return [NSData data];

    static char *decodingTable = NULL;
    if (decodingTable == NULL)
    {
        decodingTable = malloc(256);
        if (decodingTable == NULL)
            return nil;
        memset(decodingTable, CHAR_MAX, 256);
        NSUInteger i;
        for (i = 0; i < 64; i++)
            decodingTable[(short)encodingTable[i]] = i;
    }

    const char *characters = [string cStringUsingEncoding:NSASCIIStringEncoding];
    if (characters == NULL) // Not an ASCII string!
        return nil;
    char *bytes = malloc((([string length] + 3) / 4) * 3);
    if (bytes == NULL)
        return nil;
    NSUInteger length = 0;

    NSUInteger i = 0;
    while (YES)
    {
        char buffer[4];
        short bufferLength;
        for (bufferLength = 0; bufferLength < 4; i++)
        {
            if (characters[i] == '\0')
                break;
            if (isspace(characters[i]) || characters[i] == '=')
                continue;
            buffer[bufferLength] = decodingTable[(short)characters[i]];
            if (buffer[bufferLength++] == CHAR_MAX) // Illegal character!
            {
                free(bytes);
                return nil;
            }
        }

        if (bufferLength == 0)
            break;
        if (bufferLength == 1) // At least two characters are needed to produce one byte!
        {
            free(bytes);
            return nil;
        }

        // Decode the characters in the buffer to bytes.
        bytes[length++] = (buffer[0] << 2) | (buffer[1] >> 4);
        if (bufferLength > 2)
            bytes[length++] = (buffer[1] << 4) | (buffer[2] >> 2);
        if (bufferLength > 3)
            bytes[length++] = (buffer[2] << 6) | buffer[3];
    }

    bytes = realloc(bytes, length);
    return [NSData dataWithBytesNoCopy:bytes length:length];
}

- (NSString *)base64Encoding
{
    if ([self length] == 0)
        return @"";

    char *characters = malloc((([self length] + 2) / 3) * 4);
    if (characters == NULL)
        return nil;
    NSUInteger length = 0;

    NSUInteger i = 0;
    while (i < [self length])
    {
        char buffer[3] = {0,0,0};
        short bufferLength = 0;
        while (bufferLength < 3 && i < [self length]) buffer[bufferLength++] = ((char *)[self bytes])[i++]; // Encode the bytes in the buffer to four characters, including padding “=” characters if necessary.
        characters[length++] = encodingTable[(buffer[0] & 0xFC) >> 2];
        characters[length++] = encodingTable[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
        if (bufferLength > 1)
            characters[length++] = encodingTable[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)];
        else characters[length++] = '=';
        if (bufferLength > 2)
            characters[length++] = encodingTable[buffer[2] & 0x3F];
        else characters[length++] = '=';
    }

    return [[NSString alloc] initWithBytesNoCopy:characters length:length encoding:NSUTF8StringEncoding freeWhenDone:YES];
}

@end
~~~~

example code:

~~~~objc
NSString *textData = @"this is text";
NSString *iv = @"1234567890123456";//must be 16 or 16*i length
NSString *key = @"key";

NSData *encodeData =  [[textData dataUsingEncoding:NSUTF8StringEncoding] AES128EncryptWithKey:key iv:iv];

NSLog(@"encode data:%@",[encodeData base64Encoding]);// print base64 code

NSData *decodeData = [encodeData AES128DecryptWithKey:key iv:iv];

NSLog(@"decode data:%@",[[NSString alloc] initWithData:decodeData encoding:NSUTF8StringEncoding]);
~~~~