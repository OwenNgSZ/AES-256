# AES-CFB-256 encryption and decryption in PHP 、JAVA and C#

## PHP
``` php
<?php

$sPlaintext = "Hello Wrold!";
$sMethod    = 'AES-256-CFB8';
$sPassword  = "password";

$sPassword = substr(hash('sha256', $sPassword, true), 0, 32);

$iv = chr(0x16) . chr(0x61) . chr(0x0F) . chr(0x3A) . chr(0x37) . chr(0x3D) . chr(0x1B) . chr(0x51) 
    . chr(0x4A) . chr(0x39) . chr(0x5A) . chr(0x79) . chr(0x29) . chr(0x08) . chr(0x01) . chr(0x22);

// encryption
$sCiphertext = base64_encode(openssl_encrypt($sPlaintext, $sMethod, $sPassword, OPENSSL_RAW_DATA, $iv));

// decryption
$sPlaintext = openssl_decrypt(base64_decode($sCiphertext), $sMethod, $sPassword, OPENSSL_RAW_DATA, $iv);

echo 'plaintext is: ' . $sPlaintext . "\n";
echo 'encrypted to: ' . $sCiphertext . "\n";
echo 'decrypted to: ' . $sPlaintext . "\n";

```

```
plaintext is: Hello Wrold!
encrypted to: uXcxRQdC2WxPCaEQ
decrypted to: Hello Wrold!
```

## JAVA
``` java
import java.util.Base64;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptUtils {

    private static final String ALGORITHM_AES = "AES";
    
    private static final String CIPHER_ALGORITHM = "AES/CFB8/NOPADDING";

    private static byte[] IV = {
        0x16, 0x61, 0x0F, 0x3A, 0x37, 0x3D, 0x1B, 0x51,
        0x4A, 0x39, 0x5A, 0x79, 0x29, 0x08, 0x01, 0x22
    };

    private EncryptUtils() {
        throw new UnsupportedOperationException("can't instantiate");
    }

    public static String encryptAES(String key, String data) {
        try {
            final Key keySpec = createKey(key.getBytes("UTF-8"));
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(IV));
            final byte[] encoded = cipher.doFinal(data.getBytes("UTF-8"));
            return new String(Base64.getEncoder().encode(encoded));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptAES(String key, String data) {
        try {
            final Key keySpec = createKey(key.getBytes("UTF-8"));
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(IV));
            final byte[] bytes = Base64.getDecoder().decode(data);
            return new String(cipher.doFinal(bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Key createKey(byte[] key) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyByte = digest.digest(key);
        return new SecretKeySpec(keyByte, ALGORITHM_AES);
    }

}

```

``` java
import java.io.*;

public class main {
    
    public static void main(String []args) {

        String sPassword = "password";

        String sCiphertext = EncryptUtils.encryptAES(sPassword, "Hello Wrold!");
    	System.out.println("sCiphertext : " + sCiphertext);

    	String sPlaintext = EncryptUtils.decryptAES(sPassword, sCiphertext);
    	System.out.println("sPlaintext  : " + sPlaintext);
    }

}
```

```
sCiphertext : uXcxRQdC2WxPCaEQ
sPlaintext  : Hello Wrold!
```

## C#
```
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace aesApp {

    class Program {

        static byte[] iv = {
            0x16, 0x61, 0x0F, 0x3A, 0x37, 0x3D, 0x1B, 0x51,
            0x4A, 0x39, 0x5A, 0x79, 0x29, 0x08, 0x01, 0x22
        };

        static void Main(string[] args) {

            string message = "Hello Wrold!";
            string password = "password";

            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));

            string ciphertext = Encrypt(message, key);
            Console.WriteLine("ciphertext : " + ciphertext);

            string plaintext = Decrypt(ciphertext, key);
            Console.WriteLine("plaintext  : " + plaintext);

        }

        public static string Encrypt (string plainText, byte[] key) {

            Byte[] toEncryptArray = Encoding.ASCII.GetBytes(plainText);

            System.Security.Cryptography.RijndaelManaged rm = new System.Security.Cryptography.RijndaelManaged {
                Key = key,
                Mode = System.Security.Cryptography.CipherMode.CFB,
                Padding = System.Security.Cryptography.PaddingMode.None,
                IV = iv,
                FeedbackSize = 8,
                BlockSize = 128
            };

            System.Security.Cryptography.ICryptoTransform cTransform = rm.CreateEncryptor();
            Byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        public static string Decrypt (string cipherText, byte[] key) {

            Byte[] toEncryptArray = Convert.FromBase64String(cipherText);

            System.Security.Cryptography.RijndaelManaged rm = new System.Security.Cryptography.RijndaelManaged {
                Key = key,
                Mode = System.Security.Cryptography.CipherMode.CFB,
                Padding = System.Security.Cryptography.PaddingMode.None,
                IV = iv,
                FeedbackSize = 8
            };

            System.Security.Cryptography.ICryptoTransform cTransform = rm.CreateDecryptor();
            Byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Encoding.ASCII.GetString(resultArray);
        }
    }
}

```

```
ciphertext : uXcxRQdC2WxPCaEQ
plaintext  : Hello Wrold!
```
