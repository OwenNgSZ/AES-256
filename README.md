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



