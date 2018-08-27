# AES-CFB-256 encryption and decryption in PHP 、JAVA and C#

## PHP
``` php
<?php

$sPlaintext = "Hello Wrold!";
$sMethod = 'AES-256-CFB8';
$sPassword = "password";

$sPassword = substr(hash('sha256', $sPassword, true), 0, 32);

$iv = chr(0x16) . chr(0x61) . chr(0x0F) . chr(0x3A) . chr(0x37) . chr(0x3D) . chr(0x1B) . chr(0x51) 
    . chr(0x4A) . chr(0x39) . chr(0x5A) . chr(0x79) . chr(0x29) . chr(0x08) . chr(0x01) . chr(0x22);

// encryption
$sCiphertext = base64_encode(openssl_encrypt($sPlaintext, $sMethod, $sPassword, OPENSSL_RAW_DATA, $iv));

// decryption
$sPlaintext = openssl_decrypt(base64_decode($sCiphertext), $sMethod, $sPassword, OPENSSL_RAW_DATA, $iv);
```
