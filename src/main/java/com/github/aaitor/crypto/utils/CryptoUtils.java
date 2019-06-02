package com.github.aaitor.crypto.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public abstract class CryptoUtils {

    public static final String DEFAULT_ALGORITHM= "SHA256withRSA";

    /**
     * Return an instance of Signature using SHA256withRSA as algorithm
     * @return Signature instance
     * @throws NoSuchAlgorithmException Algorithm not found
     */
    public static final Signature getSignatureInstance() throws NoSuchAlgorithmException {
        return getSignatureInstance(DEFAULT_ALGORITHM);
    }

    /**
     * Return an instance of Signature using the algorithm passed as parameter
     * @param algorithm algorithm parameter
     * @return Signature instance
     * @throws NoSuchAlgorithmException
     */
    public static final Signature getSignatureInstance(String algorithm) throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm);
    }

    /**
     * Return an instance of Cipher
     * @return Cipher instance
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static final Cipher getCipherInstance() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
    }

    /**
     * Sign a message
     * @param signature Signature
     * @param privateKey Private key
     * @param data data to sign
     * @return signed data
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] sign(Signature signature, PrivateKey privateKey, byte[] data) throws InvalidKeyException, SignatureException {
        signature.initSign(privateKey, new SecureRandom());
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verify if the signed message was created by the public key given
     * @param signature Signature
     * @param publicKey Public key
     * @param messageSignature signed message
     * @param data original message
     * @return true if the signed message was signed by the public key
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(Signature signature, PublicKey publicKey, byte[] messageSignature, byte[] data)
            throws InvalidKeyException, SignatureException {

        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(messageSignature);
    }

    /**
     * Encrypt message
     * @param publicKey Public key
     * @param message message to string
     * @return encrypted message
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] message)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message);
    }

    /**
     * Decrypt message
     * @param privateKey Private privateKey
     * @param cipherMessage encrypted message
     * @return message decrypted
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] cipherMessage)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherMessage);
    }
}
