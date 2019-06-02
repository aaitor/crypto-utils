package com.github.aaitor.crypto.utils;

import com.github.aaitor.crypto.utils.helpers.KeysHelper;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CryptoUtilsTest {

    private static final String MESSAGE_STRING= "Hi there!";
    private static byte[] MESSAGE_BYTES;

    @BeforeClass
    public static void setUp() throws Exception {

        MESSAGE_BYTES= MESSAGE_STRING.getBytes("UTF-8");
    }

    @Test
    public void signAndVerify() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair keyPair= KeysHelper.generateRSAKeys();
        Signature signature= CryptoUtils.getSignatureInstance();

        byte[] signedMessage = CryptoUtils.sign(signature, keyPair.getPrivate(), MESSAGE_BYTES);
        boolean isVerified= CryptoUtils.verify(signature, keyPair.getPublic(), signedMessage, MESSAGE_BYTES);

        assertTrue(isVerified);
    }

    @Test
    public void signAndnotVerifying() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair keyPair= KeysHelper.generateRSAKeys();
        KeyPair keyPair2= KeysHelper.generateRSAKeys();

        Signature signature= CryptoUtils.getSignatureInstance();

        byte[] signedMessage = CryptoUtils.sign(signature, keyPair.getPrivate(), MESSAGE_BYTES);
        boolean isVerified= CryptoUtils.verify(signature, keyPair2.getPublic(), signedMessage, MESSAGE_BYTES);

        assertFalse(isVerified);
    }

    @Test
    public void encryptAndDecrypt()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        KeyPair keyPair= KeysHelper.generateRSAKeys();

        byte[] encryptedMessage = CryptoUtils.encrypt(keyPair.getPublic(), MESSAGE_BYTES);
        byte[] decryptedMessage = CryptoUtils.decrypt(keyPair.getPrivate(), encryptedMessage);

        assertTrue(MESSAGE_STRING.equals(new String(decryptedMessage)));
    }

    @Test(expected = BadPaddingException.class)
    public void encryptAndDecryptException()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        KeyPair keyPair= KeysHelper.generateRSAKeys();
        KeyPair keyPair2= KeysHelper.generateRSAKeys();


        byte[] encryptedMessage = CryptoUtils.encrypt(keyPair.getPublic(), MESSAGE_BYTES);
        byte[] decryptedMessage = CryptoUtils.decrypt(keyPair2.getPrivate(), encryptedMessage);

        assertTrue(MESSAGE_STRING.equals(new String(decryptedMessage)));
    }

}