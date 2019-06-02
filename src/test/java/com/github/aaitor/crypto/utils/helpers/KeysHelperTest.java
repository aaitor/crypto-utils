package com.github.aaitor.crypto.utils.helpers;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

public class KeysHelperTest {


    @Test
    public void generateAndSaveRSAKeys() throws NoSuchAlgorithmException, IOException {
        KeyPair keyPair= KeysHelper.generateRSAKeys();
        Key publicKey= keyPair.getPublic();
        Key privateKey= keyPair.getPrivate();

        assertEquals("RSA", publicKey.getAlgorithm());
        assertEquals("RSA", privateKey.getAlgorithm());

        File tempFile= File.createTempFile("test-", "");
        boolean result= KeysHelper.saveKeysAsBinary(keyPair, tempFile.getAbsolutePath());

        System.out.println("Generating temp key file in " + tempFile.getAbsolutePath());
        assertTrue(result);


        tempFile= File.createTempFile("test-", "-text");
        result= KeysHelper.saveKeysAsText(keyPair, tempFile.getAbsolutePath());

        System.out.println("Generating temp key file in " + tempFile.getAbsolutePath());
        assertTrue(result);
    }


    @Test
    public void loadKeysFromFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyPair keyPair= KeysHelper.generateRSAKeys();

        File tempFile= File.createTempFile("test-", "");
        KeysHelper.saveKeysAsBinary(keyPair, tempFile.getAbsolutePath());

        PublicKey publicKey = KeysHelper.loadPublicKeyFromFile(tempFile.getAbsolutePath() + KeysHelper.PUBLIC_KEY_FILE_SUFFIX);
        PrivateKey privateKey = KeysHelper.loadPrivateKeyFromFile(tempFile.getAbsolutePath() + KeysHelper.PRIVATE_KEY_FILE_SUFFIX);


        assertEquals("RSA", publicKey.getAlgorithm());
        assertEquals("RSA", privateKey.getAlgorithm());
    }
}
