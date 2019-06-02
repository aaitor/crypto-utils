package com.github.aaitor.crypto.utils.helpers;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public abstract class KeysHelper {

    private static final int DEFAULT_KEY_SIZE= 1024;
    public static final String PRIVATE_KEY_FILE_SUFFIX= ".key";
    public static final String PUBLIC_KEY_FILE_SUFFIX= ".pub";


    /**
     * Generate RSA Keys where key size is 1024
     * @return KeyPair instance
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateRSAKeys() throws NoSuchAlgorithmException {
        return generateRSAKeys(DEFAULT_KEY_SIZE);
    }

    /**
     * Generate RSA Keys where key size is given by parameter
     * @return KeyPair instance
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateRSAKeys(int keySize) throws NoSuchAlgorithmException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    /**
     * Given a KeyPair instance saves the content in a file in binary format
     * @param keyPair instance
     * @param outFilePath file path where the keys are going to be stored
     * @return true if everything goes okay
     * @throws IOException
     */
    public static boolean saveKeysAsBinary(KeyPair keyPair, String outFilePath)  throws IOException  {

        FileOutputStream out = new FileOutputStream(outFilePath + PRIVATE_KEY_FILE_SUFFIX);
        out.write(keyPair.getPrivate().getEncoded());
        out.close();

        out = new FileOutputStream(outFilePath + PUBLIC_KEY_FILE_SUFFIX);
        out.write(keyPair.getPublic().getEncoded());
        out.close();

        return true;
    }

    /**
     * Given a KeyPair instance saves the content in a file in plain text
     * @param keyPair instance
     * @param outFilePath file path where the keys are going to be stored
     * @return true if everything goes okay
     * @throws IOException
     */
    public static boolean saveKeysAsText(KeyPair keyPair, String outFilePath)  throws IOException  {

        Base64.Encoder encoder = Base64.getEncoder();

        FileWriter out = new FileWriter(outFilePath + PRIVATE_KEY_FILE_SUFFIX);
        out.write("-----BEGIN RSA PRIVATE KEY-----\n");
        out.write(encoder.encodeToString(keyPair.getPrivate().getEncoded()));
        out.write("\n-----END RSA PRIVATE KEY-----\n");
        out.close();

        out = new FileWriter(outFilePath + PUBLIC_KEY_FILE_SUFFIX);
        out.write("-----BEGIN RSA PUBLIC KEY-----\n");
        out.write(encoder.encodeToString(keyPair.getPublic().getEncoded()));
        out.write("\n-----END RSA PUBLIC KEY-----\n");
        out.close();

        return true;
    }

    /**
     * Read Public keys from a file and return a PublicKey instance
     * @param keyFilePath Path from where keys will be read
     * @return PublicKey instance
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey loadPublicKeyFromFile(String keyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // Read all the public key bytes
        byte[] bytes = FilesHelper.readFileBytes(keyFilePath);

        // Generate public key
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);
    }

    /**
     * Read Private keys from a file and return a PrivateKey instance
     * @param keyFilePath Path from where keys will be read
     * @return PrivateKey instance
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey loadPrivateKeyFromFile(String keyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // Read all the public key bytes
        byte[] bytes = FilesHelper.readFileBytes(keyFilePath);

        // Generate private key
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(ks);
    }


}
