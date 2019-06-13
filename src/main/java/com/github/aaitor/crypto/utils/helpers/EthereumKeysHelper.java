package com.github.aaitor.crypto.utils.helpers;

import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;

import java.io.UnsupportedEncodingException;

public abstract class EthereumKeysHelper {

    public static Bip32ECKeyPair generateKeyPair(String seed) throws UnsupportedEncodingException {
        return generateKeyPair(EncodingHelper.stringToBytes(seed));
    }

    public static Bip32ECKeyPair generateKeyPair(byte[] seed) {
        return Bip32ECKeyPair.generateKeyPair(seed);
    }

    public static Credentials generateCredentials(ECKeyPair keyPair) {
        return Credentials.create(new ECKeyPair(keyPair.getPrivateKey(), keyPair.getPublicKey()));
    }
}
