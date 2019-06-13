package com.github.aaitor.crypto.utils.helpers;

import org.junit.Test;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.*;

public class EthereumKeysHelperTest {

    @Test
    public void generateKeyPair() throws UnsupportedEncodingException {
        String seed= "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";

        Bip32ECKeyPair keyPair = EthereumKeysHelper.generateKeyPair(seed);
        Bip32ECKeyPair sameKeyPair = EthereumKeysHelper.generateKeyPair(seed);
        Bip32ECKeyPair distinctKeyPair = EthereumKeysHelper.generateKeyPair(seed + "0");

        System.out.println("Private Key: " + keyPair.getPrivateKey());
        System.out.println("Public Key: " + keyPair.getPublicKey());

        assertEquals(0, keyPair.getPrivateKey().compareTo(sameKeyPair.getPrivateKey()));
        assertEquals(0, keyPair.getPublicKey().compareTo(sameKeyPair.getPublicKey()));

        assertNotEquals(0, keyPair.getPrivateKey().compareTo(distinctKeyPair.getPrivateKey()));
        assertNotEquals(0, keyPair.getPublicKey().compareTo(distinctKeyPair.getPublicKey()));

        Credentials credentials = EthereumKeysHelper.generateCredentials(keyPair);
        Credentials sameCredentials = EthereumKeysHelper.generateCredentials(sameKeyPair);
        Credentials distinctCredentials = EthereumKeysHelper.generateCredentials(distinctKeyPair);

        System.out.println("Address: " + credentials.getAddress());

        assertEquals(credentials.getAddress(), sameCredentials.getAddress());
        assertNotEquals(credentials.getAddress(), distinctCredentials.getAddress());

        String address= Numeric.prependHexPrefix(Keys.getAddress(keyPair));
        String sameAddress= Numeric.prependHexPrefix(Keys.getAddress(sameKeyPair));
        String distinctAddress= Numeric.prependHexPrefix(Keys.getAddress(distinctKeyPair));

        assertEquals(address, sameAddress);
        assertNotEquals(address, distinctAddress);
    }
}