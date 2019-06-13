package com.github.aaitor.crypto.utils.helpers;

import org.bouncycastle.util.encoders.Hex;
import org.web3j.utils.Numeric;

import java.io.UnsupportedEncodingException;

public abstract class EncodingHelper {


    /**
     * Encodes a String in Hex
     *
     * @param input string to encode
     * @return Hex string
     * @throws UnsupportedEncodingException Error encoding to Hex
     */
    public static String encodeToHex(String input) throws UnsupportedEncodingException {
        return Hex.toHexString(input.getBytes("UTF-8"));
    }

    /**
     * Encodes a Hex String in a byte array
     *
     * @param input hex string to encode
     * @return byte[]
     * @throws UnsupportedEncodingException Error encoding to byte array
     */
    public static byte[] hexStringToBytes(String input) {
        return Numeric.hexStringToByteArray(input);
    }

    /**
     * Convert a string to hex and after to a byte array
     *
     * @param input string to encode
     * @return byte[]
     * @throws UnsupportedEncodingException Error encoding to byte array
     */
    public static byte[] stringToBytes(String input) throws UnsupportedEncodingException {
        return hexStringToBytes(encodeToHex(input));
    }



}
