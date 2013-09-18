/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.muddlemail.MuddleClient.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

import com.muddlemail.MuddleClient.config.Config;

/**
 *
 * @author matt
 */
public class CryptoFacade {
///////////////////////////////////////////////////////////////////////////////
// Class Variables ////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
    private static final String CIPHER_KEYBASED_ALGO = "RSA";
    private static final String CIPHER_SYMMETRIC_ALGO_SHORT = "AES";
    private static final String CIPHER_SYMMETRIC_ALGO_LONG = "AES/CBC/PKCS5Padding";
    private static final int CIPHER_SYMMETRIC_KEYSIZE = 256;
    private static final int CIPHER_KEYBASED_KEYSIZE = 4096;
    private static final String HASH_ALGO = "SHA-256";
    private static final int PASSWORD_SALT_BYTES = 16;
    private static final int PASSWORD_ITERATONS = 65536;
    private static final String PASSWORD_DERIVE_METHOD = "PBKDF2WithHmacSHA1";

///////////////////////////////////////////////////////////////////////////////
// Methods ////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
    
    ////////////////////////////////////////////////////////////////////////////
    // Hashing Methods                                                        //
    ////////////////////////////////////////////////////////////////////////////
    /**
     * This method will calculate a hash with the muddlemail implemented
     * algorithm.
     *
     * @param data
     * @return byte[] hash
     * @throws JvmCryptoException
     */
    public static byte[] calcHash(byte[] data) throws JvmCryptoException {
    	
        MessageDigest hash = null;

        try {
            hash = MessageDigest.getInstance(HASH_ALGO);
        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        }

        return hash.digest(data);
    }

    /**
     * This method will calculate a hash with the muddlemail implemented
     * algorithm.
     *
     * @param data
     * @return String hex-encoded-hash
     * @throws JvmCryptoException
     */
    public static String calcHashString(byte[] data) throws JvmCryptoException {
        return Hex.encodeHexString(calcHash(data));
    }

    /**
     * This method will calculate a hash with the muddlemail implemented
     * algorithm. The input string's hash will be calculated as APP_CHARSET
     * chars. The APP_CHARSET for muddlemail is set to UTF-8.
     *
     * @param string
     * @return String hex-encoded-hash
     * @throws JvmCryptoException
     */
    public static String calcHashString(String inString) 
    throws JvmCryptoException 
    {
        byte[] inData = inString.getBytes(Config.getApplicationCharEnc());
        return calcHashString(inData);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key Generation Methods                                                 //
    ////////////////////////////////////////////////////////////////////////////
    /**
     * Create a symmetric-key with the muddlemail implementation.
     *
     * @return SecretKey random-symmetric-key
     * @throws JvmCryptoException
     */
    public static SecretKey genSymmetricKey() throws JvmCryptoException {
        
    	KeyGenerator keyGen = null;

        try {
            keyGen = KeyGenerator.getInstance(CIPHER_SYMMETRIC_ALGO_SHORT);
        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        }
        keyGen.init(CIPHER_SYMMETRIC_KEYSIZE);

        return keyGen.generateKey();
    }

    /**
     * Create a symmetric-key with the muddlemail implementation.
     *
     * @param password
     * @param salt
     * @return
     * @throws JvmCryptoException
     */
    public static SecretKey genSymmetricKey(char[] password, byte[] salt) 
    throws JvmCryptoException 
    {
        SecretKey keySecret = null;
        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(PASSWORD_DERIVE_METHOD);
            KeySpec spec = new PBEKeySpec(
                    password, salt, PASSWORD_ITERATONS, CIPHER_SYMMETRIC_KEYSIZE);
            SecretKey keyTemp = factory.generateSecret(spec);
            keySecret = new SecretKeySpec(
                    keyTemp.getEncoded(), CIPHER_SYMMETRIC_ALGO_SHORT);
        } catch (InvalidKeySpecException ex) {
            throw new JvmCryptoException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        }

        return keySecret;
    }

    /**
     * Generate a key-pair with the muddlemail implemented asymmetric algorithm.
     *
     * @return KeyPair key-pair
     * @throws JvmCryptoException
     */
    public static KeyPair genAsymmetricKeyPair() throws JvmCryptoException {
        KeyPairGenerator kpg = null;

        try {
            kpg = KeyPairGenerator.getInstance(CIPHER_KEYBASED_ALGO);
            kpg.initialize(CIPHER_KEYBASED_KEYSIZE);
        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        }

        return kpg.genKeyPair();
    }

    /**
     * Generate a random alpha-numeric. All characters are lower-case.
     *
     * @param count
     * @return String lower-case-alpha-numeric
     */
    public static String genRandomAlphaNumeric(int count) {
        char[] validChars = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
            'x', 'y', 'z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
        String alphaNumeric = "";
        SecureRandom rand = new SecureRandom();

        for (int i = 0; i < count; i++) {
            int randIndex = rand.nextInt(validChars.length);
            String randChar = String.valueOf(validChars[randIndex]);
            alphaNumeric = alphaNumeric + randChar;
        }

        return alphaNumeric;
    }

    /**
     * You give me the number of bytes of random data you want and I will create
     * it.
     *
     * @param bytesOfRandData
     * @return
     */
    public static byte[] genRandomData(int bytesOfRandData) {
        byte[] randData = new byte[bytesOfRandData];
        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(randData);
        return randData;
    }

    /**
     * You give me the number of bytes of random data you want and I will create
     * it, I will then Hex encode it into a string.
     *
     * @param bytesOfRandData
     * @return
     */
    public static String genRandomDataHex(int bytesOfRandData) {
        return Hex.encodeHexString(genRandomData(bytesOfRandData));
    }

    /**
     * You give me the max integer you can handle, and I will generate a random
     * number between 0 and your max.
     *
     * @param maxValue
     * @return random-integer-between-zero-and-your-max
     */
    public static int genRandomIntegerBounded(int maxValue) {
        SecureRandom rand = new SecureRandom();
        return rand.nextInt(maxValue);
    }

    /**
     * Generate a random password salt with the muddlemail implementation.
     *
     * @return
     */
    public static byte[] genSalt() {
        return genRandomData(PASSWORD_SALT_BYTES);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Encryption Methods                                                     //
    ////////////////////////////////////////////////////////////////////////////
    /**
     * This method will encrypt your data with the muddlemail implemented
     * Asymmetric algorithm.
     *
     * @param plainData
     * @param key
     * @return byte[] encrypted-data
     * @throws JvmCryptoException
     * @throws InvalidKeyException
     */
    public static byte[] encryptWithAsymmetric(byte[] plainData, Key key) 
    throws JvmCryptoException, InvalidKeyException 
    {
        byte[] cipherData;
        
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_KEYBASED_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherData = cipher.doFinal(plainData);
        } catch (IllegalBlockSizeException ex) {
            throw new JvmCryptoException(ex);
        } catch (BadPaddingException ex) {
            throw new JvmCryptoException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        } catch (NoSuchPaddingException ex) {
            throw new JvmCryptoException(ex);
        }

        return cipherData;
    }

    /**
     * This method will encrypt your data with the muddlemail implemented
     * Asymmetric algorithm.
     *
     * @param plainData
     * @param keySecret
     * @return AesCbcData encrypted-data
     * @throws JvmCryptoException
     * @throws InvalidKeyException
     */
    public static AesCbcData encryptWithSymmetric(
    	byte[] plainData, 
    	SecretKey keySecret) 
    throws JvmCryptoException, InvalidKeyException 
    {
        byte[] cipherData;
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance(CIPHER_SYMMETRIC_ALGO_LONG);
            cipher.init(Cipher.ENCRYPT_MODE, keySecret);
            cipherData = cipher.doFinal(plainData);

        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        } catch (NoSuchPaddingException ex) {
            throw new JvmCryptoException(ex);
        } catch (IllegalBlockSizeException ex) {
            throw new JvmCryptoException(ex);
        } catch (BadPaddingException ex) {
            throw new JvmCryptoException(ex);
        }

        return new AesCbcData(cipherData, cipher.getIV());
    }

    /**
     * This method will encrypt your data with the muddlemail implemented
     * Asymmetric algorithm.
     *
     * @param plainData
     * @param keySecret
     * @return
     * @throws JvmCryptoException
     * @throws InvalidKeyException
     */
    public static AesCbcData encryptWithSymmetric(
            String plainData,
            SecretKey keySecret) 
    throws JvmCryptoException, InvalidKeyException
    {
        return encryptWithSymmetric(
        		plainData.getBytes(Config.getApplicationCharEnc()),
        		keySecret);
    }


    ////////////////////////////////////////////////////////////////////////////
    // Decryption Methods                                                     //
    ////////////////////////////////////////////////////////////////////////////
    /**
     * 
     * @param cipherData
     * @param key
     * @return
     * @throws InvalidKeyException
     * @throws JvmCryptoException
     */
    public static byte[] decryptWithAsymmetic(byte[] cipherData, Key key)
    throws InvalidKeyException, JvmCryptoException 
    {
        //
        byte[] plainData;

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_KEYBASED_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key);
            plainData = cipher.doFinal(cipherData);
        } catch (IllegalBlockSizeException ex) {
            throw new JvmCryptoException(ex);
        } catch (BadPaddingException ex) {
            throw new JvmCryptoException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        } catch (NoSuchPaddingException ex) {
            throw new JvmCryptoException(ex);
        }

        return plainData;
    }

    /**
     * 
     * @param cipherData
     * @param key
     * @return
     * @throws FailedToDecryptException
     * @throws JvmCryptoException
     */
    public static byte[] decryptWithSymmetric(
    	AesCbcData cipherData, 
    	SecretKey key)
    throws FailedToDecryptException, JvmCryptoException 
    {
        byte[] plainData;
        Cipher cipher;

        try {
            cipher = Cipher.getInstance(CIPHER_SYMMETRIC_ALGO_LONG);
            cipher.init(Cipher.DECRYPT_MODE, key,
                    new IvParameterSpec(cipherData.getIv()));
            plainData = cipher.doFinal(cipherData.getDataCipher());

        } catch (InvalidAlgorithmParameterException ex) {
            throw new FailedToDecryptException(ex);
        } catch (IllegalBlockSizeException ex) {
            throw new FailedToDecryptException(ex);
        } catch (BadPaddingException ex) {
            throw new FailedToDecryptException(ex);
        } catch (InvalidKeyException ex) {
            throw new FailedToDecryptException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new JvmCryptoException(ex);
        } catch (NoSuchPaddingException ex) {
            throw new JvmCryptoException(ex);
        }

        return plainData;
    }
    /**
     * 
     * @param cipherData
     * @param key
     * @return
     * @throws FailedToDecryptException
     * @throws JvmCryptoException
     */
    public static String decryptWithSymmetricToString(
    	AesCbcData cipherData, 
    	SecretKey key)
    throws FailedToDecryptException, JvmCryptoException 
    {
        return new String(
        		decryptWithSymmetric(cipherData, key),
                Config.getApplicationCharEnc());
    }
    
    
    ////////////////////////////////////////////////////////////////////////////
    // Digital Signature Methods                                              //
    ////////////////////////////////////////////////////////////////////////////

    /**
     * This method will produce a digital signature of your data. GIVE THIS
     * METHOD YOUR PRIVATE-KEY!!!
     *
     * @param inData
     * @param keySecret
     * @return digital-signature-of-your-data
     * @throws JvmCryptoException
     * @throws InvalidKeyException
     */
    public static byte[] genSignature(
        byte[] inData, 
        PrivateKey keySecret) 
    throws JvmCryptoException, InvalidKeyException 
    {
        byte[] hash = calcHash(inData);
        
        return encryptWithAsymmetric(hash, keySecret);
    }

    /**
     * This method will produce a digital signature of your data. GIVE THIS
     * METHOD YOUR PRIVATE-KEY!!!
     *
     * @param inData
     * @param keySecret
     * @return
     * @throws JvmCryptoException
     * @throws InvalidKeyException
     */
    public static byte[] genSignature(
    	String inData, 
    	PrivateKey keySecret) 
    throws JvmCryptoException, InvalidKeyException 
    {
        return genSignature(
        		inData.getBytes(Config.getApplicationCharEnc()), 
        		keySecret);
    }
    
    /**
     * 
     * @param signature
     * @param inData
     * @param keyPublic
     * @return
     * @throws JvmCryptoException
     * @throws InvalidKeyException
     */
    public static boolean checkSignature(
    	byte[] signature, 
    	byte[] inData, 
    	PublicKey keyPublic) 
    throws JvmCryptoException, InvalidKeyException 
    {
        byte[] myCalculatedHash = calcHash(inData);
        byte[] hashFromSignature = decryptWithAsymmetic(signature, keyPublic);

        if (Arrays.equals(myCalculatedHash, hashFromSignature)) {
            return true;
        }

        return false;
    }
}