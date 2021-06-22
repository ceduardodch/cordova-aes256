package com.ideas2it.aes256;

import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

import shaded.org.apache.commons.codec.binary.Hex;

/**
 * This class used to perform AES encryption and decryption.
 */
public class AES256 extends CordovaPlugin {

    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int PBKDF2_ITERATION_COUNT = 1001;

    private static final Random RANDOM = new SecureRandom();

    @Override
    public boolean execute(final String action, final JSONArray args,  final CallbackContext callbackContext) throws JSONException {
        try {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        if (ENCRYPT.equalsIgnoreCase(action)) {
                            callbackContext.success(encrypt(secureKey, value, iv));
                        } else if (DECRYPT.equalsIgnoreCase(action)) {
                            String secureKey = args.getString(0);
                            String iv = args.getString(1);
                            String value = args.getString(2);
                            callbackContext.success(decrypt(secureKey, value, iv));
                        } 
                        } else {
                            callbackContext.error("Invalid method call");
                        }
                    } catch (Exception e) {
                        System.out.println("Error 1 occurred while performing " + action + " : " + e.getMessage());
                        callbackContext.error("Error 1 occurred while performing " + action);
                    }
                }
            });
        } catch (Exception e) {
            System.out.println("Error 2 occurred while performing " + action + " : " + e.getMessage());
            callbackContext.error("Error 2 occurred while performing " + action);
        }
        return  true;
    }

    /**
     * <p>
     * To perform the AES256 encryption
     * </p>
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256 encryption
     * @param value     A string which will be encrypted
     * @param iv        A 16 bytes string, which will used as initial vector for AES256 encryption
     * @return AES Encrypted string
     * @throws Exception
     */
    private String encrypt(String secureKey, String value, String iv) throws Exception {

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.decodeBase64(secureKey), "AES");
        GCMParameterSpec ivParameterSpec = new GCMParameterSpec(128, Base64.decodeBase64(iv.getBytes("UTF-8")));
        
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(value.getBytes());

        return Base64.encodeToString(encrypted, Base64.DEFAULT);

    }

    /**
     * <p>
     * To perform the AES256 decryption
     * </p>
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256 decryption
     * @param value     A 16 bytes string, which will used as initial vector for AES256 decryption
     * @param iv        An AES256 encrypted data which will be decrypted
     * @return AES Decrypted string
     * @throws Exception
     */
    private String decrypt(String secureKey, String value, String iv) throws Exception {
        byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] original = cipher.doFinal(Base64.decode(value, Base64.DEFAULT));

        return new String(original);
    }


    /**
     * <p>
     * This method used to generate the random salt
     * </p>
     *
     * @return
     */
    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }
}
