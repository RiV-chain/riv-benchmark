package org.riv;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;


public class HashUtil {

    private static final Provider CRYPTO_PROVIDER;

    private static final String HASH_256_ALGORITHM_NAME;
    private static final String HASH_512_ALGORITHM_NAME;
    
    static {
        Security.addProvider(SpongyCastleProvider.getInstance());
        CRYPTO_PROVIDER = Security.getProvider("SC");
        HASH_256_ALGORITHM_NAME = "RIV-KECCAK-256";
        HASH_512_ALGORITHM_NAME = "RIV-KECCAK-256";
    }
    
    public static MessageDigest getDigest() throws NoSuchAlgorithmException {
    	return MessageDigest.getInstance(HASH_256_ALGORITHM_NAME, CRYPTO_PROVIDER);
    }
    

}