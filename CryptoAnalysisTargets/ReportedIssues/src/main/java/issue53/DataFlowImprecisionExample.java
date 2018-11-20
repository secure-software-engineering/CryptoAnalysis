package issue53;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class DataFlowImprecisionExample {
	static String field = "AES";

	public static void main() throws GeneralSecurityException{
//		cipherUsageExampleUsingFieldWithStringConstant();
	}
	public static void cipherUsageExampleUsingFieldWithStringConstant() throws GeneralSecurityException {
		SecretKey key = getKey();
		Cipher cCipher = Cipher.getInstance(field);
		cCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encText = cCipher.doFinal("".getBytes());
	}

	/**
	 * Separate method to get key to ensure it is equal across all tests
	 */
	public static SecretKey getKey() throws NoSuchAlgorithmException {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(128);
		return keygen.generateKey();
	}

    public static void cipherUsageExampleUsingStringConstantAsVariableInKeyGenerator() throws GeneralSecurityException {
        String trans = "AES";
        KeyGenerator keygen = KeyGenerator.getInstance(trans);
        keygen.init(128);
        SecretKey key = keygen.generateKey();
        Cipher cCipher = Cipher.getInstance(trans);
        cCipher.init(1, key);
        byte[] encText = cCipher.doFinal("".getBytes());
    }


}