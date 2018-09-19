package issue66.issueTwo.simplified;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

public class SecurityUtils {
	/*
	 * Scenario regarding the analysis reporting two errors on the same object. 
	 * Two errors "RequiredPredicateError violating CrySL rule for Cipher: Third parameter was not properly preparedIV" 
	 * and "RequiredPredicateError violating CrySL rule for Cipher: Third parameter was not properly preparedGCM"
	 * were reported on the same object cipher in the method 
	 * byte[] init(javax.crypto.Cipher,int,java.security.Key,java.security.spec.AlgorithmParameterSpec).
	 * 
	 * Expected: If the second part of parameter for cipher.getInstance contains CBC then the analysis should report 
	 * "Third parameter was not properly preparedIV". Or if it is GCM then the analysis should report 
	 * "Third parameter was not properly preparedGCM".
	 * 
	 * Reason: Here, the value for getInstance is passed as commandline argument (or a config file making the 
	 * analysis imprecise) then the analysis executed all the rules in the specification and hence two 
	 * errors for the same object can be reported.*/
	
	private static byte[] init(Cipher cipher, int opmode, Key key, AlgorithmParameterSpec params)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		cipher.init(opmode, key, params);
		return cipher.getIV();
	}

	private static byte[] doInit(Cipher cipher, int opmode, Key key, IvParameterSpec params)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		return init(cipher, opmode, key, params);
	}

	private static byte[] doDecrypt(Cipher cipher, Key key, byte[] input) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		int blockSize = 10;
		byte[] bytes = new byte[(int) 10];
		byte[] iv = doInit(cipher, 2, key, blockSize > 0 ? new IvParameterSpec(bytes) : null);
		return cipher.doFinal(input, iv.length, input.length - iv.length);
	}
	
	public static byte[] decrypt(Cipher cipher, Key key, byte[] input, byte[] iv) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		return doDecrypt(cipher, key, input);
	}

}
