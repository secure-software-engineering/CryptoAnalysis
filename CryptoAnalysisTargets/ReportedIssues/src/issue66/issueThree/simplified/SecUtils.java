package issue66.issueThree.simplified;

import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class SecUtils {
	/*
	 * False Positive: Forbidden error is shown for the cipher.init(int, key) in init function.
	 * 
	 * Expected: If the algorithm passed to cipher.getInstance is of type contains CBC then the
	 * analysis should report ForbiddenError.
	 * 
	 * Reason: Here, the value for getInstance is passed as commandline argument (or a config file making the 
	 * analysis imprecise) then the analysis executed all the rules in the specification and hence
	 * ForbiddenError is being reported. */
	public static void init(Cipher cipher, int opmode, Key key) throws InvalidKeyException {
		cipher.init(opmode, key);
	}
	
	public static void doInit(Cipher cipher, int opmode, Key key) throws InvalidKeyException {
		init(cipher, opmode, key);
	}

	public static void doDecrypt(Cipher cipher, Key key, byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		doInit(cipher, 2, key);
		cipher.doFinal(input);
	}
}
