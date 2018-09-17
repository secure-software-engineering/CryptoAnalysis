package issue66.issueOne.simplified;

import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class SecUtils {
	/*
	 * If the function depth is more than 2 then analysis becomes imprecise. Here, the depth of the function call is 3 where 
	 * cipher.init is called.*/
	public static void init(Cipher cipher, int opmode, Key key) throws InvalidKeyException {
		int x = 1;
		cipher.init(opmode, key);
		int y = 10;
	}
	
	public static void doInit(Cipher cipher, int opmode, Key key) throws InvalidKeyException {
		init(cipher, opmode, key);
//		cipher.init(opmode, key);
	}

	public static void doDecrypt(Cipher cipher, Key key, byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		doInit(cipher, 2, key);
		cipher.doFinal(input);
	}
}
