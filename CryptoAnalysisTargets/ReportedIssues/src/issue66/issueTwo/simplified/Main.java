package issue66.issueTwo.simplified;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {
	public void main(String...args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
//		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // Reports third parameter was not properly preparedGCM
//		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding"); // Reports third parameter was not properly preparedIV
		Cipher cipher = Cipher.getInstance(args[0]); // Reports both third parameter was not properly preparedGCM and preparedIV
		Key k = null;
		byte[] input = new byte[10];
		SecurityUtils.decrypt(cipher, k, input, input);
	}
}
