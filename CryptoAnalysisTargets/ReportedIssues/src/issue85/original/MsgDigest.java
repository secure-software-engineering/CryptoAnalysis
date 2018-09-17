package issue85.original;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MsgDigest {
	/*
	 * False Positive : Call to update is done inside for loop which converts to if and else statements in jimple. 
	 * So, there exists a path with out update call which is reported by analysis. If for loop is removed, analysis recognizes the update call.*/
	public static byte[] of(InputStream inputStream) throws IOException{
		MessageDigest md;
		try
		{
			md = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException nsae)
		{
			throw new AssertionError(nsae);
		}

		byte[] ba = new byte['c'];
		for (;;) //Problem with this line.
		{
			int n = inputStream.read(ba);
			if (n == -1) {
				break;
			}
			md.update(ba, 0, n);
		}
		byte[] result = md.digest();
		assert (result.length == 16);
		return result;
	}
}
