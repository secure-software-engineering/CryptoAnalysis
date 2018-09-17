package issue85.original;

import java.io.IOException;
import java.io.InputStream;

public class Main {
	public void main(String...args) throws IOException {
		InputStream inputStream = null;
		MsgDigest.of(inputStream);
	}	
}
