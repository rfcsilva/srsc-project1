package Utils;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

public class Utils {

	public static long getNonce() throws NoSuchAlgorithmException {
		
		java.security.SecureRandom sr;

		//TODO: Change Algorithm
		sr = java.security.SecureRandom.getInstance("sha1PRNG");

		int size = Long.BYTES + 1;
		byte[] tmp = new byte[size];
		sr.nextBytes(tmp);

		ByteBuffer buffer = ByteBuffer.wrap(tmp);
		return buffer.getLong();

	}
}
