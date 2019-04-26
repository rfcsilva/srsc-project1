package util;

import java.net.InetSocketAddress;

public class Utils {

	/**
	 * Concatenates two byte arrays
	 * @param a first array
	 * @param b second array
	 * @return concatenation result
	 */
	public static byte[] concat  (byte[] a, byte[] b) {
		if (a == null) return b;
		if (b == null) return a;
		byte[] r = new byte[a.length+b.length];
		System.arraycopy(a, 0, r, 0, a.length);
		System.arraycopy(b, 0, r, a.length, b.length);
		return r;
	}

	public static byte[] unparse(String array) {
		if(array == null)
			return null;

		String aux = array.substring(1, array.length()-1);
		String s[] = aux.split(",");

		byte[] result = new byte[s.length];

		for(int i = 0; i < s.length; i++) {
			result[i] = (byte) Integer.parseInt(s[i].trim().replace("0x", ""), 16);
		}

		return result;
	}

	public static byte[] intToByteArray(int value) {
		return new byte[] {
				(byte)(value >>> 24),
				(byte)(value >>> 16),
				(byte)(value >>> 8),
				(byte)value};
	}

	public static InetSocketAddress unparseAddr(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
