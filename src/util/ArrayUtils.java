package util;

import java.security.MessageDigest;

import org.bouncycastle.util.encoders.Hex;

public class ArrayUtils {
	
	/**
	 * Concatenates two byte arrays
	 * @param a first array
	 * @param b second array
	 * @return concatenation result
	 */
	public static byte[] concat  (byte[] a, byte[] b){
	    
		if (a == null) return b;
	    if (b == null) return a;
	    byte[] r = new byte[a.length+b.length];
	    System.arraycopy(a, 0, r, 0, a.length);
	    System.arraycopy(b, 0, r, a.length, b.length);
	    return r;
	}
	
	public static byte[] unparse(String array) {
		String aux = array.substring(1, array.length()-1);
		String s[] = aux.split(",");
		
		byte[] result = new byte[s.length];
		
		for(int i = 0; i < s.length; i++) {
			result[i] = (byte) Integer.parseInt(s[i].trim().replace("0x", ""), 16);
		}
		
		return result;
	}

}
