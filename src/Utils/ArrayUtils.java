package Utils;

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

}
