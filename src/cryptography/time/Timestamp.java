package cryptography.time;

public class Timestamp {

	private static long expiration_time = 30*1000; // 30 segundos
	private static long precision = 5; // 5 ms
	
	public static synchronized void setExpirationTime(long t) {
		expiration_time = t;
	}
	
	public static synchronized void setPrecison(long t) {
		precision = t;
	}
	
	public static synchronized long[] getTimeInterval() {
		long t1 = System.currentTimeMillis();
		long t2 = t1 + expiration_time;
		return new long[] {t1, t2};
	}
	
	public static boolean validateFreshness(long t1, long t2) throws UnsynchronizedClocksException, MessageNotFreshException {
		long t = System.currentTimeMillis();
		if(t < t1-precision) {
			throw new UnsynchronizedClocksException("Time of reception is earlier than time of sending!");
		} else if( t < t2+precision ) {
			return true;
		} else
			throw new MessageNotFreshException("Received message is not fresh!");
	}
	
}
