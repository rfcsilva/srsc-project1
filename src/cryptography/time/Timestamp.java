package cryptography.time;

public class Timestamp {

	private static long expiration_time = 30*1000*1000*1000; // 30 segundos
	
	public synchronized void setExpirationTime(long t) {
		expiration_time = t;
	}
	
	public synchronized long[] getTimeInterval() {
		long t1 = System.currentTimeMillis();
		long t2 = t1 + expiration_time;
		return new long[] {t1, t2};
	}
	
	
	
}
