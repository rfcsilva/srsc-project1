package cryptography.nonce;

import java.security.SecureRandom;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

import util.CryptographyUtils;

public class WindowNonceManager implements NonceManager {

	private SecureRandom sr;
	private int windowSize;
	private Queue<Long> nonces;
	
	private static int default_window_size = 100;
	
	public static synchronized void setDefaultWindowSize(int size) {
		default_window_size = size;
	}
	
	public WindowNonceManager(SecureRandom sr) {
		this.sr = sr;
		this.windowSize = default_window_size;
		this.nonces = new ArrayBlockingQueue<Long>(windowSize);
	}
	
	public WindowNonceManager(int windowSize, SecureRandom sr) {
		this.sr = sr;
		this.windowSize = windowSize;
		this.nonces = new ArrayBlockingQueue<Long>(windowSize);
	}
	
	@Override
	public long generateNonce() {
		long nonce = 0L;
		do {
			nonce = CryptographyUtils.getNonce(sr);
		} while(registerNonce(nonce)); // While nonce was already used, generate a new one
		
		return nonce;
	}

	@Override
	public boolean verifyReplay(long nonce) {
		return nonces.contains(nonce);
	}

	@Override
	public boolean registerNonce(long nonce) {
		if( verifyReplay(nonce) ) {
			return true;
		} else {
			if(nonces.size() == windowSize) {
				nonces.poll();
			}
			nonces.add(nonce);
			return false;
		}
	}

}
