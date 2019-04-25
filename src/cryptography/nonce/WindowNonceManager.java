package cryptography.nonce;

import java.security.SecureRandom;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

import cryptography.CryptographyUtils;

public class WindowNonceManager implements NonceManager {

	private SecureRandom sr;
	private int windowSize;
	private Queue<Long> nonces;
	
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
