package cryptography.nonce;

public interface NonceManager {

	/**
	 * Generates a new nonce.
	 * @return the generated nonce
	 * */
	public long generateNonce();
	
	
	/**
	 * Verifies if @param nonce was replayed, but does not register it.
	 * @return true if replayed, false otherwise.
	 * */
	public boolean verifyReplay(long nonce);
	
	/**
	 * Verifies if @param nonce was replayed and registers it.
	 * @return true if replayed, false otherwise.
	 * */
	public boolean registerNonce(long nonce);
	
}
