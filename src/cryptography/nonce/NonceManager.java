package cryptography.nonce;

public interface NonceManager {

	public long getNonce();
	
	public boolean verifyReplay(long nonce);
	
}
