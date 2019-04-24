package cryptography.nonce;

public class CounterNonceManager implements NonceManager {
	
	private long counter;
	private int step;
	
	public CounterNonceManager() {
		this.counter = 0;
		this.step = 1;
		System.out.println("Estou a ser criado pra crl");
	}

	public CounterNonceManager(long start) {
		this.counter = start;
		this.step = 1;
	}
	
	public CounterNonceManager(long start, int step) {
		this.counter = start;
		this.step = step;
	}
	
	@Override
	public long getNonce() {
		this.counter += step;
		return this.counter;
	}

	@Override
	public boolean verifyReplay(long nonce) {
		boolean replay = nonce <= counter;
		
		if(!replay) {
			counter = nonce;
		}
		
		return replay;
	}

}
