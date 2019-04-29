package cryptography.time;

public class UnsynchronizedClocksException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	
	public UnsynchronizedClocksException() {
		super();
	}
	
	public UnsynchronizedClocksException(String message) {
		super(message);
	}
	
}
