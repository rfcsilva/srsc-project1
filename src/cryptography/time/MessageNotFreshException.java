package cryptography.time;

public class MessageNotFreshException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	
	public MessageNotFreshException() {
		super();
	}
	
	public MessageNotFreshException(String message) {
		super(message);
	}
	
}
