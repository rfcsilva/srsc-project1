package secureSocket.exceptions;

public class InvalidMacException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public InvalidMacException() {
		super();
	}

	public InvalidMacException(String message) {
		super(message);
	}

}
