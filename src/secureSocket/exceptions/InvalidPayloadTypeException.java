package secureSocket.exceptions;

public class InvalidPayloadTypeException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public InvalidPayloadTypeException() {
		super();
	}
	
	public InvalidPayloadTypeException(String message) {
		super(message);
	}
	
}
