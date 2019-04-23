package kdc.needhamSchroeder.exceptions;

public class InvalidChallangeReplyException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	
	public InvalidChallangeReplyException() {
		super();
	}
	
	public InvalidChallangeReplyException(String message) {
		super(message);
	}
	
}
