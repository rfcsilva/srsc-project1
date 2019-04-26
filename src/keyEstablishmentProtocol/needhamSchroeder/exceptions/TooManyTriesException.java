package keyEstablishmentProtocol.needhamSchroeder.exceptions;

public class TooManyTriesException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	
	public TooManyTriesException() {
		super();
	}
	
	public TooManyTriesException(String message) {
		super(message);
	}
	
}
