package secureSocket.exceptions;

public class ReplayedNonceException extends Exception {

	private static final long serialVersionUID = 1L;

	public ReplayedNonceException() {
		super();
	}

	public ReplayedNonceException(String message) {
		super(message);
		
	}
}
