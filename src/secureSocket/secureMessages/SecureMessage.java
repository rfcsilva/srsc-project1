package secureSocket.secureMessages;

public interface SecureMessage {
	
	byte getVersionRelease();
	
	byte getPayloadType();
	
	short getPayloadSize();
	
	byte getPayload();
	
	byte[] getBytes();
	
}
