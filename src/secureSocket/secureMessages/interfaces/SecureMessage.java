package secureSocket.secureMessages.interfaces;

public interface SecureMessage {
	
	byte getVersionRelease();
	
	byte getPayloadType();
	
	short getPayloadSize();
	
	byte getPayload();
	
}
