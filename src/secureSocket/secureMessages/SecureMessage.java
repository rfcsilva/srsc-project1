package secureSocket.secureMessages;

import java.io.IOException;

public interface SecureMessage {
	
	byte getVersionRelease();
	
	byte getPayloadType();
	
	short getPayloadSize();
	
	Payload getPayload();
	
	byte[] serialize() throws IOException;
	
}
