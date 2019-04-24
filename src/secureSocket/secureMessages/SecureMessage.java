package secureSocket.secureMessages;

import java.io.IOException;

public interface SecureMessage {
	
	public byte getVersionRelease();
	
	public byte getPayloadType();
	
	public short getPayloadSize();
	
	public Payload getPayload();
	
	public byte[] serialize() throws IOException;
	
}
