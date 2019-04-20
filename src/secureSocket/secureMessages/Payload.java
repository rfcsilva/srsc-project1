package secureSocket.secureMessages;
public interface Payload {
	
	public byte getPayloadType();
		
	public byte[] serialize();
	
	public short size();
	
	public byte[] getMessage();
}
