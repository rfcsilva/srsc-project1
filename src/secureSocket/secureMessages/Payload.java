package secureSocket.secureMessages;
public interface Payload {
	
	public byte payloadType();
	
	public byte[] serialize();
	
	public int size();
	
}
