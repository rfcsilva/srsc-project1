package secureSocket.secureMessages;
public interface Payload {
	
	public byte payloadType();
	
	//public Payload deserialize();
	
	public byte[] serialize();
	
	public int size();
	
}
