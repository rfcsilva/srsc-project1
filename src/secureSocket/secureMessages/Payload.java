public interface Payload {
	
	public static byte payloadType();
	
	public byte[] serialize();
	
	public int size();
}
