package secureSocket.secureMessages;
public interface Payload {
	
	public byte getPayloadType();
		
	public byte[] serialize();
	
	public short size();

	public long[] getTimestamps();
	
	public void setTimestamps(long t1, long t2);
	
}
