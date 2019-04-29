package secureSocket.secureMessages;
public interface Payload {
	
	public byte getPayloadType();
		
	public byte[] serialize();
	
	public short size();

	long[] getTimestamps();

	void setTimestamps(long t1, long t2);

}
