// TODO : find better name for the class
public class DefaultPayload implements Payload {
	
	// TODO
	private ? id;
	private ? nonce;
	private byte[] message;
	private byte[] innerMac;
	// Guardar o ciphertext do anterior para poder comparar com o outterMac e ser calculado só 1x? Depois no serialize é só fazer get?
	private byte[] outterMac;
	
	public CipheredMessage() {
		// TODO
	}
	
	public static byte payloadType() {
		return 0x01;
	}
	
	public byte[] serialize() {
		// TODO
	}
	
	public int size() {
		// TODO
	}
}
