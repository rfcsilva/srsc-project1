package secureSocket.secureMessages;

public class PayloadFactory {

	protected static final byte TYPE1 = 0x01;

	public static Payload buildPayload(byte payloadType, byte[] rawPayload) {

		switch(payloadType ) {

		case TYPE1:
			return DefaultPayload.deserialize(rawPayload);		
		default: 
			return null;
		}
	}



}
