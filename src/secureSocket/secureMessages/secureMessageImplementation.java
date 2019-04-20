package secureSocket.secureMessages;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class secureMessageImplementation implements SecureMessage {
	
	private byte versionRelease, payloadType;
	private short payloadSize;
	private Payload payload;
	
	public secureMessageImplementation(byte versionRelease, byte payloadType, short payloadSize, Payload payload) {
		
		this.versionRelease = versionRelease;
		this.payloadType = payloadType;
		this.payloadSize = payloadSize;
		this.payload = payload;
		
	}
	
	public secureMessageImplementation(byte[] rawContent) throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.write(versionRelease);
		dataOut.write(payloadType);
		dataOut.writeShort(payloadSize);
		byte[] rawPayload = new byte[ payloadSize ];
		dataOut.write(rawPayload, 0, payloadSize);
		payload = PayloadFactory.buildPayload(payloadType, rawPayload );
		
		dataOut.flush();
		byteOut.flush();
		
	}
	
	
	@Override
	public byte getVersionRelease() {

		return versionRelease;
	}

	@Override
	public byte getPayloadType() {
	
		return payloadType;
	}

	@Override
	public short getPayloadSize() {
		
		return payloadSize;
	}

	@Override
	public byte getPayload() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return null;
	}
		
}
