package secureSocket.secureMessages;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

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
	
	public secureMessageImplementation(byte[] rawContent) {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.write(versionRelease);
		dataOut.write(payloadType);
		dataOut.writeShort(payloadSize);
		dataOut.write(message, 0, message.length);
		dataOut.flush();
		byteOut.flush();
		
	}
	
	
	@Override
	public byte getVersionRelease() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public byte getPayloadType() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public short getPayloadSize() {
		// TODO Auto-generated method stub
		return 0;
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
