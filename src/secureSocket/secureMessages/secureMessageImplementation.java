package secureSocket.secureMessages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import Utils.ArrayUtils;

public class secureMessageImplementation implements SecureMessage {
	
	private static final byte SEPARATOR = 0x00;
	private byte versionRelease, payloadType;
	private short payloadSize;
	private Payload payload;
	
	public secureMessageImplementation(byte versionRelease, Payload payload) {
		
		this.versionRelease = versionRelease;
		payloadType = payload.getPayloadType();
		this.payloadSize = payload.size();
		this.payload = payload;
		
	}
	
	//TODO payload may come null if type is invalid 
	public secureMessageImplementation(byte[] rawContent) throws IOException {
		
		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawContent);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		versionRelease = dataIn.readByte();
		payloadType = dataIn.readByte();
		payloadSize = dataIn.readShort();
		byte[] rawPayload = new byte[ payloadSize ];
		dataIn.read(rawPayload, 0, payloadSize);
		payload = PayloadFactory.buildPayload(payloadType, rawPayload );
		
		dataIn.close();
		byteIn.close();;
		
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
	public Payload getPayload() {
		
		return payload;
	}

	@Override
	public byte[] getBytes() throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.write(versionRelease);
		dataOut.write(SEPARATOR);
		dataOut.write(payloadType);
		dataOut.write(SEPARATOR);
		dataOut.writeShort(payloadSize);
		
		dataOut.flush();
		byteOut.flush();

		//retrieve header raw data
		byte[] headerBytes = byteOut.toByteArray();
		
		//retrieve payload raw data
		byte[] payloadBytes = payload.serialize();
		
		//Append both
		byte[] messageBytes = ArrayUtils.concat(headerBytes, payloadBytes);

		dataOut.close();
		byteOut.close();
		
		return messageBytes;
	}
		
}
