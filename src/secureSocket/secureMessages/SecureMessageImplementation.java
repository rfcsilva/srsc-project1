package secureSocket.secureMessages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import cryptography.nonce.NonceManager;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.exceptions.ReplayedNonceException;
import util.Utils;

public class SecureMessageImplementation implements SecureMessage {
	
	private static final byte VERSION_RELEASE = 0x01;
	private static final byte SEPARATOR = 0x00;
	private byte versionRelease, payloadType;
	private short payloadSize;
	private Payload payload;
	
	public SecureMessageImplementation(Payload payload) {
		this(VERSION_RELEASE, payload);
	}
	
	public SecureMessageImplementation(byte versionRelease, Payload payload) {
		this.versionRelease = versionRelease;
		payloadType = payload.getPayloadType();
		this.payloadSize = payload.size();
		this.payload = payload;
	}
	
	public SecureMessageImplementation(byte[] rawContent, Cryptography cryptoManager, NonceManager nonceManager) throws IOException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidMacException, ReplayedNonceException, InvalidPayloadTypeException, BrokenBarrierException {
		
		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawContent);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		versionRelease = dataIn.readByte();
		dataIn.readByte();
		payloadType = dataIn.readByte();
		dataIn.readByte();
		payloadSize = dataIn.readShort();
		byte[] rawPayload = new byte[ payloadSize ];
		dataIn.read(rawPayload, 0, payloadSize);
		payload = PayloadFactory.buildPayload(payloadType, rawPayload, cryptoManager, nonceManager );
		
		dataIn.close();
		byteIn.close();
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
	public byte[] serialize() throws IOException {
		
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
		byte[] messageBytes = Utils.concat(headerBytes, payloadBytes);

		dataOut.close();
		byteOut.close();
		
		return messageBytes;
	}
}
