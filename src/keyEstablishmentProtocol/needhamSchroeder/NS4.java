package keyEstablishmentProtocol.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.secureMessages.AbstractPayload;
import secureSocket.secureMessages.Payload;
import util.Utils;

public class NS4 extends AbstractPayload implements Payload {

	private static final String INVALID_OUTTER_MAC = "Invalid Outter Mac";

	public static final byte TYPE = 0x14;
	
	private long nb;
	private byte[] message;
	private byte[] cipherText;
	private byte[] outermac;
	
	public NS4(long nb, long t1, long t2, Cryptography cryptoManager) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		super(t1, t2);
		this.nb = nb;
		message = serialize(nb, t1, t2);
		cipherText = cryptoManager.encrypt(message);
		outermac = cryptoManager.computeOuterMac(cipherText);
	}	
	
	private NS4(long nb, byte[] cipherText, long t1, long t2, byte[] outermac) throws IOException {
		super(t1,t2);
		this.nb = nb;
		this.message = serialize(nb, t1 ,t2);
		this.cipherText = cipherText;
		this.outermac = outermac;
	}

	private byte[] serialize(long nb, long t1, long t2) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.writeLong(nb);
		
		dataOut.writeLong(t1);
		dataOut.writeLong(t2);
		
		dataOut.flush();
		byteOut.flush();

		byte[] data = byteOut.toByteArray();
		
		
		dataOut.close();
		byteOut.close();
		
		return data;
	}

	@Override
	public byte getPayloadType() {
		return TYPE;
	}

	@Override
	public byte[] serialize() {
		return Utils.concat(cipherText, outermac);
	}

	@Override
	public short size() {
		return (short) (cipherText.length + outermac.length);
	}

	public static Payload deserialize(byte[] rawPayload, Cryptography cryptoManager) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidMacException {
		byte[][] messageParts = cryptoManager.splitOuterMac(rawPayload);		
		if (!cryptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException(INVALID_OUTTER_MAC);
		else {
			byte[] plainText = cryptoManager.decrypt(messageParts[0]);
			ByteArrayInputStream byteIn = new ByteArrayInputStream(plainText);

			DataInputStream dataIn = new DataInputStream(byteIn);

			long nb = dataIn.readLong();
			
			long t1 = dataIn.readLong();
			long t2 = dataIn.readLong();
			
			dataIn.close();
			byteIn.close();

			return new NS4(nb, messageParts[0], t1, t2, messageParts[1]);
		}
	}

	public long getNb() {
		return nb;
	}

	public byte[] getNb_bytes() {
		return message;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public byte[] getOutermac() {
		return outermac;
	}
}
