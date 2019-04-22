package kdc.needhamSchroeder;

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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import cryptography.CryptographyDoubleMac;
import secureSocket.exceptions.BrokenIntegrityException;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.exceptions.ReplayedNonceException;
import secureSocket.secureMessages.Payload;
import util.ArrayUtils;

// TODO : find better name for the class
public class NS1 implements Payload {

	public static final byte TYPE = 0x11;

	// Encryption support
	// private static Cryptography2 criptoService;

	// Payload data
	private byte[] a;
	private byte[] b;
	private long Na;
	private byte[] message;
	private byte[] outerMac;

	public NS1(byte[] a, byte[] b, long Na, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.a = a;
		this.b = b;
		this.Na = Na;
		
		this.message = buildMessage(a, b, Na);

		this.outerMac = cryptoManager.computeOuterMac(this.message);
	}

	private NS1(byte[] a, byte[] b, long Na, byte[] outerMac) {
		this.a = a;
		this.b = b;
		this.Na = Na;
		this.outerMac = outerMac;
	}

	private static byte[] buildMessage(byte[] a, byte[] b, long Na) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		//dataOut.writeInt(a.length);
		dataOut.write(a, 0, a.length);
		//dataOut.writeInt(b.length);
		dataOut.write(b, 0, b.length);
		dataOut.writeLong(Na);
		
		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return msg;
	}

	public byte getPayloadType() {
		return TYPE;
	}

	public byte[] serialize() {
		return ArrayUtils.concat(this.message, this.outerMac);
	}

	public short size() {
		return (short) (message.length + outerMac.length);
	}

	// TODO handle bad macs
	// TODO : retornar Payload ou DEfaultPayload?
	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException, BrokenIntegrityException {

		byte[][] messageParts = criptoManager.splitOuterMac(rawPayload);
		if (!criptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outter Mac");
		else {
			byte[] plainText = criptoManager.decrypt(messageParts[0]);
			byte[][] payloadParts = criptoManager.splitIntegrityProof(plainText);
			if (!criptoManager.validateIntegrityProof(payloadParts[0], payloadParts[1]))
					throw new BrokenIntegrityException("Invalid Inner Mac");
			else {
				ByteArrayInputStream byteIn = new ByteArrayInputStream(payloadParts[0]);
				DataInputStream dataIn = new DataInputStream(byteIn);

				long id = dataIn.readLong();
				long nonce = dataIn.readLong();
				
				int messageSize = payloadParts[0].length - 2 * Long.BYTES;
				byte[] message = new byte[messageSize];
				dataIn.read(message, 0, messageSize);

				NS1 payload = new NS1(id, nonce, message, messageParts[0], payloadParts[1], messageParts[1]);

				dataIn.close();
				byteIn.close();

				return payload;
			}
		}	
	}

	@Override
	public byte[] getMessage() {
		return message;
	}

	public long getId() {
		return id;
	}

	public long getNonce() {
		return nonce;
	}

	public byte[] getInnerMac() {
		return innerIntegrityProof;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public byte[] getOutterMac() {
		return outterMac;
	}
}
