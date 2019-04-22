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
	private long id;
	private long nonce;
	private byte[] message;
	private byte[] innerIntegrityProof;
	private byte[] cipherText;
	private byte[] outterMac;

	public NS1(long id, long nonce, byte[] message, Cryptography criptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.message = message;
		this.id = id;
		this.nonce = nonce;
		byte[] Mp = buildMp(id, nonce, message);

		// this.criptoService = criptoService;

		this.innerIntegrityProof = criptoManager.computeIntegrityProof(Mp);
		this.cipherText = criptoManager.encrypt(ArrayUtils.concat(Mp, this.innerIntegrityProof));
		this.outterMac = criptoManager.computeOuterMac(this.cipherText);
	}

	private NS1(long id, long nonce, byte[] message, byte[] ciphertext, byte[] innerMac, byte[] outterMac) {
		this.id = id;
		this.nonce = nonce;
		this.message = message;
		this.cipherText = ciphertext;
		this.innerIntegrityProof = innerMac;
		this.outterMac = outterMac;
	}

	private static byte[] buildMp(long id, long nonce, byte[] message) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(id);
		dataOut.writeLong(nonce);
		dataOut.write(message, 0, message.length);
		dataOut.flush();
		byteOut.flush();

		byte[] mp = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return mp;
	}

	public byte getPayloadType() {
		return TYPE;
	}

	public byte[] serialize() {
		return ArrayUtils.concat(this.cipherText, this.outterMac);
	}

	public short size() {
		return (short) (cipherText.length + outterMac.length);
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
