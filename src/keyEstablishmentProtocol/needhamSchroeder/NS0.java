package keyEstablishmentProtocol.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import secureSocket.exceptions.BrokenIntegrityException;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.exceptions.ReplayedNonceException;
import secureSocket.secureMessages.AbstractPayload;
import secureSocket.secureMessages.Payload;
import util.Utils;

public class NS0 extends AbstractPayload implements Payload {

	private static final String INVALID_OUTER_MAC = "Invalid Outer Mac";

	public static final byte TYPE = 0x10;

	// Payload data
	private int error_code;
	private String error_msg;
	private byte[] cipherText;
	private byte[] outerMac;

	public NS0(int error_code, String error_msg, long t1, long t2, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		super(t1,t2);
		
		this.error_code = error_code;
		this.error_msg = error_msg;

		this.cipherText = cryptoManager.encrypt(buildMessage(error_code, error_msg, t1, t2));

		this.outerMac = cryptoManager.computeOuterMac(this.cipherText);
	}
	
	private NS0(int error_code, String error_msg, byte[] cipherText, byte[] outerMac, long t1, long t2) {
		super(t1,t2);
		this.error_code = error_code;
		this.error_msg = error_msg;
		this.cipherText = cipherText;
		this.outerMac = outerMac;
	}

	private static byte[] buildMessage(int error_code, String error_msg, long t1, long t2) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.writeInt(error_code);
		dataOut.writeUTF(error_msg);
		
		dataOut.writeLong(t1);
		dataOut.writeLong(t2);
		
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
		return Utils.concat(this.cipherText, this.outerMac);
	}

	public short size() {
		return (short) (this.cipherText.length + this.outerMac.length);
	}

	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException, BrokenIntegrityException, NoSuchProviderException, UnkonwnIdException {

		byte[][] messageParts = criptoManager.splitOuterMac(rawPayload);
		if (!criptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException(INVALID_OUTER_MAC);
		else {
		
		ByteArrayInputStream byteIn = new ByteArrayInputStream(messageParts[0]);
		DataInputStream dataIn = new DataInputStream(byteIn);

		int error_code = dataIn.readInt();
		String error_msg = dataIn.readUTF();
		
		long t1 = dataIn.readLong();
		long t2 = dataIn.readLong();

		dataIn.close();
		byteIn.close();

		return new NS0(error_code, error_msg, messageParts[0], messageParts[1], t1, t2);
		}
	}	
	
	public int getErrorCode() {
		return error_code;
	}
	
	public String getErrorMessage() {
		return error_msg;
	}
	
}
