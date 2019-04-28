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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import cryptography.nonce.NonceManager;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.exceptions.ReplayedNonceException;
import util.Utils;

public class ClearPayload extends AbstractPayload {

	public static final byte TYPE = 0x02;

	// Payload data
	private byte[] message;
	private byte[] payload;
	private byte[] outterMac;

	public ClearPayload(byte[] message, Cryptography criptoManager, NonceManager nonceManager, long t1, long t2)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		super(t1, t2);

		this.message = message;

		this.payload = buildPayload(t1, t2, message);

		this.outterMac = criptoManager.computeOuterMac(message);
	}

	private byte[] buildPayload(long t1, long t2, byte[] message) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(t1);
		dataOut.writeLong(t2);
		dataOut.writeInt(message.length);
		dataOut.write(message, 0, message.length);
		dataOut.flush();
		byteOut.flush();

		byte[] mp = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return mp;
	}

	private ClearPayload(byte[] payload, byte[] outterMac, byte[] message, long t1, long t2) {
		super(t1, t2);
		this.message = message;
		this.payload = payload;
		this.outterMac = outterMac;
	}

	public byte getPayloadType() {
		return TYPE;
	}

	public byte[] serialize() {
		return Utils.concat(this.payload, this.outterMac);
	}

	public short size() {
		return (short) (payload.length + outterMac.length);
	}

	public static ClearPayload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException {

		byte[][] messageParts = criptoManager.splitOuterMac(rawPayload);
		if (!criptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outter Mac");
		else {
			ByteArrayInputStream byteIn = new ByteArrayInputStream(messageParts[0]);
			DataInputStream dataIn = new DataInputStream(byteIn);

			long t1 = dataIn.readLong();
			long t2 = dataIn.readLong();
			int length = dataIn.readInt();
			byte[] msg = new byte[length];
			dataIn.read(msg, 0, length);

			dataIn.close();
			byteIn.close();

			ClearPayload payload = new ClearPayload(messageParts[0], messageParts[1], msg, t1, t2);
			return payload;
		}
	}

	public byte[] getOutterMac() {
		return outterMac;
	}
	
	public byte[] getMessage() {
		return message;
	}
}
