package secureSocket.secureMessages;

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

public class ClearPayload implements Payload {

	public static final byte TYPE = 0x02;

	// Payload data
	private byte[] message;
	private byte[] outterMac;

	public ClearPayload(byte[] message, Cryptography criptoManager, NonceManager nonceManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.message = message;

		this.outterMac = criptoManager.computeOuterMac(message);
	}

	private ClearPayload(byte[] message, byte[] outterMac) {
		this.message = message;
		this.outterMac = outterMac;
	}

	public byte getPayloadType() {
		return TYPE;
	}

	public byte[] serialize() {
		return Utils.concat(this.message, this.outterMac);
	}

	public short size() {
		return (short) (message.length + outterMac.length);
	}

	public static ClearPayload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException {

		byte[][] messageParts = criptoManager.splitOuterMac(rawPayload);
		if (!criptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outter Mac");
		else {
				ClearPayload payload = new ClearPayload(messageParts[0], messageParts[1]);
				return payload;
			}
	}

	public byte[] getOutterMac() {
		return outterMac;
	}
}
