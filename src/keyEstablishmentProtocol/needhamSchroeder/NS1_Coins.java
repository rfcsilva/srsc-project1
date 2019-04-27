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
import cryptography.CryptographyDoubleMac;
import keyEstablishmentProtocol.Transation;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.WrongCryptoManagerException;
import secureSocket.exceptions.BrokenIntegrityException;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.exceptions.ReplayedNonceException;
import secureSocket.secureMessages.Payload;
import util.Utils;

public class NS1_Coins implements Payload {

	private static final String MUST_USED_A_DOUBLE_MAC_CRYPTO_MANAGER = "Must used a Double MAC CryptoManager";
	private static final String INVALID_OUTER_MAC = "Invalid Outer Mac";


	public static final byte TYPE = 0x16;

	//A || {A, B, Na, Args, InnerMac_Ka}ka || outerMac_Kma


	// Payload data
	private Transation tns;
	private byte[] cipherText;
	private byte[] outerMac;
	private byte[] message;

	private CryptographyDoubleMac criptoManagerA;
	private CryptographyDoubleMac criptoManagerB;

	public NS1_Coins(String a, String b, long Na, String[] arguments, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException, WrongCryptoManagerException {

		if( !(cryptoManager instanceof CryptographyDoubleMac) ) 
			throw new WrongCryptoManagerException(MUST_USED_A_DOUBLE_MAC_CRYPTO_MANAGER);

		byte[] msg = buildMessage(a, b, Na, serializeArgs(arguments));
		byte[] innerMac = cryptoManager.computeIntegrityProof(msg);

		tns = new Transation(a, b, Na, arguments, innerMac);

		this.cipherText = cryptoManager.encrypt(tns.serialize());

		this.outerMac = cryptoManager.computeOuterMac(this.cipherText);

		this.message = serializeFinnal(a, Utils.concat(cipherText, outerMac));
	}

	private NS1_Coins(Transation tns, byte[] cipherText, byte[] outerMac, byte[] message, CryptographyDoubleMac criptoManagerA, CryptographyDoubleMac criptoManagerB) {

		this.tns = tns;
		this.cipherText = cipherText;
		this.outerMac = outerMac;
		this.message = message;
		this.criptoManagerA = criptoManagerA;
		this.criptoManagerB = criptoManagerB;
	}

	private byte[] serializeFinnal(String id, byte[] message) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(id);
		dataOut.writeInt(message.length);
		dataOut.write(message, 0, message.length);

		dataOut.flush();
		byteOut.flush();

		byte[] data = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return data;
	}

	private byte[] serializeArgs(String[] arguments) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeInt(arguments.length);
		for(int i = 0; i < arguments.length; i++) {
			dataOut.writeUTF(arguments[i]);
		}

		dataOut.flush();
		byteOut.flush();

		byte[] data = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return data;
	}

	private static byte[] buildMessage(String a, String b, long Na, byte[] args) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(a);
		dataOut.writeUTF(b);

		dataOut.writeLong(Na);

		dataOut.writeInt(args.length);
		dataOut.write(args, 0, args.length);

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
		return message;
	}

	public short size() {
		return (short) (message.length);
	}

	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException, BrokenIntegrityException, NoSuchProviderException, UnkonwnIdException {

		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawPayload);
		DataInputStream dataIn = new DataInputStream(byteIn);

		String a = dataIn.readUTF();
		int lenght = dataIn.readInt();
		byte[] cipherWithMac = new byte[lenght];
		dataIn.read(cipherWithMac, 0, lenght);

		dataIn.close();
		byteIn.close();

		CryptographyDoubleMac criptoManagerA = ((CryptographyNS) criptoManager).getCryptographyFromId(a);

		byte[][] messageParts = criptoManagerA.splitOuterMac(cipherWithMac);
		if (!criptoManagerA.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException(INVALID_OUTER_MAC);
		else {
			byte[] clearText = criptoManagerA.decrypt(messageParts[0]);
			Transation tsn = Transation.deserialize(criptoManagerA, clearText);

			CryptographyDoubleMac criptoManagerB = ((CryptographyNS) criptoManager).getCryptographyFromId(tsn.getB());

			return new NS1_Coins(tsn, messageParts[0], messageParts[1], cipherWithMac, criptoManagerA, criptoManagerB);
		}

	}	

	public CryptographyDoubleMac getCryptoManagerA() {
		return this.criptoManagerA;
	}

	public CryptographyDoubleMac getCryptoManagerB() {
		return this.criptoManagerB;
	}

	public String getA() {
		return tns.getA();
	}

	public String getB() {
		return tns.getB();
	}

	public long getNa() {
		return tns.getNa();
	}

	public String[] getArgs() {
		return tns.getArgs();
	}

}
