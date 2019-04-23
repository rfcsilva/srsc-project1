package kdc.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import cryptography.AbstractCryptography;
import cryptography.Cryptography;
import cryptography.CryptographyHash;
import cryptography.CryptographyUtils;
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
	private long na;
	private byte[] message;
	private byte[] outerMac;
	
	private Cryptography criptoManagerA;
	private Cryptography criptoManagerB;

	public NS1(byte[] a, byte[] b, long Na, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.a = a;
		this.b = b;
		this.na = Na;

		this.message = buildMessage(a, b, Na);

		this.outerMac = cryptoManager.computeOuterMac(message);
	}

	private NS1(byte[] a, byte[] b, long Na, byte[] outerMac, Cryptography criptoManagerA, Cryptography criptoManagerB) {
		this.a = a;
		this.b = b;
		this.na = Na;
		this.outerMac = outerMac;
		this.criptoManagerA = criptoManagerA;
		this.criptoManagerB= criptoManagerB;
	}

	private static byte[] buildMessage(byte[] a, byte[] b, long Na) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeInt(a.length);
		dataOut.write(a, 0, a.length);
		dataOut.writeInt(b.length);
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

		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawPayload);
		DataInputStream dataIn = new DataInputStream(byteIn);

		//read a
		int a_size = dataIn.readInt();
		byte[] a  = new byte[a_size];
		dataIn.read(a, 0, a_size);
		
		//read b
		int b_size = dataIn.readInt();
		byte[] b  = new byte[b_size];
		dataIn.read(b, 0, b_size);

		long Na = dataIn.readLong();

		dataIn.close();
		byteIn.close();
		
		// TODO: Isto não pode estar assim. Esta info deveria vir toda de fora
		KeyStore key_store = CryptographyUtils.loadKeyStrore("./configs/kdc/kdc-keystore.p12", "SRSC1819", "PKCS12");
		SecretKey kma = CryptographyUtils.getKey(key_store, "SRSC1819", "Km" + new String(a));
		Mac outerMacA = AbstractCryptography.buildMac("HMACSHA256", kma); // TODO: passar para CryptographyUtils
		SecretKey ka = CryptographyUtils.getKey(key_store, "SRSC1819", "K" + new String(a));
		byte[] iv = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
		Cipher encryptCipherA = AbstractCryptography.buildCipher("AES/CTR/PKCS5Padding", Cipher.ENCRYPT_MODE, ka, iv);
		Cipher decryptCipherA = AbstractCryptography.buildCipher("AES/CTR/PKCS5Padding", Cipher.DECRYPT_MODE, ka, iv);
		
		SecretKey kmb = CryptographyUtils.getKey(key_store, "SRSC1819", "Km" + new String(b));
		Mac outerMacB = AbstractCryptography.buildMac("HMACSHA256", kmb); // TODO: passar para CryptographyUtils
		SecretKey kb = CryptographyUtils.getKey(key_store, "SRSC1819", "K" + new String(b));
		Cipher encryptCipherB = AbstractCryptography.buildCipher("AES/CTR/PKCS5Padding", Cipher.ENCRYPT_MODE, kb, iv);
		Cipher decryptCipherB = AbstractCryptography.buildCipher("AES/CTR/PKCS5Padding", Cipher.DECRYPT_MODE, kb, iv);
		
		Cryptography criptoManagerA = new CryptographyHash(encryptCipherA, decryptCipherA, null, null, outerMacA);
		Cryptography criptoManagerB = new CryptographyHash(encryptCipherB, decryptCipherB, null, null, outerMacB);
		
		byte[][] messageParts = criptoManagerA.splitOuterMac(rawPayload);
		if (!criptoManagerA.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outter Mac");

		return new NS1(a, b, Na, messageParts[1], criptoManagerA, criptoManagerB); // Falta a msg
	}	
	
	public Cryptography getCryptoManagerA() {
		return this.criptoManagerA;
	}
	
	public Cryptography getCryptoManagerB() { // TODO: ter aqui o B ?
		return this.criptoManagerB;
	}

	@Override
	public byte[] getMessage() {
		return message;
	}
	
	public byte[] getA() {
		return a;
	}
	
	public byte[] getB() {
		return b;
	}
	
	public long getNa() {
		return na;
	}
	
}
