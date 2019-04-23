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
public class NS3 implements Payload { // A -> B : {Nc, A, B, Ks }KB

	public static final byte TYPE = 0x13;

	// Payload data
	long Nc;
	byte[] a;
	byte[] b;
	byte[] Ks;
	private byte[] ticket;
	private byte[] outerMac;
	
	//private Cryptography criptoManager;

	public NS3(byte[] ticket, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.ticket = ticket;

		this.outerMac = cryptoManager.computeOuterMac(ticket);
	}

	private NS3(long Nc, byte[] a, byte[] b, byte[] Ks, byte[] ticket, byte[] outerMac/*, Cryptography criptoManager*/) {
		this.Nc = Nc;
		this.a = a;
		this.b = b;
		this.Ks = Ks;
		this.ticket = ticket;
		this.outerMac = outerMac;
		//this.criptoManager = criptoManager;
	}

	public byte getPayloadType() {
		return TYPE;
	}

	public byte[] serialize() {
		return ArrayUtils.concat(this.ticket, this.outerMac);
	}

	public short size() {
		return (short) (ticket.length + outerMac.length);
	}

	// TODO handle bad macs
	// TODO : retornar Payload ou DEfaultPayload?
	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException, BrokenIntegrityException {

		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawPayload);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		// Separar o MAC -> como? Não sabemos o tipo de mac nem o seu length nem o lenght do ticket

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
		Cipher cipherA = AbstractCryptography.buildCipher("AES/CTR/PKCS5Padding", Cipher.DECRYPT_MODE, ka, iv);
		
		SecretKey kmb = CryptographyUtils.getKey(key_store, "SRSC1819", "Km" + new String(b));
		Mac outerMacB = AbstractCryptography.buildMac("HMACSHA256", kmb); // TODO: passar para CryptographyUtils
		SecretKey kb = CryptographyUtils.getKey(key_store, "SRSC1819", "K" + new String(b));
		Cipher cipherB = AbstractCryptography.buildCipher("AES/CTR/PKCS5Padding", Cipher.DECRYPT_MODE, kb, iv);
		
		Cryptography criptoManagerA = new CryptographyHash(cipherA, null, outerMacA);
		Cryptography criptoManagerB = new CryptographyHash(cipherB, null, outerMacB);
		
		byte[][] messageParts = criptoManagerA.splitOuterMac(rawPayload);
		if (!criptoManagerA.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outter Mac");

		return new NS3(a, b, Na, messageParts[1], criptoManagerA, criptoManagerB); // Falta a msg
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
