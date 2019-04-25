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

import cryptography.AbstractCryptography;
import cryptography.Cryptography;
import cryptography.CryptographyNS;
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
	private String a;
	private String b;
	private long na;
	private byte[] message;
	private byte[] outerMac;
	
	private Cryptography criptoManagerA;
	private Cryptography criptoManagerB;

	public NS1(String a2, String b2, long Na, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.a = a2;
		this.b = b2;
		this.na = Na;

		this.message = buildMessage(a2, b2, Na);

		this.outerMac = cryptoManager.computeOuterMac(message);
	}

	private NS1(String a, String b, long Na, byte[] outerMac, Cryptography criptoManagerA, Cryptography criptoManagerB) {
		this.a = a;
		this.b = b;
		this.na = Na;
		this.outerMac = outerMac;
		this.criptoManagerA = criptoManagerA;
		this.criptoManagerB= criptoManagerB;
	}

	private static byte[] buildMessage(String a, String b, long Na) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		/*dataOut.writeInt(a.length);
		dataOut.write(a, 0, a.length);
		dataOut.writeInt(b.length);
		dataOut.write(b, 0, b.length);*/
		
		dataOut.writeUTF(a);
		dataOut.writeUTF(b);
		
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
		/*int a_size = dataIn.readInt();
		byte[] a  = new byte[a_size];
		dataIn.read(a, 0, a_size);
		
		//read b
		int b_size = dataIn.readInt();
		byte[] b  = new byte[b_size];
		dataIn.read(b, 0, b_size);*/
		String a = dataIn.readUTF();
		String b = dataIn.readUTF();

		long Na = dataIn.readLong();

		dataIn.close();
		byteIn.close();
		
		System.out.println(a + " " + b);
		
		AbstractCryptography criptoManagerA = ((CryptographyNS) criptoManager).getCryptographyFromId(a);
		AbstractCryptography criptoManagerB = ((CryptographyNS) criptoManager).getCryptographyFromId(b);
		
		byte[][] messageParts = criptoManagerA.splitOuterMac(rawPayload);
		if (!criptoManagerA.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outer Mac");

		return new NS1(a, b, Na, messageParts[1], criptoManagerA, criptoManagerB); // Falta a msg
	}	
	
	public Cryptography getCryptoManagerA() {
		return this.criptoManagerA;
	}
	
	public Cryptography getCryptoManagerB() { // TODO: ter aqui o B ?
		return this.criptoManagerB;
	}
	
	public String getA() {
		return a;
	}
	
	public String getB() {
		return b;
	}
	
	public long getNa() {
		return na;
	}
	
}
