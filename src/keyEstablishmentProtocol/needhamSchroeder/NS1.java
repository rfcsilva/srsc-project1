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

import cryptography.AbstractCryptography;
import cryptography.Cryptography;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import secureSocket.exceptions.BrokenIntegrityException;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.exceptions.ReplayedNonceException;
import secureSocket.secureMessages.Payload;
import util.Utils;

// TODO : find better name for the class
public class NS1 implements Payload {

	public static final byte TYPE = 0x11;

	// Encryption support
	// private static Cryptography2 criptoService;

	// Payload data
	private String a;
	private String b;
	private long na;
	private String[] arguments;
	private byte[] message;
	private byte[] outerMac;
	
	private Cryptography criptoManagerA;
	private Cryptography criptoManagerB;

	public NS1(String a, String b, long Na, String[] arguments, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.a = a;
		this.b = b;
		this.na = Na;
		this.arguments = arguments;

		this.message = buildMessage(a, b, Na, arguments);

		this.outerMac = cryptoManager.computeOuterMac(message);
	}

	private NS1(String a, String b, long Na, String[] arguments, byte[] outerMac, Cryptography criptoManagerA, Cryptography criptoManagerB) {
		this.a = a;
		this.b = b;
		this.na = Na;
		this.arguments = arguments;
		this.outerMac = outerMac;
		this.criptoManagerA = criptoManagerA;
		this.criptoManagerB= criptoManagerB;
	}

	private static byte[] buildMessage(String a, String b, long Na, String[] arguments) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		/*dataOut.writeInt(a.length);
		dataOut.write(a, 0, a.length);
		dataOut.writeInt(b.length);
		dataOut.write(b, 0, b.length);*/
		
		dataOut.writeUTF(a);
		dataOut.writeUTF(b);
		
		dataOut.writeLong(Na);
		
		dataOut.writeInt(arguments.length);
		for(int i = 0; i < arguments.length; i++) {
			dataOut.writeUTF(arguments[i]);
		}

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
		return Utils.concat(this.message, this.outerMac);
	}

	public short size() {
		return (short) (message.length + outerMac.length);
	}

	// TODO handle bad macs
	// TODO : retornar Payload ou DEfaultPayload?
	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException, BrokenIntegrityException, NoSuchProviderException, UnkonwnIdException {

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
		
		int length = dataIn.readInt();
		String[] arguments = new String[length];
		for(int i = 0; i < length; i++) {
			arguments[i] = dataIn.readUTF();
		}

		dataIn.close();
		byteIn.close();
		
		AbstractCryptography criptoManagerA = ((CryptographyNS) criptoManager).getCryptographyFromId(a);
		AbstractCryptography criptoManagerB = ((CryptographyNS) criptoManager).getCryptographyFromId(b);
		
		byte[][] messageParts = criptoManagerA.splitOuterMac(rawPayload);
		if (!criptoManagerA.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outer Mac");

		return new NS1(a, b, Na, arguments, messageParts[1], criptoManagerA, criptoManagerB); // Falta a msg -> isto é o que?
	}	
	
	public Cryptography getCryptoManagerA() {
		return this.criptoManagerA;
	}
	
	public Cryptography getCryptoManagerB() {
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

	public String[] getArgs() {
		return arguments;
	}
	
}
