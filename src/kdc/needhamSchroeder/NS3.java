package kdc.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
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
import kdc.UDP_KDC_Server;
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
	
	private Cryptography session_criptoManager;

	public NS3(byte[] ticket, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		this.ticket = ticket;

		this.outerMac = cryptoManager.computeOuterMac(ticket);
	}

	private NS3(long Nc, byte[] a, byte[] b, byte[] Ks, byte[] ticket, byte[] outerMac, Cryptography session_criptoManager) {
		this.Nc = Nc;
		this.a = a;
		this.b = b;
		this.Ks = Ks;
		this.ticket = ticket;
		this.outerMac = outerMac;
		this.session_criptoManager = session_criptoManager;
	}

	public byte getPayloadType() {
		return TYPE;
	}

	public byte[] serialize() {
		return ArrayUtils.concat(ArrayUtils.intToByteArray(this.outerMac.length), ArrayUtils.concat(this.ticket, this.outerMac));
	}

	public short size() {
		return (short) (Integer.BYTES + ticket.length + outerMac.length);
	}

	// TODO handle bad macs
	// TODO : retornar Payload ou DEfaultPayload?
	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, InvalidMacException, ReplayedNonceException, BrokenIntegrityException, NoSuchProviderException {

		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawPayload);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		int outerMacSize = dataIn.readInt();
		byte[] outerMac = new byte[outerMacSize];
		System.arraycopy(rawPayload, rawPayload.length-outerMacSize, outerMac, 0, outerMacSize);
		
		byte[] ticket = new byte[rawPayload.length-Integer.BYTES-outerMacSize];
		System.arraycopy(rawPayload, Integer.BYTES, ticket, 0, ticket.length);

		dataIn.close();
		byteIn.close();
		
		byte[] clearText = criptoManager.decrypt(ticket); // this cryptoManager has to have Kb
		
		byteIn = new ByteArrayInputStream(clearText);
		dataIn = new DataInputStream(byteIn);
		
		long Nc = dataIn.readLong();
		
		System.out.println(Nc);
		
		int length = dataIn.readInt();
		byte[] a = new byte[length];
		dataIn.read(a, 0, a.length);
		
		length = dataIn.readInt();
		byte[] b = new byte[length];
		dataIn.read(b, 0, b.length);
		
		length = dataIn.readInt();
		byte[] Ks = new byte[length];
		dataIn.read(Ks, 0, Ks.length);
		
		dataIn.close();
		byteIn.close();
		
		Cryptography session_cryptoManager = UDP_KDC_Server.deserializeSessionParameters(Ks);
		
		/*byte[][] messageParts = session_cryptoManager.splitOuterMac(rawPayload);
		if (!session_cryptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outter Mac");*/
		
		if (!session_cryptoManager.validateOuterMac(ticket, outerMac))
			throw new InvalidMacException("Invalid Outter Mac");

		return new NS3(Nc, a, b, Ks, ticket, outerMac, session_cryptoManager); // Falta a msg
	}	
	
	public Cryptography getSessionCryptoManager() {
		return this.session_criptoManager;
	}

	public byte[] getA() {
		return a;
	}
	
	public byte[] getB() {
		return b;
	}

	public long getNc() {
		return Nc;
	}

	public byte[] getKs() {
		return Ks;
	}

	public byte[] getTicket() {
		return ticket;
	}

	public byte[] getOuterMac() {
		return outerMac;
	}
	
}
