package keyEstablishmentProtocol.needhamSchroeder;

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

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import secureSocket.exceptions.BrokenIntegrityException;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.exceptions.ReplayedNonceException;
import secureSocket.secureMessages.AbstractPayload;
import secureSocket.secureMessages.Payload;
import util.Utils;

public class NS3 extends AbstractPayload implements Payload {

	private static final String INVALID_OUTTER_MAC = "Invalid Outter Mac";

	public static final byte TYPE = 0x13;

	// Payload data
	private long Nc;
	private String a;
	private String b;
	byte[] Ks;
	private String[] args;
	private byte[] ticket;
	private byte[] outerMac;
	
	private Cryptography session_criptoManager;

	public NS3(byte[] ticket, long t1, long t2, Cryptography cryptoManager)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException,
			IllegalBlockSizeException, BadPaddingException, ShortBufferException {

		super(t1, t2);
		this.ticket = ticket;

		this.outerMac = cryptoManager.computeOuterMac(ticket);
	}

	private NS3(long Nc, String a, String b, byte[] Ks, String[] args, byte[] ticket, byte[] outerMac, long t1, long t2, Cryptography session_criptoManager) {
		super(t1,t2);
		this.Nc = Nc;
		this.a = a;
		this.b = b;
		this.Ks = Ks;
		this.args = args;
		this.ticket = ticket;
		this.outerMac = outerMac;
		this.session_criptoManager = session_criptoManager;
	}

	public byte getPayloadType() {
		return TYPE;
	}

	public byte[] serialize() {
		return Utils.concat(Utils.intToByteArray(this.outerMac.length), Utils.concat(this.ticket, this.outerMac));
	}

	public short size() {
		return (short) (Integer.BYTES + ticket.length + outerMac.length);
	}

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
		
		byte[] clearText = criptoManager.decrypt(ticket);
			
		Ticket t = Ticket.deserialize(clearText); 
		
		Cryptography session_cryptoManager = CryptoFactory.deserializeSessionParameters(t.getKs()); 

		if (!session_cryptoManager.validateOuterMac(ticket, outerMac))
			throw new InvalidMacException(INVALID_OUTTER_MAC);

		return new NS3(t.getNc(), t.getA(), t.getB(), t.getKs(), t.getArgs(), ticket, outerMac, t.t1(), t.t2(), session_cryptoManager); // Falta a msg
	}		
	public Cryptography getSessionCryptoManager() {
		return this.session_criptoManager;
	}

	public String getA() {
		return a;
	}
	
	public String getB() {
		return b;
	}

	public long getNc() {
		return Nc;
	}

	public byte[] getKs() {
		return Ks;
	}

	public byte[] getTicketRaw() {
		return ticket;
	}
	
	public Ticket getTicket(Cryptography cryptoManager) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException {
		return Ticket.deserialize(cryptoManager.decrypt(ticket)); 
	}

	public byte[] getOuterMac() {
		return outerMac;
	}

	public String[] getArgs() {
		return args;
	}
	
}
