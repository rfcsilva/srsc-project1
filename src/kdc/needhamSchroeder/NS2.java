package kdc.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import secureSocket.exceptions.InvalidMacException;
import secureSocket.secureMessages.Payload;
import util.ArrayUtils;

public class NS2 implements Payload { //{Na+1, Nc, Ks , B, {Nc, A, B, Ks}KB }KA 

	public static final byte TYPE = 0x12;
	
	private long Na_1;
	private long Nc;
	private byte[] Ks;
	private byte[] b;
	private byte[] ticket;
	private byte[] cipherText;
	private byte[] outerMac;
	
	public NS2(long Na_1, long Nc, byte[] Ks, byte[] a, byte[] b, Cryptography cryptoManagerB, Cryptography cryptoManagerA) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IOException { 
		this.Na_1 = Na_1;
		this.Nc = Nc;
		this.Ks = Ks;
		this.b = b;
		
		this.ticket = buildTicket(Nc, a, b, Ks, cryptoManagerB);

		this.cipherText = buildPayload(Na_1, Nc, Ks, b, ticket, cryptoManagerA);
		
		this.outerMac = cryptoManagerA.computeOuterMac(cipherText);
	}
	
	private NS2(long Na_1, long Nc, byte[] Ks, byte[] b, byte[] ticket, byte[] cipherText, byte[] outerMac) {
		this.Na_1 = Na_1;
		this.Nc = Nc;
		this.Ks = Ks;
		this.b = b;
		this.ticket = ticket;
		this.cipherText = cipherText;
		this.outerMac = outerMac;
	}
	
	// TODO : secalhar devia ser construído de fora desta class e ter uma class Ticket que constroi e deserializa para depois a serialização e desirialização disto estar no mesmo sitio
	private byte[] buildTicket(long Nc, byte[] a, byte[] b, byte[] Ks, Cryptography cryptoManagerB) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(Nc);
		dataOut.writeInt(a.length);
		dataOut.write(a, 0, a.length);
		dataOut.writeInt(b.length);
		dataOut.write(b, 0, b.length);
		dataOut.writeInt(Ks.length);
		dataOut.write(Ks, 0, Ks.length);

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();
		
		return cryptoManagerB.encrypt(msg);
	}
	
	private byte[] buildPayload(long Na_1, long Nc, byte[] Ks, byte[] b, byte[] ticket, Cryptography cryptoManagerA) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(Na_1);
		dataOut.writeLong(Nc);
		dataOut.writeInt(Ks.length);
		dataOut.write(Ks, 0, Ks.length);
		dataOut.writeInt(b.length);
		dataOut.write(b, 0, b.length);
		dataOut.writeInt(ticket.length);
		dataOut.write(ticket, 0, ticket.length);

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();
		
		return cryptoManagerA.encrypt(msg);
	}

	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidMacException {
		
		byte[][] messageParts = criptoManager.splitOuterMac(rawPayload);
		if (!criptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException("Invalid Outter Mac");
		else {
			byte[] plainText = criptoManager.decrypt(messageParts[0]);

			ByteArrayInputStream byteIn = new ByteArrayInputStream(plainText);
			DataInputStream dataIn = new DataInputStream(byteIn);

			long Na_1 = dataIn.readLong();
			long Nc = dataIn.readLong();
			
			int length = dataIn.readInt();
			byte[] Ks = new byte[length];
			dataIn.read(Ks, 0, length);
			
			length = dataIn.readInt();
			byte[] b = new byte[length];
			dataIn.read(b, 0, length);
			
			length = dataIn.readInt();
			byte[] ticket = new byte[length];
			dataIn.read(ticket, 0, length);

			dataIn.close();
			byteIn.close();

			return new NS2(Na_1, Nc, Ks, b, ticket, messageParts[0], messageParts[1]);
		}
	}
	
	@Override
	public byte getPayloadType() {
		return TYPE;
	}

	@Override
	public byte[] serialize() {
		return ArrayUtils.concat(cipherText, outerMac);
	}

	@Override
	public short size() {
		return (short) (cipherText.length + outerMac.length);
	}

	public long getNa_1() {
		return Na_1;
	}

	public long getNc() {
		return Nc;
	}

	public byte[] getKs() {
		return Ks;
	}

	public byte[] getB() {
		return b;
	}

	public byte[] getTicket() {
		return ticket;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public byte[] getOuterMac() {
		return outerMac;
	}

}
