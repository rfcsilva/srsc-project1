package keyEstablishmentProtocol.needhamSchroeder;

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
import secureSocket.secureMessages.AbstractPayload;
import secureSocket.secureMessages.Payload;
import util.Utils;

public class NS2 extends AbstractPayload implements Payload { 

	private static final String INVALID_OUTTER_MAC = "Invalid Outter Mac";

	public static final byte TYPE = 0x12;
	
	private long Na_1;
	private long Nc;
	private byte[] Ks;
	private String b;
	private String b_addr;
	private byte[] ticket;
	private byte[] cipherText;
	private byte[] outerMac;
	
	public NS2(long Na_1, long Nc, byte[] Ks, String a, String b, String b_addr, String[] args, Cryptography cryptoManagerB, Cryptography cryptoManagerA, long t1, long t2) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IOException { 
		super(t1,t2);
		this.Na_1 = Na_1;
		this.Nc = Nc;
		this.Ks = Ks;
		this.b = b;
		this.b_addr = b_addr;
		this.ticket =  cryptoManagerB.encrypt((new Ticket(Nc, a, b, Ks, args, t1,t2)).serialize());

		this.cipherText = buildPayload(Na_1, Nc, Ks, b, b_addr, ticket, t1, t2,cryptoManagerA);
		
		this.outerMac = cryptoManagerA.computeOuterMac(cipherText);
	}
	
	private NS2(long Na_1, long Nc, byte[] Ks, String b, String b_addr, byte[] ticket, byte[] cipherText, byte[] outerMac, long t1, long t2) {
		super(t1, t2);
		this.Na_1 = Na_1;
		this.Nc = Nc;
		this.Ks = Ks;
		this.b = b;
		this.b_addr = b_addr;
		this.ticket = ticket;
		this.cipherText = cipherText;
		this.outerMac = outerMac;
	}
	
	private byte[] buildPayload(long Na_1, long Nc, byte[] Ks, String b, String b_addr, byte[] ticket, long t1, long t2, Cryptography cryptoManagerA) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(Na_1);
		dataOut.writeLong(Nc);
		dataOut.writeInt(Ks.length);
		dataOut.write(Ks, 0, Ks.length);
		
		dataOut.writeUTF(b);
		dataOut.writeUTF(b_addr);
		
		dataOut.writeLong(t1);
		dataOut.writeLong(t2);
		
		dataOut.writeInt(ticket.length);
		dataOut.write(ticket, 0, ticket.length);

		dataOut.flush();
		byteOut.flush();

		byte[] data = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();
		
		return cryptoManagerA.encrypt(data);
	}

	public static Payload deserialize(byte[] rawPayload, Cryptography criptoManager) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidMacException {
		
		byte[][] messageParts = criptoManager.splitOuterMac(rawPayload);
		if (!criptoManager.validateOuterMac(messageParts[0], messageParts[1]))
			throw new InvalidMacException(INVALID_OUTTER_MAC);
		else {
			byte[] plainText = criptoManager.decrypt(messageParts[0]);

			ByteArrayInputStream byteIn = new ByteArrayInputStream(plainText);
			DataInputStream dataIn = new DataInputStream(byteIn);

			long Na_1 = dataIn.readLong();
			long Nc = dataIn.readLong();
			
			int length = dataIn.readInt();
			byte[] Ks = new byte[length];
			dataIn.read(Ks, 0, length);

			String b = dataIn.readUTF();
			String b_addr = dataIn.readUTF();
			
			long t1 = dataIn.readLong();
			long t2 = dataIn.readLong();
			
			length = dataIn.readInt();
			byte[] ticket = new byte[length];
			dataIn.read(ticket, 0, length);
			
			dataIn.close();
			byteIn.close();

			return new NS2(Na_1, Nc, Ks, b, b_addr, ticket, messageParts[0], messageParts[1], t1, t2);
		}
	}
	
	@Override
	public byte getPayloadType() {
		return TYPE;
	}

	@Override
	public byte[] serialize() {
		return Utils.concat(cipherText, outerMac);
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

	public String getB() {
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
	
	public String getBAddr() {
		return b_addr;
	}
}
