package keyEstablishmentProtocol.needhamSchroeder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Base64;

import cryptography.Cryptography;
import cryptography.CryptographyDoubleMac;
import secureSocket.exceptions.InvalidMacException;
import util.Utils;

public class Transation {
	private static final String SEPARATOR = " | ";

	private static final String INVALID_INNER_MAC = "Invalid Inner Mac";

	private String a;
	private String b;
	private long na;
	private String[] args;
	private byte[] innerMac;
	private byte[] message;
	
	public Transation(String a, String b, long na, String[] args, Cryptography cryptoManager) throws IOException, InvalidKeyException {

		this.a = a;
		this.b = b;
		this.na = na;
		this.args = args;
		message = buildMessage(a, b, na, args);
		this.innerMac = cryptoManager.computeIntegrityProof(message);

	}

	private Transation(String a, String b, long na, String[] args, byte[] innerMac, byte[] message) {
		this.a = a;
		this.b = b;
		this.na = na;
		this.args = args;
		this.innerMac = innerMac;
	}

	public String toString() {

		String asString = a.concat(SEPARATOR).concat(b).concat(SEPARATOR);
		asString =  asString.concat(String.valueOf(na)).concat(SEPARATOR);
		for(String arg : args) {
			asString = asString.concat(arg).concat(SEPARATOR);
		}

		return asString.concat(Base64.getEncoder().encodeToString(innerMac));

	}

	public Transation fromString(String asString) throws IOException {

		String[] parts = asString.split(SEPARATOR);
		String a = parts[0];
		String b = parts[1];
		long na = Long.parseLong(parts[2]);

		String[] args = new String[ parts.length - 4];
		for(int i = 3; i < parts.length -1; i++) {
			args[i-3] = parts[i];
		}

		innerMac = Base64.getDecoder().decode(parts[parts.length-1]);

		return new Transation(a, b, na, args, innerMac, buildMessage(a, b, na, args));
	}

	public byte[] serialize() throws IOException {
		return Utils.concat(message, innerMac);
	}

	public static Transation deserialize(CryptographyDoubleMac cryptoManager, byte[] rawData) throws IOException, InvalidMacException, InvalidKeyException {

		byte[][] messageParts = cryptoManager.splitIntegrityProof(rawData);	
				
		if (!cryptoManager.validateIntegrityProof(messageParts[0], messageParts[1])) {
			throw new InvalidMacException(INVALID_INNER_MAC);
		}else {

			ByteArrayInputStream byteIn = new ByteArrayInputStream(messageParts[0]);
			DataInputStream dataIn = new DataInputStream(byteIn);

			String a = dataIn.readUTF();
			String b = dataIn.readUTF();
			long na = dataIn.readLong();

			int length = dataIn.readInt();
			String[] arguments = new String[length];
			for(int i = 0; i < length; i++) {
				arguments[i] = dataIn.readUTF();
			}
			
			dataIn.close();
			byteIn.close();

			return new Transation(a, b, na, arguments, messageParts[1], messageParts[0] );

		}
	}

	private static byte[] buildMessage(String a, String b, long Na, String[] args) throws IOException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(a);
		dataOut.writeUTF(b);

		dataOut.writeLong(Na);

		dataOut.writeInt(args.length);
		for(int i = 0; i < args.length; i++) {
			dataOut.writeUTF(args[i]);
		}

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return msg;
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
		return args;
	}

	public byte[] getInnerMac() {
		return innerMac;
	}
}
