package kdc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import cryptography.AbstractCryptography;
import cryptography.Cryptography;
import cryptography.CryptographyDoubleMac;
import cryptography.CryptographyHash;
import cryptography.CryptographyUtils;
import kdc.needhamSchroeder.NS1;
import kdc.needhamSchroeder.NeedhamSchroederKDC;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

//TODO: renomear?
public class UDP_KDC_Server {

	static InetSocketAddress my_addr;

	public static void main(String[] args) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		if(args.length < 2) {
			System.out.println("usage: kdc <ip> <port>");
		}
		//InputStream inputStream = new FileInputStream("configs/kdc/ciphersuite.conf");

		my_addr = new InetSocketAddress( args[0], Integer.parseInt(args[1]) );

		KDC kdc_server = new NeedhamSchroederKDC(my_addr);

		System.out.println("KDC Server ready to receive...");

		while(true) {
			// recebe pedidos -> não deveria bloquear infintamente? ou isto lança uma excepção? eu acho que lança ...
			SecureMessage sm = new SecureMessageImplementation();
			InetSocketAddress client_addr = kdc_server.receiveRequest(sm);
			processRequest(sm, client_addr);
		}
	}

	private static void processRequest(SecureMessage request, InetSocketAddress client_addr) {
		new Thread(() -> {
			try {
				KDC kdc_server = new NeedhamSchroederKDC();
				String a = new String(((NS1)request.getPayload()).getA());
				String b = new String(((NS1)request.getPayload()).getB());
				System.out.println(a + " " + b + " " + ((NS1)request.getPayload()).getNa());

				System.out.println(client_addr.toString());

				// gera cenas e faz o mambo
				String path = "./configs/kdc/session-ciphersuite.conf";
				byte[] params = buildSessionParameters(path);

				System.out.println(Base64.getEncoder().encodeToString(params));

				// TODO: FALTA FAZER DINHEIRO

				// envia replys
				kdc_server.sendReply(((NS1)request.getPayload()), params, client_addr);
			} catch(Exception e) {
				e.printStackTrace(); // TODO: tratar as excepções
			}
		}).start();
	}

	
	// TODO: secalhar ir para o CryptoMAnager?
	private static byte[] buildSessionParameters(String path) throws NoSuchAlgorithmException, IOException { // TODO: passar para outra class ou assim
		InputStream inputStream = new FileInputStream(path);
		Properties ciphersuit_properties = new Properties();
		ciphersuit_properties.load(inputStream);

		// Secure Random
		String secureRandomAlgorithm = ciphersuit_properties.getProperty("secure-random");

		SecureRandom sr = java.security.SecureRandom.getInstance(secureRandomAlgorithm);

		// Cipher Suite
		String cipherAlgorithm = ciphersuit_properties.getProperty("session-ciphersuite"); 
		String session_key_gen_alg = ciphersuit_properties.getProperty("session-key-gen-alg"); 
		int session_key_size = Integer.parseInt(ciphersuit_properties.getProperty("session-key-size"));
		SecretKey ks = CryptographyUtils.generateKey(session_key_gen_alg, session_key_size); // Session key
		int ivSize = Integer.parseInt(ciphersuit_properties.getProperty("iv-size"));
		
		byte[] iv = null;
		if(cipherAlgorithm.contains("CTR")) {
			int messageNumber = 1; // TODO : Descobrir o que é isto
			iv = CryptographyUtils.createCtrIvForAES(messageNumber, sr).getIV();
		} else if( ivSize > 0 ) {
				iv = CryptographyUtils.createGenericIvForAES(ivSize).getIV();
		} else
			iv = new byte[0];

		String aux = ciphersuit_properties.getProperty("tag-size");
		int tagSize = aux == null ? 0 : Integer.parseInt(aux);
		
		// Outer Mac Suite
		String outerMacAlgorithm = ciphersuit_properties.getProperty("outer-mac-ciphersuite");
		String outer_key_gen_alg = ciphersuit_properties.getProperty("outer-mac-key-gen-alg");
		int outer_mac_key_size = Integer.parseInt(ciphersuit_properties.getProperty("outer-mac-key-size"));
		SecretKey kms = CryptographyUtils.generateKey(outer_key_gen_alg, outer_mac_key_size); // outer Mac Session Key

		boolean useHash = Boolean.parseBoolean(ciphersuit_properties.getProperty("use-hash")); 

		// Inner Mac Suite
		String innerMacAlgorithm = ciphersuit_properties.getProperty("inner-mac-ciphersuite");
		String inner_key_gen_alg = ciphersuit_properties.getProperty("inner-mac-key-gen-alg");
		int inner_mac_key_size = Integer.parseInt(ciphersuit_properties.getProperty("inner-mac-key-size"));
		SecretKey kms2 = useHash ? null : CryptographyUtils.generateKey(inner_key_gen_alg, inner_mac_key_size);  // inner Mac Session Key -> ver se é preciso

		// Hash Suite
		String hashAlgorithm = ciphersuit_properties.getProperty("hash-ciphersuite");

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(secureRandomAlgorithm);

		dataOut.writeUTF(cipherAlgorithm);
		dataOut.writeUTF(session_key_gen_alg);
		byte[] session_key_encoded = ks.getEncoded();
		dataOut.writeInt(session_key_encoded.length);
		dataOut.write(session_key_encoded, 0, session_key_encoded.length);

		dataOut.writeInt(iv.length);
		dataOut.write(iv, 0, iv.length);
		
		dataOut.writeInt(tagSize);

		dataOut.writeUTF(outerMacAlgorithm);
		dataOut.writeUTF(outer_key_gen_alg);
		byte[] outer_mac_key_encoded = kms.getEncoded();
		dataOut.writeInt(outer_mac_key_encoded.length);
		dataOut.write(outer_mac_key_encoded, 0, outer_mac_key_encoded.length);

		dataOut.writeBoolean(useHash);

		if(useHash) {
			dataOut.writeUTF(hashAlgorithm);
		} else {
			dataOut.writeUTF(innerMacAlgorithm);
			dataOut.writeUTF(inner_key_gen_alg);
			byte[] inner_mac_key_encoded = kms2.getEncoded();
			dataOut.writeInt(inner_mac_key_encoded.length);
			dataOut.write(inner_mac_key_encoded, 0, inner_mac_key_encoded.length);
		}

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray(); // TODO: renomear de msg para outra coisa

		dataOut.close();
		byteOut.close();

		return msg;
	}

	public static Cryptography deserializeSessionParameters(byte[] rawParams) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException { // TODO: passar para outra class ou assim
		ByteArrayInputStream byteIn = new ByteArrayInputStream(rawParams);
		DataInputStream dataIn = new DataInputStream(byteIn);

		String secureRandomAlgorithm = dataIn.readUTF();

		String cipherAlgorithm = dataIn.readUTF();
		String session_key_alg = dataIn.readUTF();
		int length = dataIn.readInt();
		byte[] ks_encoded = new byte[length];
		dataIn.read(ks_encoded, 0, length);
		SecretKey ks = new SecretKeySpec(ks_encoded, session_key_alg);

		length = dataIn.readInt();
		byte[] iv = new byte[length];
		dataIn.read(iv, 0, length);
		
		int tagSize = dataIn.readInt();

		String outerMacAlgorithm = dataIn.readUTF();
		String outer_key_alg = dataIn.readUTF();
		length = dataIn.readInt();
		byte[] outer_mac_key_encoded = new byte[length];
		dataIn.read(outer_mac_key_encoded, 0, length);
		SecretKey kms = new SecretKeySpec(outer_mac_key_encoded, outer_key_alg);

		boolean useHash = dataIn.readBoolean();

		Cryptography cryptoManager = null;
		Cipher encryptCipher = AbstractCryptography.buildCipher(cipherAlgorithm, Cipher.ENCRYPT_MODE, ks, iv, tagSize);
		Cipher decryptCipher = AbstractCryptography.buildCipher(cipherAlgorithm, Cipher.DECRYPT_MODE, ks, iv, tagSize);
		Mac outerMac = AbstractCryptography.buildMac(outerMacAlgorithm, kms);
		SecureRandom secureRandom = AbstractCryptography.buildSecureRandom(secureRandomAlgorithm);
		
		if(useHash) {
			String hashAlgorithm = dataIn.readUTF();
			MessageDigest innerHash = AbstractCryptography.buildHash(hashAlgorithm);

			cryptoManager = new CryptographyHash(encryptCipher, decryptCipher, secureRandom, innerHash, outerMac);
		} else {
			String innerMacAlgorithm = dataIn.readUTF();
			String inner_key_alg = dataIn.readUTF();
			length = dataIn.readInt();
			byte[] inner_mac_key_encoded = new byte[length];
			dataIn.read(inner_mac_key_encoded, 0, length);
			SecretKey kms2 = new SecretKeySpec(inner_mac_key_encoded, inner_key_alg);

			Mac innerMac = AbstractCryptography.buildMac(innerMacAlgorithm, kms2);

			cryptoManager = new CryptographyDoubleMac(encryptCipher, decryptCipher, secureRandom, innerMac, outerMac);
		}
		
		System.out.println("BINA3: " + (((CryptographyDoubleMac)cryptoManager).getInnerMac()== null));

		return cryptoManager;
	}

}
