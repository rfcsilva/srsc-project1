package stream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import cryptography.CryptographyDoubleMac;
import cryptography.CryptographyHash;
import cryptography.CryptographyNS;
import cryptography.CryptographyUtils;
import kdc.KDC;
import kdc.needhamSchroeder.NS1;
import kdc.needhamSchroeder.NeedhamSchroederKDC;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;
import util.ArrayUtils;

//TODO: renomear?
public class UDP_KDC_Server {

	static InetSocketAddress my_addr;

	public static void main(String[] args) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException {
		if(args.length < 2) {
			System.out.println("usage: kdc <ip> <port> <master-ciphersuit.conf> <session-ciphersuit.con>");
		}

		my_addr = new InetSocketAddress( args[0], Integer.parseInt(args[1]) );

		System.out.println("KDC Server ready to receive...");
		
		Properties masterCipherSuite = CryptoFactory.loadFile(args[2]);
		SecureRandom sr = CryptoFactory.generateRandom(masterCipherSuite.getProperty(CryptoFactory.SECURE_RANDOM), masterCipherSuite.getProperty(CryptoFactory.SECURE_RANDOM_PROVIDER));
		String path = masterCipherSuite.getProperty(CryptoFactory.KEYSTORE);
		String password = masterCipherSuite.getProperty(CryptoFactory.KEYSTORE_PASSWORD);
		String type = masterCipherSuite.getProperty(CryptoFactory.KEYSTORE_TYPE);
		String macAlgorithm = masterCipherSuite.getProperty(CryptoFactory.OUTER_MAC_CIPHERSUITE);
		String ivString = masterCipherSuite.getProperty(CryptoFactory.IV);
		byte[] iv = ArrayUtils.unparse(ivString);
		String cipherAlgorithm = masterCipherSuite.getProperty(CryptoFactory.SESSION_CIPHERSUITE);
		
		KeyStore keyStore = CryptographyUtils.loadKeyStrore(path, password, type);	
		
		CryptographyNS nsc = new CryptographyNS(sr, password, keyStore, macAlgorithm, iv, cipherAlgorithm);
		KDC kdc = new NeedhamSchroederKDC(my_addr, nsc, args[3]);
		kdc.start();
	}

}