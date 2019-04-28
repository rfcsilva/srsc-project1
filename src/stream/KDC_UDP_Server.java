package stream;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptoFactory;
import keyEstablishmentProtocol.KeyEstablishmentProtocolKDC;
import keyEstablishmentProtocol.needhamSchroeder.CryptographyNS;
import keyEstablishmentProtocol.needhamSchroeder.NeedhamSchroederKDC;
import secureSocket.exceptions.InvalidPayloadTypeException;

public class KDC_UDP_Server {

	public static void main(String[] args) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException {
		if(args.length < 6) {
			System.out.println("usage: kdc <local-address> <port> <master-ciphersuit.conf> <session-ciphersuit.conf> <services.conf> <movieprice>");
			System.exit(-1);
		}

		InetSocketAddress my_addr = new InetSocketAddress( args[0], Integer.parseInt(args[1]) );

		System.out.println("KDC Server ready to receive...");
				
		CryptographyNS NSCryptoManager = CryptographyNS.loadFromprops(CryptoFactory.loadFile(args[2]));
		KeyEstablishmentProtocolKDC kdc = new NeedhamSchroederKDC(my_addr, NSCryptoManager, args[3], args[4], args[5]);
		kdc.start();
	}

}