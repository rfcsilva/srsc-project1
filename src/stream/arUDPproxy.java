/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

//
package stream;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import keyEstablishmentProtocol.KeyEstablishmentProtocolClient;
import keyEstablishmentProtocol.needhamSchroeder.NeedhamSchroederClient;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnServerException;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;

class arUDPproxy {

	private static final String LOCALDELIVERY = "localdelivery";
	//private static final String REMOTE = "remote";
	private static final String KDC = "kdc";
	private static final String ERROR_USER_INPUT = "Error, use: myReceive <ciphersuite.conf> <proxyProps.properties> <client-id> <password> <server-id> <movie-name>";
	private static final int ERROR_CODE = -1;
	private static final String DEFAULT_MOVIE_PRICE = "3.00�";

	public static void main(String[] args) {

		if (args.length != 6) {
			System.err.println(ERROR_USER_INPUT);
			System.exit(ERROR_CODE);
		}
		String destinations = null, kdc = null;

		try {
			InputStream inputStream = new FileInputStream(args[1]);
			Properties properties = new Properties();
			properties.load(inputStream);
			kdc = properties.getProperty(KDC); 
			destinations = properties.getProperty(LOCALDELIVERY);
		} catch(IOException e) {
			System.err.println("Unable to read file " + args[1]  + " properly.");
			System.exit(-1);	
		}

		InetSocketAddress kdc_addr = parseSocketAddress(kdc);
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

		// Create inSocket 
		Cryptography cryptoManager;
		SecureDatagramSocket inSocket;
		DatagramSocket outSocket;
		try {
			Cryptography master_cryptoManager = CryptoFactory.getInstace(args[3], args[0]);
			KeyEstablishmentProtocolClient kdc_client = new NeedhamSchroederClient(kdc_addr, args[2], master_cryptoManager);
			System.out.println(DEFAULT_MOVIE_PRICE);
			cryptoManager = kdc_client.getSessionParameters(args[4], new String[] {args[5], DEFAULT_MOVIE_PRICE});

			inSocket = new SecureDatagramSocket(kdc_client.getMyAddr(), cryptoManager);

			outSocket = new DatagramSocket();
			byte[] buffer = new byte[4 * 1024];

			System.out.println("Proxy ready to receive...");

			// main loop
			while (true) {
				DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);

				inSocket.receive(inPacket);

				System.out.print("*");
				for (SocketAddress outSocketAddress : outSocketAddressSet) {
					outSocket.send(new DatagramPacket(inPacket.getData(), inPacket.getLength(), outSocketAddress));
				}
			}
		} catch (UnkonwnServerException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (InvalidKeyException e) {
			System.err.println("Invalid Key or ciphersuite parameters: " + e.getMessage());
			System.exit(-1);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Alorithm not found: " + e.getMessage());
			System.exit(-1);
		} catch (UnrecoverableEntryException e) {
			System.err.println("Unable to recover an entry in the keystore: " + e.getMessage());
			System.exit(-1);
		} catch (KeyStoreException | CertificateException e) {
			System.err.println("Keystore error: " + e.getMessage());
			System.exit(-1);
		} catch (InvalidPayloadTypeException e) {
			System.err.println("Payload is ivalid/unkown: " + e.getMessage());
			System.exit(-1);
		} catch(IOException e) {
			System.out.println(e.getMessage());
			System.err.println("Unable to read file " + args[0]  + " properly.");
			System.exit(-1);		
		} catch(Exception e) {
			e.printStackTrace();
			System.exit(-1);		
		}
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
