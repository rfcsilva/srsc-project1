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
import kdc.KDCClient;
import kdc.needhamSchroeder.NeedhamSchroederClient;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;

class arUDPproxy {

	private static final String LOCALDELIVERY = "localdelivery";
	private static final String REMOTE = "remote";
	private static final String ERROR_USER_INPUT = "Erro, usar: myReceive <ciphersuite.conf> <proxyProps.properties>";
	private static final int ERROR_CODE = -1;

	public static void main(String[] args) {

		if (args.length != 2) {
			System.err.println(ERROR_USER_INPUT);
			System.exit(ERROR_CODE);
		}
		String remote = null, destinations = null;

		try {
			InputStream inputStream = new FileInputStream(args[1]);
			Properties properties = new Properties();
			properties.load(inputStream);
			remote = properties.getProperty(REMOTE);
			destinations = properties.getProperty(LOCALDELIVERY);
		} catch(IOException e) {
			System.err.println("Unable to read file " + args[1]  + " properly.");
			System.exit(-1);	
		}

		InetSocketAddress inSocketAddress = parseSocketAddress(remote);
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

		// Create inSocket 
		Cryptography cryptoManager;
		SecureDatagramSocket inSocket;
		DatagramSocket outSocket;
		try {
			//KDCServer kdc_server = new NeedhamSchroederServer(inSocketAddress);
			//cryptoManager = kdc_server.getSessionParameters();
			InetSocketAddress b_addr = new InetSocketAddress( "localhost", 8889);
			InetSocketAddress kdc_addr = new InetSocketAddress("localhost", 8888); // TODO: ler das configs
			
			Cryptography master_cryptoManager = CryptoFactory.loadFromConfig(args[0]);
			KDCClient needhamClient = new NeedhamSchroederClient(kdc_addr, "a", master_cryptoManager); // TODO: read a and b from some file
			cryptoManager = needhamClient.getSessionParameters("b", b_addr);
			
			inSocket = new SecureDatagramSocket(inSocketAddress, cryptoManager);
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
			System.err.println("Unable to read file " + args[1]  + " properly.");
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
