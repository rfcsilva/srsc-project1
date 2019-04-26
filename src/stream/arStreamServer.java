/*
 * hjStreamServer.java 
 * Streaming server: emitter of video streams (movies)
 * Can send in unicast or multicast IP for client listeners
 * that can play in real time the transmitted movies
 */

package stream;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import keyEstablishmentProtocol.KeyEstablishmentProtocolServer;
import keyEstablishmentProtocol.needhamSchroeder.NeedhamSchroederServer;
import secureSocket.SecureDatagramSocket;

class arStreamServer {

	private static final String INVALID_KEY_OR_CIPHER_PARAMETERS = "Invalid Key or Cipher parameters: ";
	private static final String ALORITHM_NOT_FOUND = "Alorithm not found: ";
	private static final String DONE_PACKETS_SENT = "DONE! packets sent: ";
	private static final String ERROR_USER_INPUT = "        or: mySend <movies-folder> <local-address> <port> <ciphersuite.conf>";
	private static final String UNABLE_TO_LOAD_MOVIE_FILE = "Unable to load movie file.";

	static public void main( String []args ) {
		if (args.length != 4) {
			System.out.println(ERROR_USER_INPUT);
			System.exit(-1);
		}

		try {
			Cryptography master_cryptoManager = CryptoFactory.loadFromConfig(args[3]);
			InetSocketAddress b_addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
			KeyEstablishmentProtocolServer kdc_server = new NeedhamSchroederServer(b_addr, master_cryptoManager);
			kdc_server.start( (inSocket, addr, arguments) -> {streamMovie(inSocket, addr, arguments[0], args[0]);} );

		} catch(InvalidKeyException e) {
			System.out.println(INVALID_KEY_OR_CIPHER_PARAMETERS + e.getMessage());
			System.exit(-1);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(-1);
		} catch (NoSuchAlgorithmException e) {
			System.err.println(ALORITHM_NOT_FOUND + e.getMessage());
			System.exit(-1);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}

	private static void streamMovie(SecureDatagramSocket socket, InetSocketAddress addr, String movie, String moviesFolder) {
		int size;
		int count = 0;
		long time;
		DataInputStream g = null;
		
		try {
			g = new DataInputStream( new FileInputStream(moviesFolder + movie + ".dat") );

			byte[] buff = new byte[65000];

			DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
			long t0 = System.nanoTime(); // tempo de referencia para este processo
			long q0 = 0;

			while ( g.available() > 0 ) {
				size = g.readShort();
				time = g.readLong();
				if ( count == 0 ) q0 = time; // tempo de referencia no stream
				count += 1;
				g.readFully(buff, 0, size );
				p.setData(buff, 0, size );
				p.setSocketAddress( addr );
				long t = System.nanoTime();
				Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
				socket.send( p );
				System.out.print( "." );
			}

			g.close();
			socket.close();

			System.out.println("\n" + DONE_PACKETS_SENT + count);
			
		} catch(InvalidKeyException e) {
			System.out.println(INVALID_KEY_OR_CIPHER_PARAMETERS + e.getMessage());
		} catch (FileNotFoundException e) {
			System.err.println(UNABLE_TO_LOAD_MOVIE_FILE);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println(ALORITHM_NOT_FOUND + e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
