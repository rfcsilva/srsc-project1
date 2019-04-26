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
import kdc.KDCClient;
import kdc.KDCServer;
import kdc.needhamSchroeder.NeedhamSchroederClient;
import kdc.needhamSchroeder.NeedhamSchroederServer;
import secureSocket.SecureDatagramSocket;

class arStreamServer {

	private static final String ALORITHM_NOT_FOUND = "Alorithm not found: ";
	private static final String DONE_PACKETS_SENT = "DONE! packets sent: ";
	private static final String ERROR_USER_INPUT_2 = "        or: mySend <movie> <ip-unicast-address> <port> <ciphersuite.conf>";
	private static final String ERROR_USER_INPUT = "Erro, usar: mySend <movie> <ip-multicast-address> <port> <ciphersuite.conf>";
	private static final String UNABLE_TO_LOAD_MOVIE_FILE = "Unable to load movie file.";

	static public void main( String []args ) {
		if (args.length != 4) {
			System.out.println(ERROR_USER_INPUT);
			System.out.println(ERROR_USER_INPUT_2);
			System.exit(-1);
		}

		int size;
		int count = 0;
		long time;
		DataInputStream g = null;
		try {
			g = new DataInputStream( new FileInputStream(args[0]) );
		} catch (FileNotFoundException e) {
			System.err.println(UNABLE_TO_LOAD_MOVIE_FILE);
			System.exit(-1);
		}
		

		try {
		byte[] buff = new byte[65000];
		
		Cryptography master_cryptoManager = CryptoFactory.loadFromConfig(args[3]);
	    InetSocketAddress b_addr = new InetSocketAddress( "localhost", 8889);
		KDCServer kdc_server = new NeedhamSchroederServer(b_addr, master_cryptoManager); // TODO: COLOCAR ID
		Cryptography session_cryptoManager = kdc_server.getSessionParameters();
		
		SecureDatagramSocket socket = new SecureDatagramSocket(session_cryptoManager);

		//InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		InetSocketAddress addr = kdc_server.getClientAddr();
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

		System.out.println(DONE_PACKETS_SENT+count);
		}catch(InvalidKeyException e) {
			
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(-1);
		} catch (InterruptedException e) {
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

}
