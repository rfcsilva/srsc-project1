package stream;

import java.util.Scanner;

import util.arKeyStore;

public class RegisterClient {

	public static void main(String[] args) throws Exception {
		
		Scanner in = new Scanner(System.in);
		
		System.out.print("keystore path: ");
		String keystore_path = in.nextLine();
		
		System.out.print("keystore password: ");
		String password = in.nextLine();
		
		System.out.print("keystore type: ");
		String type = in.nextLine();
		
		arKeyStore keystore = new arKeyStore(keystore_path, password, type);
		
		while(true) {
			
			String cmd = in.nextLine();
			
			if(cmd.equals("exit"))
				break;
			else if(cmd.equals("set entry") || cmd.equals("add entry") || cmd.equals("put entry")) {
				System.out.print("id: ");
				String id = in.nextLine();
				System.out.print("password: ");
				String user_password = in.nextLine();
				
				if(keystore.contains("k" + id)) {
					System.err.println("id already in use");
				} else {
					SecretKey ks = null;
					SecretKey kms = null; // TODO
					
					keystore.setKey("k" + id, ks);
					keystore.setKey("km" + id, kms);
				}
			} else if(cmd.equals("rm entry") || cmd.equals("remove entry") || cmd.equals("del entry") || cmd.equals("delete entry")) {
				System.out.print("id: ");
				String id = in.nextLine();
				
				keystore.removeKey("k" + id);
				keystore.removeKey("km" + id);
			} else if(cmd.equals("list") || cmd.equals("ls")) {
				for(String s : keystore.aliases()) {
					System.out.println(s);
				}
			}
			
		}
		
	}

}
