package kdc;

public class NeedhamSchroederClient {
	
	// KDC Client returns CriptoMananger
	// Alterar construtor do SecureSocket para receber CriptoManager

	// A -> KDC : A, B, Na
	// KDC -> A : {Na+1, Nc, Ks , B, {Nc, A, B, Ks }KB }KA 
	
	// A -> B : {Nc, A, B, Ks }KB
	// B -> A : {Nb }Ks
	// A -> B : {Nb+1 }Ks
	
	// A -> KDC : Dá-me Chaves
	// KDC -> A : toma
	// A -> B : toma também
	
}
