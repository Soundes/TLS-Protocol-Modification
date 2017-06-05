package org.bouncycastle.tls.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.util.Base64;
import java.util.logging.Level;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.omg.CORBA.Principal;

import com.sun.corba.se.impl.oa.poa.ActiveObjectMap.Key;
import com.sun.istack.internal.logging.Logger;

import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class utilities {

	 private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption"; 
	 private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME; 
	 
	  
	  static  byte[] EncryptWithGivenPubllicKey (String text) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException
	    {
	    	 
	    	String pubKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4IJZLsjlx+o4RSvafaAcReoNnzrI0UXu7kZyXPe31ql32X9AvhC6QQIUmLkr1"+
								"Evm0zP/SgVG9YX3DSqBUgPo04iv1I1/wNKwAf1/uH9EiiqdpczefyxxnzJiKUTcx2/4mA4E4QxCIL5JsZb78WoYZrd2kToW/WD01MnSFi"+
								"CgSyjGdd812GY2EVzfvlv8kYuti3icMUyitEfHhtw8cAWI6/nVrRPNs0e5NsvtZJ0nfrXsfQDR0C7+ivQK+fQabi8oRGsbTZceAvVlqVE669z"+
								"oIwIFLcB+eYXTxbka4E7veUMpaF9w//HdwVS2y/2jJiI+16qPStQQPIKQ4Cucoif7/UHfIBuVGVJ5MIVyK7NC7TV/lyoXmyo7ZcnVZnI7r"+
								"Zcw5/qZcqaZ0VCrzvHijwTK7100hOOjiarvRa2OJGXHLIeAUlbrHOXEXS6ah2glPhLDEg6Qzp/lKVSISolal7q73qyhF483P9jXn3hefSLA9"+
								"J1/1LgeajWvuVkxuw+dy2Tlv7oUpNBkX47/TOho5qttr1y9K3hD5Q87RAJPdBtFdDbY8qUPxoiBsTbUWjVoEjJf2YAsLTJIIi2ZISkbD/Vdr"+
								"tZnS73QSJkJReOMNT9XYNGDJvwNIrRcNGFKlJcX6qq+ozGNsDkrt0ObxAD7YCTjAYQVTlbQOaTu5DbGxGDNCoMCAwEAAQ==";
	    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    	byte[] keyBytes = Base64.getDecoder().decode(pubKey.getBytes()); //assuming base64 encoded key
	    	X509EncodedKeySpec  KeySpec = new X509EncodedKeySpec (keyBytes);
	    	RSAPublicKey mypublicKey = (RSAPublicKey)keyFactory.generatePublic(KeySpec);
	    	
	    	 Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	         cipher.init(Cipher.ENCRYPT_MODE, mypublicKey);
	         byte[] cipherData = cipher.doFinal(text.getBytes("UTF-8"));

	         
	         return cipherData;  	 
	    }
	  
	  static byte[] Encode64Base(String x){
		  
		  byte[] encodedBytes = Base64.getEncoder().encode(x.getBytes());
		  
		  return encodedBytes;
		  
	  }
	  
	  private static X509Certificate createSignedCertificate(X509Certificate cetrificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey) throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
	       
          Principal issuer =  (Principal) issuerCertificate.getSubjectDN();
          String issuerSigAlg = issuerCertificate.getSigAlgName();
            
          byte[] inCertBytes = cetrificate.getTBSCertificate();
          X509CertInfo info = new X509CertInfo(inCertBytes);
          //info.set(X509CertInfo.ISSUER, (X500Name)issuer);
            
          //No need to add the BasicContraint for leaf cert
          if(!cetrificate.getSubjectDN().getName().equals("CN=TOP")){
              CertificateExtensions exts=new CertificateExtensions();
              BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
              exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
              info.set(X509CertInfo.EXTENSIONS, exts);
          }
            
          X509CertImpl outCert = new X509CertImpl(info);
          outCert.sign(issuerPrivateKey, issuerSigAlg);
            
          return  outCert;
  }

	  public static X509V3CertificateGenerator GenerateSelfSignedCerteficate(X500Principal dnName1,X500Principal dnName2, BigInteger  serialNumber ,PublicKey mypublicKey, PrivateKey myprivateKey, KeyUsage Keyus ) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException
	    {
	    	 // build a certificate generator
			   X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		 

			   //certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new DERSequence(new DERObjectIdentifier("2.23.43.6.1.2")));

			   certGen.setSerialNumber(serialNumber);
			   certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		       certGen.setIssuerDN(dnName1); // use the same
			   certGen.setSubjectDN(dnName2);
			   // yesterday
			   certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
			   // in 2 years
			   certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
			   certGen.setPublicKey(mypublicKey);
			   certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
			   certGen.addExtension(X509Extensions.KeyUsage, true, Keyus);
			   certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

			   
	    	return certGen;
	    	
	    }
	  
	  private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws OperatorCreationException, CertificateException { 
	        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey); 
	        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer)); 
	    }
	  
	  
	  static X509Certificate generateX509Certificate(String certificateName) throws CertificateException, FileNotFoundException, IOException {
		    InputStream inStream = null;
		    X509Certificate cert = null;
		    try {
		        inStream = new FileInputStream(certificateName);
		        CertificateFactory cf = CertificateFactory.getInstance("X.509");
		        cert = (X509Certificate) cf.generateCertificate(inStream);
		    } finally {
		        if (inStream != null) {
		            inStream.close();
		        }
		    }
		    return cert;
		}
	  
	  public static void SaveCertToFile(String FileName, X509Certificate cert ) throws UnsupportedEncodingException, IOException, CertificateEncodingException
	    {

		     //save the certeficate
		     final FileOutputStream os = new FileOutputStream(FileName);
		     os.write("-----BEGIN CERTIFICATE-----\n".getBytes("UTF-8"));
		     os.write(Base64.getEncoder().encode(cert.getEncoded())) ;
		     os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
		     os.close(); 
	    	
	    	
	    }

	  
	  protected static final String KEYSTORE = "keystore";
	  protected static final String KEYSTORE_PASSWORD = "1234";

	  protected static KeyStore initKeyStore(String keyStore, String keyStoreType, String keyPass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
	      KeyStore ks = null;
	      try {

	          ks = KeyStore.getInstance(keyStoreType);
	          ks.load(new FileInputStream(keyStore), keyPass.toCharArray());
	          ks.load(null, keyPass.toCharArray());
	      } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
	          Logger.getLogger("CNS", null).
	                  log(Level.SEVERE, null, e);
	          X509Certificate certificate = generateX509Certificate("CNS"); 
	          ks = KeyStore.getInstance(keyStoreType);
	          ks.load(null, keyPass.toCharArray());
	          KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	          kpg.initialize(2048);
	          KeyPair kp = kpg.genKeyPair();
	          PublicKey publicKey = kp.getPublic();
	          PrivateKey privateKey = kp.getPrivate();
	          Certificate[] certChain = new Certificate[1];  
	          String alias = "soundes";
	          ks.setKeyEntry(alias, kp.getPrivate(), KEYSTORE_PASSWORD.toCharArray(), (java.security.cert.Certificate[]) certChain);
	          try (FileOutputStream writeStream = new FileOutputStream(keyStore)) {
	              ks.store(writeStream, keyPass.toCharArray());
	          }
	      }
	      return ks;
	  }
	  
	  
	  public static KeyPair GenrateandEncrypt(String keyname) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
	    {
	    	
	    	//generate my key pair 4096
	    	KeyPairGenerator kpg;
	        kpg = KeyPairGenerator.getInstance("RSA");
          kpg.initialize(4096);
          
          KeyPair kp = kpg.genKeyPair();
          PublicKey publicKey = kp.getPublic();
          PrivateKey privateKey = kp.getPrivate();

          //save keys 
          
         
          String sPublic = Base64.getEncoder().encodeToString( publicKey.getEncoded());
          String sPrivate = Base64.getEncoder().encodeToString( privateKey.getEncoded());

          File file1 = new File(keyname+"public.txt");
			FileWriter fileWriter1 = new FileWriter(file1);
			fileWriter1.write(sPublic);
			
			
			File file2 = new File(keyname+"private.txt");
			FileWriter fileWriter2 = new FileWriter(file2);
			fileWriter2.write(sPrivate);
			 
          fileWriter1.flush();
          fileWriter1.close();
          
          fileWriter2.flush();
          fileWriter2.close();
          ////////////
           
          return kp;
	    }
	  
	  @SuppressWarnings("deprecation")
	public static X509Certificate GenerateASelfSignedCerteficate(X500Principal dnName1,
	    		X500Principal dnName2, BigInteger  serialNumber ,PublicKey mypublicKey,
	    		PrivateKey myprivateKey, KeyUsage Keyus ) 
	            throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, 
	            NoSuchAlgorithmException, SignatureException
	    {
	    	   // build a certificate generator
			   X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		
             //Add the serial number
			   certGen.setSerialNumber(serialNumber);
			   certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
			   
			   //Issuer Id extension 
		       certGen.setIssuerDN(dnName1); 
		       
		       //Subject DN extension
			   certGen.setSubjectDN(dnName2);
			   
			   //Not before 
			   certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
			   
			   // Not After
			   certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
			   
			   //Set the public Key
			   certGen.setPublicKey(mypublicKey);
			   
			   //Sign the certificate
			   certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
			   certGen.addExtension(X509Extensions.KeyUsage, true, Keyus);
			   certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
	    	
			
			   
			   // finally, sign the certificate with the private key of the same KeyPair
			   Security.addProvider(new BouncyCastleProvider());
			   
			   X509Certificate certroot =  certGen.generate(myprivateKey,"BC");
			   
			   
	    	return certroot;
	    }
}
