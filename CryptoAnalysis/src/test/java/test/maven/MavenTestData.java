package test.maven;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class MavenTestData {
	List<MavenJar> jars;
	Map<Integer, String> errorMap;
	
	public MavenTestData() {
		jars = new LinkedList<>();
		errorMap = new HashMap<>();
		prepareData();
	}
	
	public void prepareData() {
		MavenJar jar1 = new MavenJar("de.unkrig.commons", "commons-lang", "1.2.11");
		jar1.addErrors("<de.unkrig.commons.lang.crypto.Encryptors: de.unkrig.commons.lang.crypto.Encryptor fromKey(java.security.Key)>", 
				"crypto.analysis.errors.ImpreciseValueExtractionError", 1);
				//TruePositive - Value couldn't be extracted statically for parameter of getInstance.
		jar1.addErrors("<de.unkrig.commons.lang.crypto.PasswordAuthenticationStores: de.unkrig.commons.lang.crypto.PasswordAuthenticationStore encryptPasswords(javax.crypto.SecretKey,de.unkrig.commons.lang.crypto.PasswordAuthenticationStore)>",
				"crypto.analysis.errors.IncompleteOperationError", 4);
		jar1.addErrors("<de.unkrig.commons.lang.crypto.Decryptors: de.unkrig.commons.lang.crypto.Decryptor fromKey(java.security.Key)>", 
				"crypto.analysis.errors.ImpreciseValueExtractionError", 1);
				//TruePositive - Value couldn't be extracted statically for parameter of getInstance.
		jar1.addErrors("<de.unkrig.commons.lang.crypto.SecretKeys: javax.crypto.SecretKey adHocSecretKey(java.io.File,char[],java.lang.String,char[])>", 
				"crypto.analysis.errors.TypestateError", 1);
				//*FalsePositive - call to load is done in loadKeyStoreFromFile method.
		jar1.addErrors("<de.unkrig.commons.lang.crypto.SecretKeys: void saveKeyStoreToFile(java.security.KeyStore,java.io.File,char[])>",
				"crypto.analysis.errors.TypestateError", 2);
				//*FalsePositive - TypeStateError should be for setEntry rather than getEntry and getKey. And setEntry is performed in one of the if blocks which cannot be determined statically. (For both the calls of saveKeyStoreToFile)
		jar1.addErrors("<de.unkrig.commons.lang.crypto.SecretKeys: javax.crypto.SecretKey adHocSecretKey(java.io.File,char[],java.lang.String,java.lang.String,java.lang.String,java.lang.String)>", 
				"crypto.analysis.errors.TypestateError", 1);
				//TruePositive - call to load is done in loadKeyStoreFromFile method. Other path
				//TODO Open an issue about if setKeyEntry is to be added to KeyStore.cryptsl file. Check the java docs. Open a ticket in git.
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(byte[],int,int)>",
				"crypto.analysis.errors.ConstraintError", 1);
				//TruePositive - parameter should be any of SHA-256, SHA-384, SHA-512
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(byte[],int,int)>", 
				"crypto.analysis.errors.ImpreciseValueExtractionError", 1);
				//TruePositive - Value couldn't be extracted statically for parameter of getInstance.
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(java.io.InputStream)>", 
				"crypto.analysis.errors.ConstraintError", 1);
				//TruePositive - parameter should be any of SHA-256, SHA-384, SHA-512
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(java.io.InputStream)>", 
				"crypto.analysis.errors.TypestateError", 1);
				//FalsePositive - Calls to gets, digest and update are in order but md has been used before even it is declared. TypestateError may be because of this.
				//TODO make documentation. Write test case to reproduce the same. Open a ticket in git.
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(java.io.InputStream)>", 
				"crypto.analysis.errors.ImpreciseValueExtractionError", 1);
				//TruePositive - Value couldn't be extracted statically for parameter of getInstance.
		jars.add(jar1);
		
		MavenJar jar2 = new MavenJar("com.github.t3t5u", "common-util", "1.0.0");
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: java.security.KeyPair generateKeyPair(java.lang.String)>",
				"crypto.analysis.errors.TypestateError", 1);
			//TruePositive - Missing call for init violating order constraint (line 23 in KeyPaiGenerator.cryptsl)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] init(javax.crypto.Cipher,int,java.security.Key)>", 
				"crypto.analysis.errors.ForbiddenMethodError", 1);
				//*FalsePositive - ForbiddenMethodError.
				//TODO Ask Melani for the issue. Test case for nocallto.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] init(javax.crypto.Cipher,int,java.security.Key)>", 
				"crypto.analysis.errors.RequiredPredicateError", 1);
				//*FalsePositive - key is just a parameter. It can be passed as random or not. But analysis considers it as not a random number.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
				//TruePositive - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				"crypto.analysis.errors.ImpreciseValueExtractionError", 1);
				//We cannot tell anything about this as analysis did not have enough information.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				"crypto.analysis.errors.TypestateError", 2);
				//FalsePositive - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher) if block
				//FalsePositive - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher) else block
				//TODO Make a test case.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doEncrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				"crypto.analysis.errors.TypestateError", 1);
				//FalsePositive - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				"crypto.analysis.errors.TypestateError", 1);
				//FalsePositive - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
				//TruePositive - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doEncrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
				//TruePositive - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] doEncrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				"crypto.analysis.errors.TypestateError", 1);
				//FalsePositive - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] encrypt(java.lang.String,java.security.Key,byte[])>",
				"crypto.analysis.errors.IncompleteOperationError", 1);
				//FalsePositive - It is just a man in the middle function. Calls to init and doFinal are carried out in encrypt function. But in the scope of encrypt this is TruePositive.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] encrypt(java.lang.String,java.security.Key,byte[],byte[])>",
				"crypto.analysis.errors.IncompleteOperationError", 1);
				//FalsePositive - It is just a man in the middle function. Calls to init and doFinal are carried out in callee (encrypt(four params)). But in the scope of encrypt this is TruePositive.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] decrypt(java.lang.String,java.security.Key,byte[])>",
				"crypto.analysis.errors.IncompleteOperationError", 1);
				//FalsePositive - It is just a man in the middle function. Calls to init and doFinal are carried out in doDncrypt function. But in the scope of encrypt this is TruePositive.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] decrypt(java.lang.String,java.security.Key,byte[],byte[])>",
				"crypto.analysis.errors.IncompleteOperationError", 1);
				//FalsePositive - It is just a man in the middle function. Calls to init and doFinal are carried out in callee (encrypt(four params)). But in the scope of encrypt this is TruePositive.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: java.security.Signature getSignature(java.lang.String,java.security.PrivateKey,byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
				//*FalsePositive - We cannot determine the value of privateKey statically in this context. 
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: byte[] init(javax.crypto.Cipher,int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>",
				"crypto.analysis.errors.RequiredPredicateError", 3);
				//FalsePositive - We cannot determine the value statically in this context.
				//FalsePositive - Two errors are shown for same variable preparedIV and preparedGCM
				//FalsePositive - Two errors are shown for same variable preparedIV and preparedGCM
				//TODO Make a test case.
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: javax.crypto.Cipher doInit(javax.crypto.Cipher,int,java.security.Key,byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
				//TruePositive - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)
		jar2.addErrors("<com.github.t3t5u.common.util.SecurityUtils: java.security.Signature getSignature(java.lang.String,java.security.PublicKey,byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
				//FalsePositive - We cannot determine the value of publicKey statically in this context. lack of information
		jars.add(jar2);
		
		MavenJar jar3 = new MavenJar("io.rubrica", "rubrica", "0.1.8");
		jar3.addErrors("<io.rubrica.util.OcspUtils: boolean isValidCertificate(java.security.cert.X509Certificate)>",
				"crypto.analysis.errors.TypestateError", 4);
		//TruePositive - Order is not being followed. (line 19 of TrustAnchor.cryptsl) [for all four different objects]
		jar3.addErrors("<io.rubrica.sign.odf.ODFSigner: byte[] sign(byte[],java.lang.String,java.security.PrivateKey,java.security.cert.Certificate[],java.util.Properties)>",
				"crypto.analysis.errors.TypestateError", 1);
		//TruePositive - reset is not called on message digest. (line 35 of MessageDigest.cryptsl)
		jar3.addErrors("<io.rubrica.sign.odf.ODFSigner: byte[] sign(byte[],java.lang.String,java.security.PrivateKey,java.security.cert.Certificate[],java.util.Properties)>",
				"crypto.analysis.errors.ConstraintError", 1);
		//TruePositive - Parameter should be of {"SHA-256", "SHA-384", "SHA-512"} but is SHA1. (line 38 in MessageDigest.cryptsl)
		jar3.addErrors("<io.rubrica.util.HttpClient: void disableSslChecks()>", "crypto.analysis.errors.ConstraintError", 1);
		//TruePositive - parameter should be in {"TLSv1", "TLSv1.1", "TLSv1.2"} but it is SSL. (line 28 in SSLContext.cryptsl)
		jar3.addErrors("<io.rubrica.util.HttpClient: void disableSslChecks()>", "crypto.analysis.errors.RequiredPredicateError", 2);
		//TruePositive - first parameter is not generated properly. (line 31 of SSLContext.cryptsl)
		//TruePositive - second parameter is not generated properly. (line 32 of SSLContext.cryptsl)
		jar3.addErrors("<io.rubrica.sign.Main: void main(java.lang.String[])>",  "crypto.analysis.errors.NeverTypeOfError", 1);
		//TruePositive - Parameter is of type string (line 47 in KeyStore.cryptsl)
		jar3.addErrors("<io.rubrica.keystore.FileKeyStoreProvider: java.security.KeyStore getKeystore(char[])>",  "crypto.analysis.errors.NeverTypeOfError", 1);
		//TruePositive - Parameter is of type string (line 47 in KeyStore.cryptsl)
		jars.add(jar3);
		
		MavenJar jar4 = new MavenJar("com.github.kcjang", "scmutil", "1.0.2.2");
		jar4.addErrors("<com.kichang.util.SSLTool: void disableCertificateValidation()>",
				"crypto.analysis.errors.RequiredPredicateError", 2);
				//*FalsePositive - They are using X509TrustManager for which cryptsl file is not present.
				//TruePostive - First parameter is null but we expect it to be an object of KeyManager (line 18 of SSLContext.cryptsl)
		jar4.addErrors("<com.kichang.util.SSLTool: void disableCertificateValidation()>",
				"crypto.analysis.errors.ConstraintError", 1);
				//TruePositive - First parameter should be in {TLSv1, TLSv1.1, TLSv1.2} but is SSL (line 28 in SSLContext.cryptsl)
		jar4.addErrors("<com.kichang.util.HttpsClientWithoutValidation: byte[] postData(java.lang.String,java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 2); 
				//TruePositive - KeyManager should be generated but is sent as null in first parameter.
				//*FalsePositive - They are using X509TrustManager for which cryptsl file is not present.
		jar4.addErrors("<com.kichang.util.HttpsClientWithoutValidation: byte[] postData(java.lang.String,java.lang.String)>",
				"crypto.analysis.errors.ConstraintError", 1);
				//TruePositive
		jar4.addErrors("<com.kichang.util.HttpsClientWithoutValidation: byte[] getHttps(java.lang.String)>",
				"crypto.analysis.errors.ConstraintError", 1);
				//TruePositive
		jar4.addErrors("<com.kichang.util.HttpsClientWithoutValidation: byte[] getHttps(java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 2);
				//TruePositive - KeyManager should be generated but is sent as null in first parameter.
				//*FalsePositive - They are using X509TrustManager for which cryptsl file is not present.
		jar4.addErrors("<com.kichang.util.Crypto: java.lang.String decrypt(java.lang.String,java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 3);
				//*FalsePositive - Randomization of second parameter is not up to the mark (Cipher)
				//TruePositive - Randomization of first parameter is not up to the mark. (SecretKeySpec)
				//TruePositive - Randomization of first parameter is not up to the mark (IvParameterSpec). They are just using hex value of 86afc43868fea6abd40fbf6d5ed50905
		jar4.addErrors("<com.kichang.util.Crypto: java.lang.String encrypt(java.lang.String,java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 4);
				//*FalsePositive - Randomization of second parameter is not up to the mark (Cipher)
				//TruePositive - Randomization of first parameter is not up to the mark. (SecretKeySpec)
				//TruePositive - Randomization of first parameter is not up to the mark (IvParameterSpec). They are just using hex value of 86afc43868fea6abd40fbf6d5ed50905
				//TruePositive - Third parameter was not properly preparedIV (Cipher - not passing callTo(iv) constraint in line 84 of Cipher.cryptsl)
		jar4.addErrors("<com.kichang.util.Crypto2: java.lang.String encrypt(java.lang.String,java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 4);
				//TruePositive - Third parameter was not properly preparedIV (Cipher - not passing callTo(iv) constraint in line 84 of Cipher.cryptsl)
				//TruePositive - Randomization of first parameter is not up to the mark (IvParameterSpec). They are just using hex value of 86afc43868fea6abd40fbf6d5ed50905
				//*FalsePositive - Randomization of second parameter is not up to the mark (Cipher)
				//TruePositive - Randomization of first parameter is not up to the mark. (SecretKeySpec)
		jars.add(jar4);
		
		MavenJar jar5 = new MavenJar("com.google.code.spring-crypto-utils", "spring-crypto-utils", "1.4.0");
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.KeyGeneratorImpl: void afterPropertiesSet()>", "crypto.analysis.errors.TypestateError", 2);
		//TruePositive - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [if block]
		//TruePositive - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [else block]
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.KeyGeneratorImpl: void afterPropertiesSet()>", "crypto.analysis.errors.ConstraintError", 2);
		//TruePositive - First parameter is not according to specification. It is DESede instead of {AES, Blowfish, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512} (line 27 in KeyGenerator.cryptsl) [if block]
		//TruePositive - First parameter is not according to specification. It is DESede instead of {AES, Blowfish, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512} (line 27 in KeyGenerator.cryptsl) [else block]
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.Base64EncodedKeyGeneratorImpl: void afterPropertiesSet()>", "crypto.analysis.errors.IncompleteOperationError", 2);
		//TruePositive - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [if block]
		//TruePositive - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [else block]
		jar5.addErrors("<com.springcryptoutils.core.signature.SignerImpl: byte[] sign(byte[])>", "crypto.analysis.errors.ConstraintError", 2);
		//TruePositive - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [if block]
		//TruePositive - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [else block]
		jar5.addErrors("<com.springcryptoutils.core.signature.SignerImpl: byte[] sign(byte[])>", "crypto.analysis.errors.RequiredPredicateError", 2);
		//*FalsePositive - Can be IncompleteOperationError since there is no enough information regarding the privatekey used.
		//*FalsePositive - Same error repeated again
		jar5.addErrors("<com.springcryptoutils.core.signature.VerifierImpl: boolean verify(byte[],byte[])>", "crypto.analysis.errors.ConstraintError", 2);
		//TruePositive - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [if block]
		//TruePositive - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [else block]
		jar5.addErrors("<com.springcryptoutils.core.signature.VerifierImpl: boolean verify(byte[],byte[])>", "crypto.analysis.errors.RequiredPredicateError", 2);
		//*FalsePositive - Can be IncompleteOperationError since there is no enough information regarding the publickey used.
		//*FalsePositive - Same error repeated again
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.CiphererImpl: byte[] encrypt(byte[],byte[],byte[])>", "crypto.analysis.errors.RequiredPredicateError", 10);
		//*FalsePositive - Can be IncompleteOperationError as the key is passed as a parameter but analysis reports as RequiredPredicateError. SecretKeySpec(key, this.keyAlgorithm).
		//*FalsePositive - Can be IncompleteOperationError as the key is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(1, skey, initializationVectorSpec). case ENCRYPT
		//*FalsePositive - Can be IncompleteOperationError as the key is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(2, skey, initializationVectorSpec). case DECRYPT
		//*FalsePositive - Can be IncompleteOperationError as the initializationVector is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(1, skey, initializationVectorSpec). case ENCRYPT
		//*FalsePositive - Can be IncompleteOperationError as the initializationVector is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(2, skey, initializationVectorSpec). case DECRYPT
		//FalsePositive - repeated
		//FalsePositive - repeated
		//FalsePositive - repeated
		//*FalsePositive - Can be IncompleteOperationError as the initializationVector is passed as a parameter but analysis reports as RequiredPredicateError. new IvParameterSpec(initializationVector)
		//FalsePositive - repeated
		jar5.addErrors("<com.springcryptoutils.core.cipher.asymmetric.Base64EncodedCiphererWithChooserByKeyIdImpl: java.lang.String encrypt(java.lang.String,java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 4);
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter. case ENCRYPT
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter. case DECRYPT
		//FalsePositive - repeat
		//FalsePositive - repeat
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererImpl: java.lang.String encrypt(java.lang.String,java.lang.String,java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 10);
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case DECRYPT
		//FalsePositive - repeat
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function.
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case DECRYPT
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case ENCRYPT
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case ENCRYPT
		//FalsePositive - repeat [case ENCRYPT]
		//FalsePositive - repeat [case ENCRYPT]
		//FalsePositive - repeat [case DECRYPT]
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function.
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.CiphererWithStaticKeyImpl: byte[] encrypt(byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 8);
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (second parameter) [case DECRYPT]
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (third parameter) [case DECRYPT]
		//FalsePositive - repeat (second parameter) [case DECRYPT]
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (third parameter) [case ENCRYPT]
		//*FalsePositive - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (second parameter) [case ENCRYPT]
		//FalsePositive - repeat (second parameter) [case ENCRYPT]
		//FalsePositive - repeat (third parameter) [case ENCRYPT]
		//FalsePositive - repeat (third parameter) [case DECRYPT]
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.CiphererWithStaticKeyImpl: void setInitializationVector(java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
		//*FalsePositive - There is no enough information about the initializationVector passed as the parameter.
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.CiphererWithStaticKeyImpl: void afterPropertiesSet()>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
		//*FalsePositive - There is no enough information about the parameter.
		jar5.addErrors("<com.springcryptoutils.core.cipher.asymmetric.Base64EncodedCiphererImpl: java.lang.String encrypt(java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 4);
		//*FalsePositive - There is no enough information about the parameter. [case DECRYPT]
		//FalsePositive - repeat [case DECRYPT]
		//*FalsePositive - There is no enough information about the parameter. [case ENCRYPT]
		//FalsePositive - repeat [case ENCRYPT]
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererWithStaticKeyImpl: java.lang.String encrypt(java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 8);
		//*FalsePositive - There is no enough information about the parameter. (second parameter) [case ENCRYPT]
		//*FalsePositive - There is no enough information about the parameter. (third parameter) [case DECRYPT]
		//*FalsePositive - There is no enough information about the parameter. (third parameter) [case ENCRYPT]
		//FalsePositive - repeat (third parameter) [case ENCRYPT]
		//*FalsePositive - There is no enough information about the parameter. (second parameter) [case DECRYPT]
		//FalsePositive - repeat (second parameter) [case DECRYPT]
		//FalsePositive - repeat (second parameter) [case ENCRYPT]
		//FalsePositive - repeat (third parameter) [case DECRYPT]
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererWithStaticKeyImpl: void setInitializationVector(java.lang.String)>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
		//*FalsePositive - There is no enough information about the initializationVector passed as the parameter.
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererWithStaticKeyImpl: void afterPropertiesSet()>",
				"crypto.analysis.errors.RequiredPredicateError", 1);
		//*FalsePositive - There is no enough information about the parameter.
		jar5.addErrors("<com.springcryptoutils.core.cipher.asymmetric.CiphererWithChooserByKeyIdImpl: byte[] encrypt(java.lang.String,byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 4);
		//*FalsePositive - key is passed as a parameter. There is no enough information about it (second parameter) [case ENCRYPT]
		//*FalsePositive - key is passed as a parameter. There is no enough information about it (second parameter) [case DECRYPT]
		//FalsePositive - repeat (second parameter) [case DECRYPT]
		//FalsePositive - repeat (second parameter) [case ENCRYPT]
		jar5.addErrors("<com.springcryptoutils.core.cipher.asymmetric.CiphererImpl: byte[] encrypt(byte[])>",
				"crypto.analysis.errors.RequiredPredicateError", 4);
		//*FalsePositive - key is passed as a parameter. There is no enough information about it (second parameter) [case DECRYPT]
		//FalsePositive - repeat (second parameter) [case DECRYPT]
		//*FalsePositive - key is passed as a parameter. There is no enough information about it (second parameter) [case ENCRYPT]
		//FalsePositive - repeat (second parameter) [case ENCRYPT]
		jars.add(jar5);
		
		MavenJar jar6 = new MavenJar("com.github.emc-mongoose", "mongoose-storage-driver-atmos", "0.1.6");
		jar6.addErrors("<com.emc.mongoose.storage.driver.atmos.AtmosStorageDriver: javax.crypto.Mac lambda$static$0(java.lang.String)>", "crypto.analysis.errors.IncompleteOperationError", 1);
		jar6.addErrors("<com.emc.mongoose.storage.driver.atmos.AtmosStorageDriver: javax.crypto.Mac lambda$static$0(java.lang.String)>", "crypto.analysis.errors.RequiredPredicateError", 1);
		jars.add(jar6);
	}
}
