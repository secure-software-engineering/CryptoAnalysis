package test.maven;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import crypto.analysis.errors.ConstraintError;
import crypto.analysis.errors.ForbiddenMethodError;
import crypto.analysis.errors.ImpreciseValueExtractionError;
import crypto.analysis.errors.IncompleteOperationError;
import crypto.analysis.errors.NeverTypeOfError;
import crypto.analysis.errors.RequiredPredicateError;
import crypto.analysis.errors.TypestateError;

public class MavenTestData {
	List<MavenJar> jars;
	Map<Integer, String> errorMap;
	List<String> errorDescs;

	public MavenTestData() {
		jars = new LinkedList<>();
		errorMap = new HashMap<>();
		errorDescs = new ArrayList<>();
		prepareData();
	}

	public void prepareData() {
		MavenJar jar1 = new MavenJar("de.unkrig.commons", "commons-lang", "1.2.11");
		errorDescs.add(MavenJar.TP + " - Value couldn't be extracted statically for parameter of getInstance.");
		jar1.addErrors(
				"<de.unkrig.commons.lang.crypto.Encryptors: de.unkrig.commons.lang.crypto.Encryptor fromKey(java.security.Key)>",
				ImpreciseValueExtractionError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FN);
		errorDescs.add(MavenJar.FN);
		errorDescs.add(MavenJar.FN);
		errorDescs.add(MavenJar.FN);
		jar1.addErrors(
				"<de.unkrig.commons.lang.crypto.PasswordAuthenticationStores: de.unkrig.commons.lang.crypto.PasswordAuthenticationStore encryptPasswords(javax.crypto.SecretKey,de.unkrig.commons.lang.crypto.PasswordAuthenticationStore)>",
				IncompleteOperationError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - Value couldn't be extracted statically for parameter of getInstance.");
		jar1.addErrors(
				"<de.unkrig.commons.lang.crypto.Decryptors: de.unkrig.commons.lang.crypto.Decryptor fromKey(java.security.Key)>",
				ImpreciseValueExtractionError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FP + " - call to load is done in loadKeyStoreFromFile method.");
		jar1.addErrors(
				"<de.unkrig.commons.lang.crypto.SecretKeys: javax.crypto.SecretKey adHocSecretKey(java.io.File,char[],java.lang.String,char[])>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - TypeStateError should be for setEntry rather than getEntry and getKey. And setEntry is performed in one of the if blocks which cannot be determined statically.");
		errorDescs.add(MavenJar.TP
				+ " - TypeStateError should be for setEntry rather than getEntry and getKey. And setEntry is performed in one of the if blocks which cannot be determined statically.");
		jar1.addErrors(
				"<de.unkrig.commons.lang.crypto.SecretKeys: void saveKeyStoreToFile(java.security.KeyStore,java.io.File,char[])>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - call to load is done in loadKeyStoreFromFile method in other path");
		jar1.addErrors(
				"<de.unkrig.commons.lang.crypto.SecretKeys: javax.crypto.SecretKey adHocSecretKey(java.io.File,char[],java.lang.String,java.lang.String,java.lang.String,java.lang.String)>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - parameter should be any of SHA-256, SHA-384, SHA-512");
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(byte[],int,int)>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - Value couldn't be extracted statically for parameter of getInstance.");
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(byte[],int,int)>",
				ImpreciseValueExtractionError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - parameter should be any of SHA-256, SHA-384, SHA-512");
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(java.io.InputStream)>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FP
				+ " - Call to update is done inside for loop which converts to if and else statements in jimple. So, there exists a path with out update call which is reported by analysis.");
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(java.io.InputStream)>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - Value couldn't be extracted statically for parameter of getInstance.");
		jar1.addErrors("<de.unkrig.commons.lang.crypto.MD5: byte[] of(java.io.InputStream)>",
				ImpreciseValueExtractionError.class, errorDescs);
		errorDescs.clear();

		jars.add(jar1);

		errorDescs = new ArrayList<>();
		MavenJar jar2 = new MavenJar("com.github.t3t5u", "common-util", "1.0.0");
		errorDescs.add(MavenJar.TP
				+ " - Missing call for init violating order constraint (line 23 in KeyPaiGenerator.cryptsl)");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: java.security.KeyPair generateKeyPair(java.lang.String)>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FP + " - ");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] init(javax.crypto.Cipher,int,java.security.Key)>",
				ForbiddenMethodError.class, errorDescs);
		errorDescs.clear();
		// TODO Ask Melani for the issue. Test case for nocallto.

		errorDescs.add(MavenJar.TP + " - key is just a parameter. It can be passed as random or not.");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] init(javax.crypto.Cipher,int,java.security.Key)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(
				MavenJar.TP + " - We cannot tell anything about this as analysis did not have enough information.");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				ImpreciseValueExtractionError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FP
				+ " - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher) if block");
		errorDescs.add(MavenJar.FP
				+ " - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher) else block");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				TypestateError.class, errorDescs);
		errorDescs.clear();
		//Test case - issue66.issueOne

		errorDescs.add(MavenJar.FP
				+ " - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher) if block");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doEncrypt(javax.crypto.Cipher,java.security.Key,byte[])>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FP
				+ " - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher)");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doDecrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doEncrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FP
				+ " - init is done in doInit function but analysis reports that init is not called before doFinal. (Cipher)");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] doEncrypt(javax.crypto.Cipher,java.security.Key,byte[],byte[])>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP);
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] encrypt(java.lang.String,java.security.Key,byte[])>",
				IncompleteOperationError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP);
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] encrypt(java.lang.String,java.security.Key,byte[],byte[])>",
				IncompleteOperationError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP);
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] decrypt(java.lang.String,java.security.Key,byte[])>",
				IncompleteOperationError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP);
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] decrypt(java.lang.String,java.security.Key,byte[],byte[])>",
				IncompleteOperationError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - We cannot determine the value of privateKey statically in this context.");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: java.security.Signature getSignature(java.lang.String,java.security.PrivateKey,byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.FP + " - We cannot determine the value statically in this context.");
		errorDescs.add(MavenJar.FP + " - Two errors are shown for same variable preparedIV and preparedGCM");
		errorDescs.add(MavenJar.FP + " - Two errors are shown for same variable preparedIV and preparedGCM");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: byte[] init(javax.crypto.Cipher,int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();
		// TODO Make a test case.

		errorDescs.add(MavenJar.TP
				+ " - Just taking the subarray from input which is not properly randomised for IvParameterSpec (line 14 of IvParameterSpec.cryptsl)");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: javax.crypto.Cipher doInit(javax.crypto.Cipher,int,java.security.Key,byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - We cannot determine the value of publicKey statically in this context. lack of information");
		jar2.addErrors(
				"<com.github.t3t5u.common.util.SecurityUtils: java.security.Signature getSignature(java.lang.String,java.security.PublicKey,byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		jars.add(jar2);

		errorDescs = new ArrayList<>();
		MavenJar jar3 = new MavenJar("io.rubrica", "rubrica", "0.1.8");
		errorDescs.add(MavenJar.TP + " - Order is not being followed. (line 19 of TrustAnchor.cryptsl)");
		errorDescs.add(MavenJar.TP + " - Order is not being followed. (line 19 of TrustAnchor.cryptsl)");
		errorDescs.add(MavenJar.TP + " - Order is not being followed. (line 19 of TrustAnchor.cryptsl)");
		errorDescs.add(MavenJar.TP + " - Order is not being followed. (line 19 of TrustAnchor.cryptsl)");
		jar3.addErrors("<io.rubrica.util.OcspUtils: boolean isValidCertificate(java.security.cert.X509Certificate)>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - reset is not called on message digest. (line 35 of MessageDigest.cryptsl)");
		jar3.addErrors(
				"<io.rubrica.sign.odf.ODFSigner: byte[] sign(byte[],java.lang.String,java.security.PrivateKey,java.security.cert.Certificate[],java.util.Properties)>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Parameter should be of {\"SHA-256\", \"SHA-384\", \"SHA-512\"} but is SHA1. (line 38 in MessageDigest.cryptsl)");
		jar3.addErrors(
				"<io.rubrica.sign.odf.ODFSigner: byte[] sign(byte[],java.lang.String,java.security.PrivateKey,java.security.cert.Certificate[],java.util.Properties)>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - parameter should be in {\"TLSv1\", \"TLSv1.1\", \"TLSv1.2\"} but it is SSL. (line 28 in SSLContext.cryptsl)");
		jar3.addErrors("<io.rubrica.util.HttpClient: void disableSslChecks()>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - first parameter is not generated properly. (line 31 of SSLContext.cryptsl)");
		errorDescs.add(MavenJar.TP + " - second parameter is not generated properly. (line 32 of SSLContext.cryptsl)");
		jar3.addErrors("<io.rubrica.util.HttpClient: void disableSslChecks()>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - Parameter is of type string (line 47 in KeyStore.cryptsl)");
		jar3.addErrors("<io.rubrica.sign.Main: void main(java.lang.String[])>",
				NeverTypeOfError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - Parameter is of type string (line 47 in KeyStore.cryptsl)");
		jar3.addErrors("<io.rubrica.keystore.FileKeyStoreProvider: java.security.KeyStore getKeystore(char[])>",
				NeverTypeOfError.class, errorDescs);

		errorDescs.clear();
		jars.add(jar3);

		errorDescs = new ArrayList<>();
		MavenJar jar4 = new MavenJar("com.github.kcjang", "scmutil", "1.0.2.2");
		errorDescs.add(MavenJar.FP + " - They are using X509TrustManager for which cryptsl file is not present.");
		errorDescs.add(MavenJar.TP
				+ " - First parameter is null but we expect it to be an object of KeyManager (line 18 of SSLContext.cryptsl)");
		jar4.addErrors("<com.kichang.util.SSLTool: void disableCertificateValidation()>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - First parameter should be in {TLSv1, TLSv1.1, TLSv1.2} but is SSL (line 28 in SSLContext.cryptsl)");
		jar4.addErrors("<com.kichang.util.SSLTool: void disableCertificateValidation()>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - KeyManager should be generated but is sent as null in first parameter.");
		errorDescs.add(MavenJar.FP + " - They are using X509TrustManager for which cryptsl file is not present.");
		jar4.addErrors(
				"<com.kichang.util.HttpsClientWithoutValidation: byte[] postData(java.lang.String,java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP);
		jar4.addErrors(
				"<com.kichang.util.HttpsClientWithoutValidation: byte[] postData(java.lang.String,java.lang.String)>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP);
		jar4.addErrors("<com.kichang.util.HttpsClientWithoutValidation: byte[] getHttps(java.lang.String)>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - KeyManager should be generated but is sent as null in first parameter.");
		errorDescs.add(MavenJar.FP + " - They are using X509TrustManager for which cryptsl file is not present.");
		jar4.addErrors("<com.kichang.util.HttpsClientWithoutValidation: byte[] getHttps(java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - Randomization of second parameter is not up to the mark (Cipher)");
		errorDescs.add(MavenJar.TP + " - Randomization of first parameter is not up to the mark. (SecretKeySpec)");
		errorDescs.add(MavenJar.TP
				+ " - Randomization of first parameter is not up to the mark (IvParameterSpec). They are just using hex value of 86afc43868fea6abd40fbf6d5ed50905");
		jar4.addErrors("<com.kichang.util.Crypto: java.lang.String decrypt(java.lang.String,java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - Randomization of second parameter is not up to the mark (Cipher)");
		errorDescs.add(MavenJar.TP + " - Randomization of first parameter is not up to the mark. (SecretKeySpec)");
		errorDescs.add(MavenJar.TP
				+ " - Randomization of first parameter is not up to the mark (IvParameterSpec). They are just using hex value of 86afc43868fea6abd40fbf6d5ed50905");
		errorDescs.add(MavenJar.TP
				+ " - Third parameter was not properly preparedIV (Cipher - not passing callTo(iv) constraint in line 84 of Cipher.cryptsl)");
		jar4.addErrors("<com.kichang.util.Crypto: java.lang.String encrypt(java.lang.String,java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Third parameter was not properly preparedIV (Cipher - not passing callTo(iv) constraint in line 84 of Cipher.cryptsl)");
		errorDescs.add(MavenJar.TP
				+ " - Randomization of first parameter is not up to the mark (IvParameterSpec). They are just using hex value of 86afc43868fea6abd40fbf6d5ed50905");
		errorDescs.add(MavenJar.TP + " - Randomization of second parameter is not up to the mark (Cipher)");
		errorDescs.add(MavenJar.TP + " - Randomization of first parameter is not up to the mark. (SecretKeySpec)");
		jar4.addErrors("<com.kichang.util.Crypto2: java.lang.String encrypt(java.lang.String,java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		jars.add(jar4);

		errorDescs = new ArrayList<>();
		MavenJar jar5 = new MavenJar("com.google.code.spring-crypto-utils", "spring-crypto-utils", "1.4.0");
		errorDescs.add(MavenJar.TP
				+ " - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [if block]");
		errorDescs.add(MavenJar.TP
				+ " - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [else block]");
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.KeyGeneratorImpl: void afterPropertiesSet()>",
				TypestateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - First parameter is not according to specification. It is DESede instead of {AES, Blowfish, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512} (line 27 in KeyGenerator.cryptsl) [if block]");
		errorDescs.add(MavenJar.TP
				+ " - First parameter is not according to specification. It is DESede instead of {AES, Blowfish, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512} (line 27 in KeyGenerator.cryptsl) [else block]");
		jar5.addErrors("<com.springcryptoutils.core.cipher.symmetric.KeyGeneratorImpl: void afterPropertiesSet()>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [if block]");
		errorDescs.add(MavenJar.TP
				+ " - Order is not followed in the function afterPropertiesSet. But it is followed if generate() is called after afterPropertiesSet(). (line 24 in KeyGenerator.cryptsl) [else block]");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.Base64EncodedKeyGeneratorImpl: void afterPropertiesSet()>",
				IncompleteOperationError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [if block]");
		errorDescs.add(MavenJar.TP
				+ " - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [else block]");
		jar5.addErrors("<com.springcryptoutils.core.signature.SignerImpl: byte[] sign(byte[])>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError since there is no enough information regarding the privatekey used.");
		errorDescs.add(MavenJar.FP
				+ " - Can be IncompleteOperationError since there is no enough information regarding the privatekey used.");
		jar5.addErrors("<com.springcryptoutils.core.signature.SignerImpl: byte[] sign(byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [if block]");
		errorDescs.add(MavenJar.TP
				+ " - First parameter is SHA1withRSA, but should be in {NONEwithDSA, SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA256withRSA, SHA256withECDSA}. (line 44 in Signature.cryptsl) [else block]");
		jar5.addErrors("<com.springcryptoutils.core.signature.VerifierImpl: boolean verify(byte[],byte[])>",
				ConstraintError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError since there is no enough information regarding the publickey used.");
		errorDescs.add(MavenJar.FP
				+ " - Can be IncompleteOperationError since there is no enough information regarding the publickey used.");
		jar5.addErrors("<com.springcryptoutils.core.signature.VerifierImpl: boolean verify(byte[],byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError as the key is passed as a parameter but analysis reports as RequiredPredicateError. SecretKeySpec(key, this.keyAlgorithm).");
		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError as the key is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(1, skey, initializationVectorSpec). case ENCRYPT");
		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError as the key is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(2, skey, initializationVectorSpec). case DECRYPT");
		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError as the initializationVector is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(1, skey, initializationVectorSpec). case ENCRYPT");
		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError as the initializationVector is passed as a parameter but analysis reports as RequiredPredicateError. cipher.init(2, skey, initializationVectorSpec). case DECRYPT");
		errorDescs.add(MavenJar.FP + " - repeated");
		errorDescs.add(MavenJar.FP + " - repeated");
		errorDescs.add(MavenJar.FP + " - repeated");
		errorDescs.add(MavenJar.TP
				+ " - Can be IncompleteOperationError as the initializationVector is passed as a parameter but analysis reports as RequiredPredicateError. new IvParameterSpec(initializationVector)");
		errorDescs.add(MavenJar.FP + " - repeated");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.CiphererImpl: byte[] encrypt(byte[],byte[],byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter. case ENCRYPT");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter. case DECRYPT");
		errorDescs.add(MavenJar.FP + " - repeated");
		errorDescs.add(MavenJar.FP + " - repeated");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.asymmetric.Base64EncodedCiphererWithChooserByKeyIdImpl: java.lang.String encrypt(java.lang.String,java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case DECRYPT");
		errorDescs.add(MavenJar.FP + " - repeated");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function.");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case DECRYPT");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case ENCRYPT");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. case ENCRYPT");
		errorDescs.add(MavenJar.FP + " - repeated [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeated [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeated [case DECRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function.");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererImpl: java.lang.String encrypt(java.lang.String,java.lang.String,java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (third parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (third parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information to calculate if the parameter is generated properly. It is passed as a parameter to the function. (second parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (third parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (third parameter) [case DECRYPT]");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.CiphererWithStaticKeyImpl: byte[] encrypt(byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - There is no enough information about the initializationVector passed as the parameter.");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.CiphererWithStaticKeyImpl: void setInitializationVector(java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - There is no enough information about the parameter.");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.CiphererWithStaticKeyImpl: void afterPropertiesSet()>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - There is no enough information about the parameter. [case DECRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat [case DECRYPT]");
		errorDescs.add(MavenJar.TP + " - There is no enough information about the parameter. [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat [case ENCRYPT]");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.asymmetric.Base64EncodedCiphererImpl: java.lang.String encrypt(java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - There is no enough information about the parameter. (second parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information about the parameter. (third parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information about the parameter. (third parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (third parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - There is no enough information about the parameter. (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (third parameter) [case DECRYPT]");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererWithStaticKeyImpl: java.lang.String encrypt(java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - There is no enough information about the initializationVector passed as the parameter.");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererWithStaticKeyImpl: void setInitializationVector(java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP + " - There is no enough information about the parameter.");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.symmetric.Base64EncodedCiphererWithStaticKeyImpl: void afterPropertiesSet()>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - key is passed as a parameter. There is no enough information about it (second parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - key is passed as a parameter. There is no enough information about it (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case ENCRYPT]");
		jar5.addErrors(
				"<com.springcryptoutils.core.cipher.asymmetric.CiphererWithChooserByKeyIdImpl: byte[] encrypt(java.lang.String,byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		errorDescs.add(MavenJar.TP
				+ " - key is passed as a parameter. There is no enough information about it (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case DECRYPT]");
		errorDescs.add(MavenJar.TP
				+ " - key is passed as a parameter. There is no enough information about it (second parameter) [case ENCRYPT]");
		errorDescs.add(MavenJar.FP + " - repeat (second parameter) [case ENCRYPT]");
		jar5.addErrors("<com.springcryptoutils.core.cipher.asymmetric.CiphererImpl: byte[] encrypt(byte[])>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();

		jars.add(jar5);

		errorDescs = new ArrayList<>();
		MavenJar jar6 = new MavenJar("com.github.emc-mongoose", "mongoose-storage-driver-atmos", "0.1.6");
		errorDescs.add(MavenJar.TP + " - ");
		jar6.addErrors(
				"<com.emc.mongoose.storage.driver.atmos.AtmosStorageDriver: javax.crypto.Mac lambda$static$0(java.lang.String)>",
				IncompleteOperationError.class, errorDescs);
		errorDescs.clear();
		errorDescs.add(MavenJar.TP + " - ");
		jar6.addErrors(
				"<com.emc.mongoose.storage.driver.atmos.AtmosStorageDriver: javax.crypto.Mac lambda$static$0(java.lang.String)>",
				RequiredPredicateError.class, errorDescs);
		errorDescs.clear();
		jars.add(jar6);
	}
}
