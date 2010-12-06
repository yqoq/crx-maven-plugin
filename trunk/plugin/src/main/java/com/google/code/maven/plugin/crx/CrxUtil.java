package com.google.code.maven.plugin.crx;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.codehaus.plexus.util.Base64;

/**
 * Build CRX files. Similar to running this command:
 * 
 * <pre>
 * /Applications/Google Chrome.app/Contents/MacOS/Google Chrome \
 *   --enable-apps \
 *   --pack-extension=src/main/webapp \
 *   --pack-extension-key=my_app.pem \
 *   --no-message-box
 * </pre>
 * 
 * http://www.madboa.com/geek/openssl/
 * 
 * <pre>
 * # Chrome generates key pairs by doing these two steps:
 * # 1) create 1024 bit key 
 * openssl genrsa -out keypair.pem 1024
 * # 2) change format to pkcs8
 * openssl pkcs8 -topk8 -in keypair.pem -inform pem -out keypair_pk8.pem -outform pem -nocrypt
 * 
 * # to extract the public key from an RSA private key, try: 
 * openssl rsa -in mykey.pem -pubout > public.pem
 * </pre>
 * 
 * @author <a href="mailto:jasonthrasher@gmail.com">Jason Thrasher</a>
 */
public class CrxUtil {
	private static final String MAGIC = "Cr24";
	private static final int EXT_VERSION = 2;
	private static final int KEY_SIZE = 1024;

	private byte[] privateKey2;
	private byte[] cert;

	public CrxUtil(File pemKey, File pemCert) throws NoSuchAlgorithmException,
			InvalidKeySpecException, IOException {
		privateKey2 = pemToDer(getFileBytes(pemKey));
		cert = pemToDer(getFileBytes(pemCert));
	}

	/**
	 * Build the CRX file.
	 * 
	 * @param webappDir
	 * @param crxFilename
	 * @return the CRX file.
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public File buildCrx(String crxFilename, File webappDir)
			throws IOException, GeneralSecurityException {
		if (webappDir == null || !webappDir.isDirectory()) {
			throw new RuntimeException("cannot build CRX from directory: "
					+ webappDir);
		}

		// check manifest
		File manifest = new File(webappDir, "manifest.json");
		if (!manifest.exists()) {
			throw new FileNotFoundException("manifest not found: " + manifest);
		}

		return buildCrx(crxFilename, webappStructure(webappDir));
	}

	public File buildCrx(String crxFilename, File webappDir, String[] include)
			throws IOException, GeneralSecurityException {

		Map<String, File> files = new HashMap<String, File>();
		FilenameFilter filter = new FilesOnlyFilenameFilter();

		for (String shortPath : include) {
			System.out.println("shortPath: " + shortPath);
			if (filter.accept(webappDir, shortPath)) {
				File file = new File(webappDir, shortPath);
				System.out.println("file path: " + file);
				files.put(shortPath, file);
			}
		}

		return buildCrx(crxFilename, files);
	}

	private File buildCrx(String crxFilename, Map<String, File> files)
			throws IOException, GeneralSecurityException {
		File zip = File.createTempFile("crx", ".temp.zip");
		doZip(files, zip);

		PrivateKey privateKey = getPrivateKey(privateKey2);
		byte[] signature = sign(privateKey, zip);

		File crx = new File(crxFilename);
		DataOutputStream out = new DataOutputStream(new BufferedOutputStream(
				new FileOutputStream(crxFilename)));

		ByteBuffer bb = ByteBuffer.allocate(Integer.SIZE / Byte.SIZE);
		bb.order(ByteOrder.LITTLE_ENDIAN);

		out.write(MAGIC.getBytes("UTF-8"));
		out.write(bb.putInt(0, EXT_VERSION).array());
		out.write(bb.putInt(0, cert.length).array());
		out.write(bb.putInt(0, signature.length).array());
		out.write(cert);
		out.write(signature);

		BufferedInputStream in = new BufferedInputStream(new FileInputStream(
				zip));
		int len = 0;
		byte[] buff = new byte[1024 * 10];
		while ((len = in.read(buff)) != -1) {
			out.write(buff, 0, len);
		}

		out.close();

		return crx;

	}

	/**
	 * Read the file's data into a byte array.
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	private static byte[] getFileBytes(File file) throws IOException {
		byte[] data = new byte[(int) file.length()];

		DataInputStream in = new DataInputStream(new FileInputStream(file));
		in.readFully(data);
		in.close();

		return data;
	}

	private static PrivateKey getPrivateKey(byte[] der) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException {

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		// decode private key
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(der);
		RSAPrivateKey privKey = (RSAPrivateKey) keyFactory
				.generatePrivate(privSpec);

		return privKey;
	}

	private static PublicKey getPublicKey(byte[] der)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		// decode public key
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(der);
		RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);

		return pubKey;
	}

	/**
	 * Convert a PEM format file into a DER format file.
	 * 
	 * PEM files consist of a header, body and footer as ASCII characters with
	 * the body being the Base64 encoded content of the DER file. You can
	 * convert PEM to DER in two obvious ways -
	 * 
	 * 1) Use openssl to convert the PEM to DER using something like
	 * 
	 * openssl rsa -inform PEM -in rsapriv.pem -outform DER -pubout -out
	 * rsapub.der openssl pkcs8 -topk8 -inform PEM -in rsapriv.pem -outform DER
	 * -nocrypt -out rsapriv.der
	 * 
	 * Check the openssl 'man page' for further details.
	 * 
	 * -OR-
	 * 
	 * 2) Within your Java, strip the header and footer and then Base64 decode
	 * the body before using the body to create the keys.
	 * 
	 * @param pem
	 * @return
	 */
	private static byte[] pemToDer(byte[] pem) {
		String privateKeyStr = new String(pem);
		int pemStartIndex = privateKeyStr.indexOf("\n") + 1;
		int pemEndIndex = privateKeyStr.indexOf("-----END");

		String pemBody = privateKeyStr.substring(pemStartIndex, pemEndIndex);

		return Base64.decodeBase64(pemBody.getBytes());
	}

	/**
	 * Signs the data with the given key and the provided algorithm.
	 * 
	 * @throws IOException
	 */
	private static byte[] sign(PrivateKey priavetKey, File zip)
			throws GeneralSecurityException, IOException {

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(priavetKey);

		BufferedInputStream in = new BufferedInputStream(new FileInputStream(
				zip));
		byte[] buff = new byte[1024 * 10];
		int len = 0;
		while ((len = in.read(buff)) != -1) {
			signature.update(buff, 0, len);
		}
		return signature.sign();
	}

	/**
	 * Zip up a bunch of files.
	 * 
	 * @throws IOException
	 * @throws Exception
	 */
	private static long doZip(Map<String, File> zipStructure, File zipFile)
			throws IOException {
		// sort the files by key
		TreeMap<String, File> sortedStructure = new TreeMap<String, File>();
		sortedStructure.putAll(zipStructure);

		// Create the ZIP file
		ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zipFile));
		out.setComment("created with my program");
		out.setMethod(ZipOutputStream.DEFLATED);// DEFLATED or STORED
		out.setLevel(Deflater.DEFAULT_COMPRESSION);// Deflater.NO_COMPRESSION

		// Create a buffer for reading the files
		byte[] buf = new byte[1024 * 10];

		// Compress the files
		for (String key : sortedStructure.keySet()) {
			FileInputStream in = new FileInputStream(sortedStructure.get(key));

			// Add ZIP entry to output stream.
			out.putNextEntry(new ZipEntry(key));

			// Transfer bytes from the file to the ZIP file
			int len;
			while ((len = in.read(buf)) > 0) {
				out.write(buf, 0, len);
			}

			// Complete the entry
			out.closeEntry();
			in.close();
		}

		// Complete the ZIP file
		out.close();

		return zipFile.length();
	}

	// TODO: accept includes and excludes filters as argument here
	private static HashMap<String, File> webappStructure(File webappDir) {
		// find all files
		File[] files = FileUtil.listFilesAsArray(webappDir,
				new FilesOnlyFilenameFilter(), true);

		// map structure keys relative to webappDirectory
		HashMap<String, File> struct = new HashMap<String, File>(files.length);
		for (File f : files) {
			// key relative path into the zip file, strip seperator
			String key = f.getAbsolutePath().substring(
					webappDir.getAbsolutePath().length() + 1);
			struct.put(key, f);
		}

		return struct;
	}

	/**
	 * Create a private/public key pair in DER format.
	 * 
	 * @see http://code.google.com/apis/apps/articles/sso-keygen.html#UsingJCA
	 * 
	 * @param derPrivateKey
	 * @param derPublicKey
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 */
	private static void genRsaKeypairDer(File derPrivateKey, File derPublicKey)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			IOException {
		// Generate a 1024-bit RSA key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "SUN");
		// "SHA1PRNG", "SUN"
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(KEY_SIZE, random);

		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();

		byte[] encPriv = priv.getEncoded();
		FileOutputStream privfos = new FileOutputStream(derPrivateKey);
		privfos.write(encPriv);
		privfos.close();

		byte[] encPub = pub.getEncoded();
		FileOutputStream pubfos = new FileOutputStream(derPublicKey);
		pubfos.write(encPub);
		pubfos.close();

	}

	private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
	private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

	private static String derPrivateKeyToPemPrivateKey(byte[] privateKeyBytes)
			throws IOException {
		StringBuilder sb = new StringBuilder();

		ByteArrayOutputStream baos = new ByteArrayOutputStream(
				privateKeyBytes.length);
		baos.write(Base64.encodeBase64(privateKeyBytes));
		baos.close();
		String b64 = baos.toString();
		sb.append(BEGIN_PRIVATE_KEY);
		for (int i = 0; i < b64.length(); i += 64) {
			if (i + 65 < b64.length()) {
				sb.append(b64.substring(i, i + 64));
				sb.append('\n');
			} else {
				sb.append(b64.substring(i));
				sb.append('\n');
			}
		}
		sb.append(END_PRIVATE_KEY);

		return sb.toString();
	}

	private static class FilesOnlyFilenameFilter implements FilenameFilter {
		public boolean accept(File dir, String name) {
			File f = new File(dir, name);
			// TODO: filter based on include/exclude
			boolean accept = f.isFile() && f.exists();
			return accept;
		}
	}
}
