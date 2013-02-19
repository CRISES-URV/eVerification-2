/* 
 * Copyright (c) 2013, Universitat Rovira i Virgili
 * All rights reserved.
 * 
 * The license for this file is based on the BSD-3-Clause license
 * (http://www.opensource.org/licenses/BSD-3-Clause).
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * - Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * - Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 * 
 * - Neither the name of the Universitat Rovira i Virgili nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * 
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 * This work has been developed within the project eVerification2 TSI-020100-2011-39,
 * leaded by Scytl Secure Electronic Voting S.A. and supported by the Spanish 
 * Ministry of Industry, Commerce and Tourism (through the development program AVANZA 
 * I+D). We would like to thank Scytl for their support and to the Ministery for the 
 * needed founding required to carry it out.
 * The Beta version of this code has been implemented by Jordi Castellà, Vicenç Creus, 
 * Roger Jardí and Jordi Pujol ([jordi.castella,vicenc.creus,roger.jardi,jordi.pujol]@urv.cat).
 * 
 */
package cat.urv.crises.smartcard.elgamal;  
  
import javacard.framework.ISO7816;
//import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.Key;
//import javacard.security.PublicKey;
import javacardx.crypto.Cipher;

/**
 * ElGamal Cipher implementation.  
 * 
 * <p>Nomenclature:
 * <dl>
 *   <dt><strong>b</strong>
 *   <dd>generator; base of the exponentiation (in {@code 2..p-2})
 *   <dt><strong>a</strong>
 *   <dd>exponent; private key (in {@code 2..p-2})
 *   <dt><strong>p</strong>
 *   <dd>modulus, prime number such that {@code p=2q+1}, and {@code q} is also
 *   a prime number. 
 *   <dt><strong>b</strong>
 *   <dd>random number generated for encrypting (in {@code 2..p-2}). 
 *   <dt><strong>m</strong>
 *   <dd>message to encrypt (in {@code 2..p-2})
 * </dl>
 * <p>Key pair:
 * <ul>
 *   <li><strong>Private key:</strong> {@code a}</li>
 *   <li><strong>Public key:</strong> {@code g**a}</li>
 *   <li><strong>Public parameters:</strong> {@code g, p}</li> 
 * </ul>
 * <p>Functionality:
 * <ul>
 *   <li>Encryption: {@code (y1, y2) = ( (g**b mod p), (g**(ab)m mod p) )}.</li>
 *   <li>Decryption: {@code m = ((y1**a)**-1)y2 mod p}.</br>
 *   Alternatively: having {@code x=p-1-a,  x>0}, we can also obtain m from:</br>
 *   {@code m = (y1**x)y2 mod p}, where {@code p-1} is the {@code totient(p)}.</li>
 * </ul>
 * The last alternative for decrypting the message {@code m} will be used,
 * in order to avoid calculating modular inverse numbers.
 * 
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló  
 */
public class ElGamalCipher extends Cipher {
	
	/* ************* CONSTANT VALUES **************************/
	
	/** ElGamal cryptosystem code. */
	public static final byte ALG_ELGAMAL = 18;

	/* ************* VALUES CURRENTLY IN USE **************************/
	
	/** Current public ElGamal properties. */
	public ElGamalPublicProperties props;
	/** Current pair of public and private keys. */
	private ElGamalKeyPair keyPair;
	/** Current mode. Possible values: 
	 * <code>Cipher.MODE_DECRYPT</code> or <code>Cipher.MODE_ENCRYPT</code>. */
	private byte mode;
	
	/* ************* TEMPORAL VALUES **************************/
	
	/** Result of the encryption/decryption. */
	private MutableBigInteger result;
	/** Other parts of the encryption. */
	private MutableBigInteger result2, result3, result4;
	/** Reference to p. */
	private MutableBigInteger p;
	/** Reference to p-1. */
	private MutableBigInteger p1;
	/** Reference to q. */
	private MutableBigInteger q;
	/** Reference to p - 1 - a. */
	private MutableBigInteger x;
	/** Reference to g. */
	private MutableBigInteger g;
	/** Reference to a, to the private key. */
	private MutableBigInteger a;
	/** Random number as exponent when encrypting. */
	private MutableBigInteger b;
	/** Number of bytes long, for internal temporary use. */
	private short len;
	/** Whether to store byte[] in RAM (when true), or in EEPROM (if false).
	 * It takes the value from {@link cat.urv.crises.config.Configuration#inRAM}.*/
	private final boolean inRAM;
	/** Instance for the singleton design pattern. */
	public static ElGamalCipher instance = null;
	
	/**
	 * Instantiates the singleton.
	 * @param maxBitPrecision maximum number of bits to use as a backend.
	 * @param currentBitPrecision current size of bit precision in use
	 * (@code currentBitPrecision <= maxBitPrecision}).
	 * @return an instance of ElGamalCipher.
	 */
	public static ElGamalCipher getInstance(short maxBitPrecision) {
		if (instance == null) {
			instance = new ElGamalCipher(maxBitPrecision);
		}
		return instance;
	}
	/**
	 * Creates an empty instance. 
	 */
	protected ElGamalCipher(short maxBitPrecision) {
		inRAM = Configuration.inRAM;
		Configuration.init();
		Configuration.setMaxSize(maxBitPrecision);	
		Math.init(); //requires Configuration.setSize() be invoked
		
		b = new MutableBigInteger(inRAM);
		result = new MutableBigInteger(inRAM);
		result2 = new MutableBigInteger(inRAM);
		result3 = new MutableBigInteger(inRAM);
		result4 = new MutableBigInteger(inRAM);
		x = new MutableBigInteger(inRAM);
	
		props = ElGamalPublicProperties.getInstance();
		p = props.p;
		p1 = props.p1;
		q = props.q;
		g = props.g;
		keyPair = ElGamalKeyPair.getInstance();
		a = keyPair.getPrivateValue();
	}
	
	/**
	 * Resets the content of all numbers to zero.
	 */
	public void initialize(short currentSize) {
		Configuration.setCurrentSize(currentSize);
		Math.postInit();
		props.clear(); //p and g references to props.p and props.g, so nothing to do with them
		keyPair.clear(); //a references to the private key, that is already cleared.
		result.clear();
		result2.clear();
		result3.clear();
		result4.clear();
		x.clear();
		b.clear();
	}

	/**
	 * Stores the given public parameter {@code p} (the modulus value).
	 * This method can be instantiated several times for long values. The last
	 * invokation will have {@code last} as {@code true}.
	 * @param buf buffer from where to read the value of {@code p}.
	 * @param off first position to read from the buffer {@code buf}.
	 * @param len number of bytes to read from.
	 * @param last {@code true} when the given value is the last portion of
	 * {@code p}; {@code false} otherwise.
	 */
	public void saveP(byte[] buf, short off, short len, boolean last) {
		p.append(buf, off, len);
		if (last) { //only at the last portion we make this post-initialization
			Math.subtract(p1, p, Math.ONE);
			p.normalize();
			p1.normalize();
		}
	}
	
	/**
	 * Stores the given public parameter {@code p} (the modulus value).
	 * This method can be instantiated several times for long values. The last
	 * invokation will have {@code last} as {@code true}.
	 * @param buf buffer from where to read the value of {@code p}.
	 * @param off first position to read from the buffer {@code buf}.
	 * @param len number of bytes to read from.
	 * @param last {@code true} when the given value is the last portion of
	 * {@code p}; {@code false} otherwise.
	 */
	public void saveQ(byte[] buf, short off, short len, boolean last) {
		q.append(buf, off, len);
		if (last) { //only at the last portion we make this post-initialization
			q.normalize();
		}
	}
	
	/**
	 * Stores the given public parameter {@code q} (the modulus value).
	 * This method can be instantiated several times for long values. The last
	 * invokation will have {@code last} as {@code true}.
	 * @param buf buffer from where to read the value of {@code p}.
	 * @param off first position to read from the buffer {@code buf}.
	 * @param len number of bytes to read from.
	 * @param last {@code true} when the given value is the last portion of
	 * {@code q}; {@code false} otherwise.
	 */
	public void saveG(byte[] buf, short off, short len, boolean last) {
		g.append(buf, off, len);
		if (last) {
			g.normalize();
		}
	}
	
	
	/**
	 * (Re)Builds the pair of keys for the ElGamal cipher, given the current
	 * values of {@code p} and {@code g}. 
	 */
	public void buildKeys() {
		keyPair.genKeyPair();
	}
	
	/**
	 * Generates the private key.
	 */
	public void buildPrivateKey() {
		keyPair.genPrivateKey();
	}
	
	/**
	 * Generates the private key.
	 */
	public void buildPublicKey() {
		keyPair.genPublicKey();
	}
	
	/**
	 * Generates the public key and calculates the exponent {@code x} to
	 * speed up the decryption process.
	 * @return the public key value as a big number.
	 */
	public MutableBigInteger genPublicKey() {
		Math.subtract(x, p, Math.ONE);
		Math.selfSubtract(x, a);
		Math.modPow(result, g, a, p); //g**a mod p -> stored in result
		
		return result;
	}

	/**
	 * It is invoked to do the final step of the encryption phase, or
	 * the complete decryption process. 
	 * 
	 * @see javacardx.crypto.Cipher#doFinal(byte[], short, short, byte[], short)
	 */
	public short doFinal(byte[] inBuff, short inOffset, short inLength,
            byte[] outBuff, short outOffset) throws CryptoException {
		if (mode == Cipher.MODE_ENCRYPT) { 
			// 0. inBuff contains the message m to encrypt. 
			//    result2 has the y2'
			result.append(inBuff, inOffset, inLength); //message 'm' is stored in result
			// 1. Calculate: y2 = y2'*m (mod p) -> result4 = result2 * result (mod p)
			Math.modMul(result4, result2, result, p);  
			// 2. Copy y1, y2 to output buffer
			//keyPair.getPublicValue().copyTo(outBuff, outOffset);
			//keyPair.getPrivateValue().copyTo(outBuff, (short)(outOffset+Configuration.currentSizeInBytes));
			result3.copyTo(outBuff, outOffset);
			result4.copyTo(outBuff, (short)(outOffset+Configuration.currentSizeInBytes));
			len = (short)(Configuration.currentSizeInBytes<<1); //twice inLength
		} else { // DECRYPT
			// 0. inBuff may contain y1, or (y1, y2) or y2.
			update(inBuff, inOffset, inLength, outBuff, outOffset);
			// 3. Compute: m = (y1**x)y2 mod p -> stored in
			Math.modPow(result3, result, x, p); //y1**x mod p -> stored in result4
			Math.modMul(result, result3, result2, p); //result3*y2 mod p -> stored in result
			len=result.copyTo(outBuff, outOffset); 
			//len=result.copyTo(outBuff, outOffset);
		}
		return len;
		//return inLength;
	}
	
	public short doThresholdDec(byte[] inBuff, short inOffset, short inLength,
            byte[] outBuff, short outOffset, MutableBigInteger share, MutableBigInteger lagrange) throws CryptoException {
	
		// 0. inBuff may contain y1, or (y1, y2) or y2.
		update(inBuff, inOffset, inLength, outBuff, outOffset);
		// 3. Compute: Z1i = ((z1**)hi)**landai mod p -> stored in
		
		Math.modPow(result4, result, share, p); //(z1**)hi mod p -> stored in result3

		Math.modPow(result, result4, lagrange, p); //result3*landai mod p -> stored in result

		len=result.copyTo(outBuff, outOffset);
		
		return len;
	}
	

	/**
	 * Explicit specification of {@link ALG_ELGAMAL} algorithm.
	 * @return {@link ALG_ELGAMAL}
	 */
	public byte getAlgorithm() {
		return ALG_ELGAMAL;
	}
	
	
	/**
	 * Debug method used in ElGamalApplet.
	 * @return
	 */
	public ElGamalKeyPair getKeyPair() {
		return keyPair;
	}

	/**
	 * Initializes the cipher for <b>decrypting</b>. 
	 */
	public void initDecrypt() throws CryptoException {
		init(null, Cipher.MODE_DECRYPT);
	}
	
	/** 
	 * Initialize the cipher for <b>decrypting</b>.
	 * @see javacardx.crypto.Cipher#init(javacard.security.Key, byte)
	 */
	public void init(Key key, byte mode) throws CryptoException {
		if (mode == Cipher.MODE_ENCRYPT) 
			throw new CryptoException(CryptoException.INVALID_INIT);

		// 1. Initialize local attributes.
		this.mode = mode;
		result.clear();
		result2.clear();
	}

	/**
	 * Initializes the cipher for <b>encrypting</b>.
	 * @param buf input buffer containing random number for encryption.
	 * @param bOff offset within buf where the number starts.
	 * @param bLen length of the number (in number of bytes).
	 */
	public void initEncrypt(byte[] buf, short bOff, short bLen) 
		throws CryptoException {
		init(null, Cipher.MODE_ENCRYPT, buf, bOff, bLen); 
	}
	
	/**
	 * Initialize the cipher for <b>encrypting</b>.
	 * @see javacardx.crypto.Cipher#init(javacard.security.Key, byte, byte[], short, short)
	 */
	public void init(Key key, byte mode, byte[] buf, short bOff, short bLen)
			throws CryptoException {
		if (mode == Cipher.MODE_DECRYPT)
			throw new CryptoException(CryptoException.INVALID_INIT);
		
		// 1. Initialize local attributes.
		result.clear();
		this.mode = mode;
		
		// 2. Compute y2 = ((g**a)**b)m (mod p) 
		// Here we only receive the random value 'b', so we only calculate
		// a partial result y2'=((g**a)**b) mod p -> partial result stored in result2
		b.copyValue(buf, bOff, bLen); 
		Math.modPow(result2, keyPair.getPublicValue(), b, p);
		
		// 3. Compute y1=g**b (mod p) -> result3 = g**b mod p
		Math.modPow(result3, g, b, p);
		
		// Note: result2 is y2'; result3 is y1
		// Note: Remaining part: y2 = y2'*m (mod p) -> a = result2 * m (mod p)
	}

	/**
	 * Method not allowed; it always throws an exception with code <code>0xFF</code>. 
	 * @param inBuf the input buffer of data to be encrypted/decrypted
     * @param inOff the offset into the input buffer at which to begin encryption/decryption
     * @param inLen the byte length to be encrypted/decrypted
     * @param outBuf the output buffer, may be the same as the input buffer
     * @param outOff the offset into the output buffer where the resulting ciphertext/plaintext begins 
	 * @return  number of bytes output in outBuff 
	 * @throws javacardx.crypto.CryptoException with error <code>0xFF</code> always.
	 * @see javacardx.crypto.Cipher#update(byte[], short, short, byte[], short)
	 */
	public short update(byte[] inBuf, short inOff, short inLen, byte[] outBuf,
			short outOff) throws CryptoException {
		if (inLen == 0) return 0;
		switch (mode) {
		case Cipher.MODE_ENCRYPT:
			//0. inBuff contains the message m to encrypt. 
			//    result2 has the y2'
			result.append(inBuf, inOff, inLen); //message 'm' is stored in result
			break;
		case Cipher.MODE_DECRYPT:
			// 0. inBuff contains y1, or (y1, y2), or y2; it receives y2 first, and then y1.
			// 1. appending values from y2 if it is not completed.
			if (result2.len < Configuration.currentSizeInBytes) {
				len = (short)(Configuration.currentSizeInBytes - result2.len);
				len = (len > inLen)?inLen:len;
				result2.append(inBuf, (short)(inOff + (inLen - len)), len);
			} else {
				len = 0;
			}
			// 2. when full y2 and there are remaining values, append into y1
			if (inLen > len) {
				len = (short)(inLen - len);
				result.append(inBuf, inOff, len);
			}
			//result contains y1, result2 contains y2
			break;
		default:
			CryptoException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		return 0;
	}
	
	/**
	 * Proceeds to remove all references to Objects.
	 */
	public void uninstall() {
		Math.uninstall();
		props = null;
		keyPair = null;
		result = null;
		result2 = null;
		result3 = null;
		result4 = null;
		p = null;
		q = null;
		g = null;
		a = null;
		b = null;
	}
	
}
