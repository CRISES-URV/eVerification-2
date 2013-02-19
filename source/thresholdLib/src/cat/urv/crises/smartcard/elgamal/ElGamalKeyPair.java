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

import javacard.security.CryptoException;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;

/**
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló 
 *
 */
public final class ElGamalKeyPair {
	
	/** Private key for ElGamal cipher. */
	private final ElGamalPrivateKey prKey;
	/** Public key for ElGamal cipher. */
	private final ElGamalPublicKey puKey;
	/** Public properties of ElGamal (p, g).*/
	private final ElGamalPublicProperties props;
	/** Instance for Singleton design pattern. */
	private static ElGamalKeyPair instance = null; 
	
	/**
	 * Returns the singleton instance of this key pair.
	 * @return an instance of key pair.
	 */
	public static ElGamalKeyPair getInstance() {
		if (instance == null) {
			instance = new ElGamalKeyPair(ElGamalCipher.ALG_ELGAMAL);
		}
		return instance;
	}
	
	/**
	 * Initializes the pair of keys if and only if the {@code algorithm}
	 * is {@link cat.urv.crises.smartcard.elgamal.ElGamalCipher#ALG_ELGAMAL}.
	 * @param algorithm necessarily {@link cat.urv.crises.smartcard.elgamal.ElGamalCipher#ALG_ELGAMAL}.
	 * @throws CryptoException with reason {@link javacard.security.CryptoException#NO_SUCH_ALGORITHM} if
	 * {@code algorithm} is not {@link cat.urv.crises.smartcard.elgamal.ElGamalCipher#ALG_ELGAMAL}.
	 * @see javacard.security.KeyPair#KeyPair(byte, short)
	 */
	protected ElGamalKeyPair(byte algorithm) {
		if (algorithm == ElGamalCipher.ALG_ELGAMAL) {
			props = ElGamalPublicProperties.getInstance();
			prKey = new ElGamalPrivateKey(props);
			puKey = new ElGamalPublicKey(props);
			
			
		} else {
			throw new CryptoException(CryptoException.NO_SUCH_ALGORITHM);
		}
	}
	
	/**
	 * Initializes the pair of keys with the given {@code publicKey} and {@code privateKey}.
	 * @param publicKey necessarily an instance of {@link cat.urv.crises.smartcard.elgamal.ElGamalPublicKey}.
	 * @param privateKey necessarily an instance of {@link cat.urv.crises.smartcard.elgamal.ElGamalPrivateKey}.
	 * @see javacard.security.KeyPair#KeyPair(PublicKey, PrivateKey)
	 */
	/*public ElGamalKeyPair(PublicKey publicKey, PrivateKey privateKey) {
		props = ElGamalPublicProperties.getInstance();
		puKey = (ElGamalPublicKey)publicKey;
		prKey = (ElGamalPrivateKey)privateKey;
	}*/
	
	/**
	 * @see javacard.security.KeyPair#getKeyPair()
	 */
	public void genKeyPair() {
		// 1. generate short secure random value
		prKey.setKey(Configuration.random, props.p1);
		// 2. calculate the public key value and set it to the public key.
		puKey.setKey(ElGamalCipher.instance.genPublicKey()); //g**a mod p
	}
	
	/**
	 * Generates randomly the private key.
	 */
	public void genPrivateKey() {
		//generate and set random value
		prKey.setKey(Configuration.random, props.p1);
	}
	
	/**
	 * Generates randomly the private key.
	 */
	public void genPublicKey() {
		//generate and set random value
		puKey.setKey(ElGamalCipher.instance.genPublicKey()); //g**a mod p
	}
	
	/**
	 * @see javacard.security.KeyPair#getPrivate()
	 */
	public PrivateKey getPrivate() {
		return prKey;
	}
	
	/**
	 * Gets the value of the private key as a big number.
	 * @return big number containing the private key value.
	 */
	public MutableBigInteger getPrivateValue() {
		return prKey.getPrivateKey();
	}
	
	/**
	 * @see javacard.security.KeyPair#getPublic()
	 */
	public PublicKey getPublic() {
		return puKey;
	}

	/**
	 * Gets the value of the public key as a big number.
	 * @return big number containing the public key value.
	 */
	public MutableBigInteger getPublicValue() {
		return puKey.getPublicKey();
	}

	
	/**
	 * Clears the current values of the keys.
	 */
	public void clear() {
		prKey.clearKey();
		puKey.clearKey();
	}

}
