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
 
import javacard.security.PublicKey;

/**
 * Public key of the ElGamal key pair. This implementation is immutable.
 * 
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló  
 *
 */
public class ElGamalPublicKey implements PublicKey { 
	
	/** Base <code>g**a<code>, where 'a' is the private key. */
	private final MutableBigInteger y;
	/** Public properties of the keypair. */
	private final ElGamalPublicProperties props; 
	private boolean initialized = false;
	
	/**
	 * Initializes the ElGamal public key
	 * @param y result of the generator number exponentiated to the private key (i.e., {@code g**a}).
	 * @param props public properties from the key pair.
	 */
	public ElGamalPublicKey(ElGamalPublicProperties props) {
		this.y = new MutableBigInteger(false); //false -> in EEPROM
		this.props = props;
	}

	/* Specific ElGamal methods. */
	
	/** 
	 * Returns the public key from ElGamal (the base).
	 * @return the public key.
	 */
	public MutableBigInteger getPublicKey() {
		return y;
	}
	
	/**
	 * Returns the public properties of the key pair.
	 * @return the public properties.
	 */
	public ElGamalPublicProperties getProperties() {
		return props;
	}
	
	/**
	 * Updates the public key to the given {@code newKey}.
	 * @param newKey new public key.
	 */
	public void setKey(MutableBigInteger newKey) {
		y.copyValue(newKey);
		initialized = true;
	}
	
	
	/**
	 * Updates the public key to the given {@code newKey}.
	 * @param newKey new public key.
	 */
	public void setKey(byte[] newKey) {
		y.copyValue(newKey);
		initialized = true;
	}
	
	/* PublicKey interface implementation. */
	/** 
	 * Gets the size in bits of the key length.
	 * @return the length of the key.
	 * @see javacard.security.Key#getSize()
	 */
	public short getSize() {
		return Configuration.maxSizeInBits;
	}

	/** Does nothing. */
	public void clearKey() {
		initialized = false;
	}

	/** Retuns always 0 (zero) (key for encryption). */
	public byte getType() {
		return 0;
	}

	/** Returns always true. */
	public boolean isInitialized() {
		return initialized;
	}
}
