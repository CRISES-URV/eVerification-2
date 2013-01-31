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
 
import javacard.security.PrivateKey;
import javacard.security.RandomData;

/**
 * Private key for the ElGamal key pair. This implementation is immutable.
 * 
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló   
 *
 */
public class ElGamalPrivateKey implements PrivateKey {
	
	/** Secret exponent of the ElGamal cryptosystem. */
	private final MutableBigInteger a;
	/** Public properties of the keypair. */
	private final ElGamalPublicProperties props; 
	private boolean initialized = false;

	/**
	 * Initializes the private key.
	 * @param a private exponent.
	 * @param props public properties from the key pair.
	 */
	public ElGamalPrivateKey(ElGamalPublicProperties props) {
		this.a = new MutableBigInteger(true); //true = in ram 
		this.props = props;
	}
	
	/* ElGamal specific methods. */
	
	/**
	 * Returns the private exponent of the ElGamal key pair.
	 * @return the private exponent.
	 */
	public MutableBigInteger getPrivateKey() {
		return a;
	}
	
	/**
	 * Returns the public properties of the key pair.
	 * @return the public properties.
	 */
	public ElGamalPublicProperties getProperties() {
		return props;
	}
	
	/**
	 * Sets randomly the private key.
	 * @param random A secure random data generator.
	 * @param p1 (p-1).
	 */
	public void setKey(RandomData random, MutableBigInteger p1) {
		// ensure 1 < a < (p-1)
		a.clear();
		while (a.isZero() || a.isOne() || a.compare(p1)>0) {
			Configuration.random.generateData(a.data, (short)(a.data.length-Configuration.currentSizeInBytes), Configuration.currentSizeInBytes);
			a.off = a.findFirstNonZero();
			a.len = (short)(MutableBigInteger.LENGTH - a.off);
		}
		
		initialized=true;
	}
	
	/**
	 * Updates the internal value. 
	 * @param newKey new key value.
	 */
	public void setKey(MutableBigInteger newKey) {
		a.copyValue(newKey);
		initialized = true;
	}
	
	/**
	 * Updates the internal value. 
	 * @param newKey new key value.
	 */
	public void setKey(byte[] newKey) {
		a.copyValue(newKey);
		initialized = true;
	}
	
	/* PrivateKey interface implementation. */
	
	/** Sets to zero the private key. */
	public void clearKey() {
		a.clear();
		initialized=false;
	}

	/** Returns the key length in number of bits. */
	public short getSize() {
		return Configuration.currentSizeInBits;
	}

	/** Always returns 1 (key for decryption). */
	public byte getType() {
		return 1;
	}

	/** Returns always true. */
	public boolean isInitialized() {
		return initialized;
	}

}
