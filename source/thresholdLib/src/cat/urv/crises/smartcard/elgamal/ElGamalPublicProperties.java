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
 

/**
 * Public properties of the ElGamal key pair. These properties will be accessed
 * from both keys. These properties are immutable.
 * 
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló 
 *
 */ 
public class ElGamalPublicProperties {
	/** Base for the exponentiation; the generator number. */
	public final MutableBigInteger g;
	/** Modulus number = 2q + 1. */
	public final MutableBigInteger p;
	/** Modulus number - 1 = 2q. */
	public final MutableBigInteger p1;
	/** Modulus number - 1 / 2 = q. **/
	public final MutableBigInteger q;
	/** Instance for the Singleton design pattern. */
	private static ElGamalPublicProperties instance = null; 
	
	/**
	 * Gets the instance of these properties according to the singleton
	 * design pattern.
	 * @return The unique instance of these properties.
	 */
	public static ElGamalPublicProperties getInstance() {
		if (instance == null) {
			instance = new ElGamalPublicProperties();
		}
		return instance;
	}
	
	/** 
	 * Initializes the properties for the public keypair's properties of ElGamal cipher.
	 */
	protected ElGamalPublicProperties() {
		this.g = new MutableBigInteger(false); //false -> stored in EEPROM
		this.p = new MutableBigInteger(false); //false -> stored in EEPROM
		this.p1 = new MutableBigInteger(false); //false -> stored in EEPROM
		this.q = new MutableBigInteger(false); //false -> stored in EEPROM
	}
	
	/**
	 * Resets to zero all public properties.
	 */
	public void clear() {
		p.clear();
		p1.clear();
		g.clear();
		q.clear();
	}
}
