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

import javacard.security.RandomData;

/**
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló     
 * 
 */
public class Configuration {   
	 
	/**
	 * Specification of whether {@code byte[]} have to be stored in RAM (when
	 * true) or in EEPROM (if false).  This is <strong>manually</strong> to
	 * test different working modes.
	 */
	public static final boolean inRAM = false;  
	
	/**
	 * Maximum number of bits long of the numbers to work with within the current 
	 * ElGamal instance.
	 */
	public static short maxSizeInBits;
	/**
	 * Maximum number of bytes long of the numbers to work with within the current 
	 * ElGamal instance.
	 */
	public static short maxSizeInBytes;
	
	/**
	 * Current number of bits long of the numbers to work with within the current 
	 * ElGamal instance.
	 */
	public static short currentSizeInBits;
	/**
	 * Current number of bytes long of the numbers to work with within the current 
	 * ElGamal instance.
	 */
	public static short currentSizeInBytes;
	/**
	 * Random data generator.
	 */
	public static RandomData random;
	
	/**
	 * Initialize the secure random data generator.
	 */
	public static void init() {
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	
	/**
	 * Updates the maximum number of bits (and bytes) long of the numbers to work with within the
	 * current ElGamal Instance. The number of bytes long is updated to provide
	 * the necessary room to represent the given number of bits.
	 * @param maxBitPrecision maximum number of bits to represent.
	 */
	public static void setMaxSize(short maxBitPrecision) {
		// 1. set size in bits
		maxSizeInBits = maxBitPrecision;
		// 2. set size in bytes
		maxSizeInBytes = (short)(maxBitPrecision>>3);
		// 2.1. adjust size to reach the necessary bit representation 
    	if ((maxBitPrecision & 0x7) > 0)
    		maxSizeInBytes++;
    	// 3. this means that 'maxSizeInBytes*8 >= maxSizeInBits'.
	}

	/**
	 * Sets the current size of the big numbers to use, that has to be less
	 * than or equal to the {@code maxSizeInBits}.
	 * 
	 * @param bitPrecision number of bits to use, less than or equals to
	 * {@code maxSizeInBits}. 
	 */
	public static void setCurrentSize(short bitPrecision) {
		// 1. set size in bits
		currentSizeInBits = bitPrecision;
		// 2. set size in bytes
		currentSizeInBytes = (short)(bitPrecision>>3);
		// 3.1. adjust size to reach the necessary bit representation 
    	if ((bitPrecision & 0x7) > 0)
    		currentSizeInBytes++;
    	// 4. this means that 'sizeInBytes*8 >= sizeInBits'.
	}
	
}
