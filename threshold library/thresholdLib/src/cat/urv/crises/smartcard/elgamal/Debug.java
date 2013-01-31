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

import javacard.framework.ISOException;
import javacard.security.CryptoException;

/**
 * This class provides the functionality to make easier the debug of the 
 * CryptoException when this is caught elsewhere.
 * @see #showCase(CryptoException, short)
 * 
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló   
 * 
 * 
 */
public class Debug { 
	 
	/**
	 * According to the {@code base} hexadecimal value of the form {@code 0xYY00},
	 * this method shows the exact reason within the CryptoException adding
	 * an offset to the value {@code 0xYY00} of the form {@code 0x00ZZ}. The idea
	 * behind the existence of {@code base} is that it allows to differ between
	 * different debug places as it may be necessary.
	 * <p>
	 * The values, are as follows:
	 * <dl>
	 * 	<dt>{@link javacard.security.CryptoException#ILLEGAL_USE}
	 *  <dd>{@code 0x00ZZ=0x0011}
	 *  <dt>{@link javacard.security.CryptoException#ILLEGAL_VALUE}
	 *  <dd>{@code 0x00ZZ=0x0021}
	 *  <dt>{@link javacard.security.CryptoException#INVALID_INIT}
	 *  <dd>{@code 0x00ZZ=0x0031}
	 *  <dt>{@link javacard.security.CryptoException#NO_SUCH_ALGORITHM}
	 *  <dd>{@code 0x00ZZ=0x0041}
	 *  <dt>{@link javacard.security.CryptoException#UNINITIALIZED_KEY}
	 *  <dd>{@code 0x00ZZ=0x0051}
	 *  <dt>otherwise
	 *  <dd>{@code 0x00ZZ=0x0071}
	 * </dl>
	 * It has been observed that when this method is invoked along the 
	 * applet installation phase, the observed error is instead 
	 * {@code 0x6A80 (Wrong data)}, regardless of the specific reason.
	 * @param e CryptoException to be analysed.
	 * @param base hexadecimal number of the form {@code 0xYY00}.
	 */
	public static void showCase(CryptoException e, short base) { 
		switch (e.getReason()) {
		case CryptoException.ILLEGAL_USE:
			ISOException.throwIt((short)(base + 0x11));
			break;
		case CryptoException.ILLEGAL_VALUE:
			ISOException.throwIt((short)(base + 0x21));
			break;
		case CryptoException.INVALID_INIT:
			ISOException.throwIt((short)(base + 0x31));
			break;
		case CryptoException.NO_SUCH_ALGORITHM:
			ISOException.throwIt((short)(base + 0x41));
			break;
		case CryptoException.UNINITIALIZED_KEY:
			ISOException.throwIt((short)(base + 0x51));
			break;
		default:
			ISOException.throwIt((short)(base + 0x71));
		}
	}

}
