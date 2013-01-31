package cat.urv.crises.smartcard.elgamal;
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
import java.math.BigInteger;
import java.util.ArrayList;

import javax.smartcardio.CardException;

/**
 * Class to make a concurrent tally.
 * 
 * @author Roger Jardí Cedó {@link roger.jardi@urv.cat} & Vicenç Creus Garcia {@link vicens.creus@urv.cat}
 */
public class ConcurrentTally extends Thread {

	private CardClient cc;
	private int id, idinlist;
	private ArrayList<BigInteger> partialreturns= new ArrayList<BigInteger>();
	/**
	 * The constructor to the initialization the parameters of the SC thatis part in the tally process.
	 * @param scc reference to a CardClient object to do the operations in the SC
	 * @param index identifier of the SC
	 * @param numinlist number of the SC in the list
	 * @param partrets save the partial decrypts
	 */
	public ConcurrentTally(CardClient scc, int index, int numinlist, ArrayList<BigInteger> partrets){
		super();
		cc= scc;
		id = index;
		idinlist =numinlist;	
		partialreturns = partrets;
		
	}
	public final void run () {
		BigInteger ret=null;
		try {
			cc.cardConnection(id,idinlist);
			cc.appletSelectionInitialization(true, id );
			ret = new BigInteger(cc.tally(id), 16);
			partialreturns.add(ret);
			cc.cardDisconnection(id);
			//dec = dec.multiply(ret).mod(p);
		} catch (CardException e) {
			e.printStackTrace();
		}
		
	}
}
