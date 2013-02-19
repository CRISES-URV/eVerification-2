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
 * The Beta version of this code has been implemented by Jordi Castell�, Vicen� Creus, 
 * Roger Jard� and Jordi Pujol ([jordi.castella,vicenc.creus,roger.jardi,jordi.pujol]@urv.cat).
 * 
 */
import java.util.ArrayList;
import java.util.Formatter;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.math.BigInteger;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


/**
 * Operations implemented in the SC
 * 
 * @author Roger Jard� Ced� {@link roger.jardi@urv.cat} & Vicen� Creus Garcia {@link vicens.creus@urv.cat}
 * 
 */

public class CardClient {
	
	List<CardTerminal> terminals;
	TerminalFactory factory;
	CardTerminal[] terminal;
	Card[] card;
	CardChannel[] channel;
	ResponseAPDU r;
	String AID_STRING = "12345654322801";
	byte[] AID = hexStringToByteArray(AID_STRING);
	
	String[] coefs_commit;
	String[] shares;
	String[] shares_commit;
	
	String pk = "";
	BigInteger p, rand, m, g, sk, q;
	BigInteger[] z = new BigInteger[2];;
	BigInteger dec, ret;
	
	long ini_time, generation_time, broadcasting_time, tally_time, end_time;
	short currentsizeinbits;
	short currentsizeinbytes;
	private int THRESHOLD;
	private int NUM_SHARES;
	private int id_card;
	private int[] cards;
	private static BigInteger[] eval_values;	
	private static BigInteger[] lagrange_cef;
	private String[] responsesw;
	private BigInteger y1total, y2total;
	private ArrayList<BigInteger> partialreturns;
	/**
	 * Constructor
	 * @param numshares number of shares
	 * @param threshold threshold value
	 * @param sizeinbits key size
	 * @param cards cards connected to use
	 * @throws CardException
	 */
	public CardClient(int numshares, int threshold, short sizeinbits, int[]cards) throws CardException {
		this.responsesw= new String[2];
		this.THRESHOLD = threshold;
		this.NUM_SHARES =numshares;
		this.cards=cards;
		
		terminal = new CardTerminal[NUM_SHARES];
		channel = new CardChannel[NUM_SHARES];
		card = new Card[NUM_SHARES];
		
		eval_values = new BigInteger[NUM_SHARES];
		lagrange_cef = new BigInteger[NUM_SHARES];
		coefs_commit = new String[THRESHOLD-1];
		shares = new String[NUM_SHARES];
		shares_commit = new String[NUM_SHARES];
		
		this.currentsizeinbits =sizeinbits;
		currentsizeinbytes = (short) (currentsizeinbits/8);
		
        switch(currentsizeinbits){
        case 512:	
        	p = new BigInteger("ff5618011c81a94b5c7175dd019561cc0b589732a878a5e743562c50d568259cda313b77fda2b7d30b5b7c0dc732f45e335a73da6d7098444c65fbb357581f57",16);
            q = new BigInteger("7fab0c008e40d4a5ae38baee80cab0e605ac4b99543c52f3a1ab16286ab412ce6d189dbbfed15be985adbe06e3997a2f19ad39ed36b84c222632fdd9abac0fab",16);
        	g = new BigInteger("365eac55418cbf3b4a014d6154e1b213fa494eeb8589e2159acbffccf63a685d2312998e417a556f0ba1f20f876cdf3daca76c7dc3ed51248b73fc9ba6316e3c",16);
        	break;
        case 768:
        	p = new BigInteger("b9ded760f0d43377dc39a621002ca5a805850acb9d510afb3a014dc8b5a7e4cb4041e9f9b522e65f9cdc0b0dfbc4faaf4757df6064f074c8b2713c7afd77057f4b765af5f9c258150389f0081c2f14b9f5c5d2624cd24c92e0a452228b798ca3",16);
            q = new BigInteger("5cef6bb0786a19bbee1cd310801652d402c28565cea8857d9d00a6e45ad3f265a020f4fcda91732fce6e0586fde27d57a3abefb032783a6459389e3d7ebb82bfa5bb2d7afce12c0a81c4f8040e178a5cfae2e931266926497052291145bcc651",16);
        	g = new BigInteger("550c59e16ab23717a034906ebb76754b76e95bfb9b6a267be4ec76815db265ad98118bd6c9f18e8a7b29f2b161bc58c74fc350f938747d26d02475d81cead8f32b43e3855e988f5a1d18d8156b5a76278480c1c454c6947b47b1c05e79eded03",16);
        	break;
        case 1024:
        	p = new BigInteger("b4af96b1b6e50e21ee226110750945537aa4a68e246368dd8ddd778bf3b4cd82c545f59731e0beb2bc7a81ffc8ef84446d1192bcf13e132e683a08a232411692c4718cad9cafbf5396a6ca33c02b73df799112ceb132935bc5df0815a58e7b41dc1d92d864f1f2b37c368adc59562972a0d71bd16d4c1db8f714ab63fb4dd1db",16);
            q = new BigInteger("5a57cb58db728710f71130883a84a2a9bd5253471231b46ec6eebbc5f9da66c162a2facb98f05f595e3d40ffe477c2223688c95e789f0997341d045119208b496238c656ce57dfa9cb536519e015b9efbcc88967589949ade2ef840ad2c73da0ee0ec96c3278f959be1b456e2cab14b9506b8de8b6a60edc7b8a55b1fda6e8ed",16);        
        	g = new BigInteger("435b6e9b3b4fdcfb63c6932ac0c0615048cb84be6660ed2915ded1e3273096b4aa2e24458a70fb81420058a3791473b651b146ed63cbd558d31bc41102f0d362ef418825bcd4e324f615f64bb5ca439d86adf0f57dcb264565410f63ad0327f28875de82c43232b6f0c20559ee4fb41d2f1c4a8327871d18af2f8c31e4693f16",16);
        	break;
        case 1536:
        	p = new BigInteger("ac64eed8467f549ed161b9ab05b14e20e11897a69d838046d1d9b17610d2f2a0090990256e850d1a3c96d1cd38bde5de6cb36976ee4b02c1afa05eb8239e51f22df85a2ab9031ce3698d1255679cbb42e2d8419628b822dffa2d9f077941b7702d45315d0884e35d39ceb1ae0cbe615f7347c92fff56627924f864eaa29a6cd6855734ca1a07d0df37529854a7094ea52b960969f89189fcd9a08c9e1e401b4ce78a469f085d4ecb011189466980735abc3522afbafdcd9161e97840692ee253",16);
            q = new BigInteger("5632776c233faa4f68b0dcd582d8a710708c4bd34ec1c02368ecd8bb086979500484c812b742868d1e4b68e69c5ef2ef3659b4bb77258160d7d02f5c11cf28f916fc2d155c818e71b4c6892ab3ce5da1716c20cb145c116ffd16cf83bca0dbb816a298ae844271ae9ce758d7065f30afb9a3e497ffab313c927c3275514d366b42ab9a650d03e86f9ba94c2a5384a75295cb04b4fc48c4fe6cd0464f0f200da673c5234f842ea7658088c4a334c039ad5e1a9157dd7ee6c8b0f4bc2034977129",16);        
        	g = new BigInteger("7db17b6dcc729f7278919512a832f3c14d7fdd8a0645a60e4aebc0651f14f01f9e973ef29cc75b899cf556a790b0dbdd37f6a6181dd572d45b13601ba9f46bdb09deb7b48891c48bf572e4462021a10cf0ff8bd1b81ce08f61feb3450b562aa395a27175574a799c410dc875736e2c0b9ada57c085719cf5ba7c483b4abda442e34e17e6bdd113bf07899c9ced9c1a26b090cda136a362f56244b1001efbe193970ccac092673dc5cf13e3acdd57568fdfa10b90eff5b74195f0e52cab1154f3",16);
        	break;
        case 2048:
        	p = new BigInteger("c8a21abbb339218b396ebb685a791be93c36ce28f3325663cebe93cb7d933b9816258c9c4daabfdf214066be21bf29df12fbb68c729e1ce807f8f32f72fc6e1a576790db9f7c82ed8b6c3a2b728bfbd4e736ed2969ab0a75f21c7bcbfa0b80d953bbcc59c5ae6a5105f974344f7c9bc686f26bd1841a67e2f329e6237c9153acf4d0fec0bdf4d552cc40fc359e085d22925e6fc51a9568ea41c764a42a139c970ed9029a643b31f08592450a3c77c2d694eb4f8d95e689d03d94c4ccab9403bf9ee24956ed028493527e1d33ed037e6ca9c0e89b7ae9e2ff0c006447bb07b422b5cda69a62f951edab96bda552b91e37ee4194420c963519e05ea8e55269c407",16);
        	q = new BigInteger("64510d5dd99c90c59cb75db42d3c8df49e1b671479992b31e75f49e5bec99dcc0b12c64e26d55fef90a0335f10df94ef897ddb46394f0e7403fc7997b97e370d2bb3c86dcfbe4176c5b61d15b945fdea739b7694b4d5853af90e3de5fd05c06ca9dde62ce2d7352882fcba1a27be4de3437935e8c20d33f17994f311be48a9d67a687f605efa6aa966207e1acf042e91492f37e28d4ab47520e3b2521509ce4b876c814d321d98f842c922851e3be16b4a75a7c6caf344e81eca626655ca01dfcf7124ab76814249a93f0e99f681bf3654e0744dbd74f17f86003223dd83da115ae6d34d317ca8f6d5cb5ed2a95c8f1bf720ca21064b1a8cf02f5472a934e203",16);
        	g = new BigInteger("70b2634adcf6286f95e644d1f1174b52fdfc2c0618d8f2f0d513b900b608985625bb257a1ac9ba6af9fd72b6dbc3c2d4dc4fa8e7e1939166f7a5893153e026a5c6f2d59ee9d56248593626d60e8a89a24a5b5c9883b2163cf7c08c38c8fe1473d873f680383a5bfde43926f3ca7084c884ff26460d8f14bd043e550f57eb86215f41a74ff3eccfadbac8aef0cad22de50475e703be559477d91c599ff14b2e9de682101bedc1ca4db6e81b798f39748666c90463038495faae9650291f3d085b061c3c86e1f7ed959ccd042b1468136f776c3dcbcae8616e2eba16d7a65259f2cfc480e727148e7dd56b98fc2f2eb3c0ea1a73f4767d49fb6af0c97e7351b2f5",16);
        	break;
        default: System.exit(-1);
        }
        
        g = g.modPow(new BigInteger("2"), p);
        sk = new BigInteger("0"); //it is not passed to SC, it is generated into SC.
            	
		
	}
	
	/**
	 * Create a new message and new random number
	 */
	protected void createMessage(){
		m = new BigInteger(currentsizeinbits-2,new Random() );
		rand = new BigInteger(currentsizeinbits-1, new Random());
	}
	/**
	 * Create a message with the parameter String and generate a new random number
	 * @param str message to use
	 */
	protected void createMessageBox(String str){
		try{
			m = new BigInteger(str,16);
			rand = new BigInteger(currentsizeinbits-1, new Random());
		}catch(NumberFormatException e){
			byte[] bytearray =str.getBytes();
			m = new BigInteger(bytearray);
			rand = new BigInteger(currentsizeinbits-1, new Random());
			//si_numeric = false;
		}
	}
	/**
	 * Get message
	 * @return message in a BigInteger
	 */
	protected BigInteger getM(){
		return m;
	}
	/**
	 * Get partial decrypts
	 * @return list with all partial decrypts 
	 */
	protected ArrayList<BigInteger> getPartialreturns() {
		return partialreturns;
	}
	/**
	 * Get message 
	 * @return message in a String
	 */
	protected String getMtoString() {
		return byteArrayTohexString(m.toByteArray());
	}
	/**
	 * Message decrypted
	 * @return message decrypted in a String 
	 */
	protected String getDECtoString(){
		return byteArrayTohexString(dec.toByteArray());
	}
	/**
	 * Use for obtains the encryption of the message
	 * @throws CardException
	 */
	protected String getZ2toString() throws CardException{   //PC encrypt 
		cardConnection(0,this.cards[0]);
		appletSelectionInitialization(true,0); //true = is initialized //
		String ret =voting(0,byteArrayTohexString(m.toByteArray()));
		cardDisconnection(0);
		return ret;
	}
	/**
	 * Encryption and agregation of the messages
	 * @param primer to know if the first step or the following steps
	 * @param votes message
	 * @return list of results
	 * @throws CardException
	 */
	protected BigInteger[] Z_Encrypt(boolean primer, String votes)throws CardException{
		m = new BigInteger(votes);
		getZ2toString();
		
		if(primer){
        	y1total = z[0];
        	y2total = z[1];
		}else{
			this.y1total= z[0].multiply(this.y1total).mod(this.p);
        	this.y2total= z[1].multiply(this.y2total).mod(this.p);
		}
		System.out.println("\n-------------------------------------------------");
		System.out.println("Y1TOTAL: "+this.y1total);
		System.out.println("Y2TOTAL: "+this.y2total);
		System.out.println("\n-------------------------------------------------");
		return z;
	}

	/**
	 * Decryption and factorization
	 * @param primers
	 * @param ids
	 * @return Result of tally
	 * @throws CardException
	 */
	protected ArrayList<Integer> Z_Decrypt(ArrayList<Integer> primers, Integer[] ids) throws CardException{
		Integer prime, result=0;
		ArrayList<Integer> ress=new ArrayList<Integer>();
		z[0] = y1total;
		z[1] = y2total;
		useTally(ids);
	
		Iterator<Integer> it = primers.iterator();
		while (it.hasNext()){
			prime = (Integer)it.next();
			
			result = getFactor(dec, prime);
			
			System.out.println("Base g primer ("+prime.toString()+ ") es igual " + result.toString());
			ress.add(result);
		}
		return ress;
	}
	/**
	 * Factorization 
	 * @param a
	 * @param p
	 * @return number obtained of the factorization 
	 */
	private Integer getFactor(BigInteger a, Integer p){
		Integer i = 0;
		BigInteger prime = new BigInteger(p.toString());
		BigInteger[] b = a.divideAndRemainder(prime);
		while (b[1].compareTo(BigInteger.ZERO) == 0){
			i++;
			b = b[0].divideAndRemainder(prime);
			
		}
		return i;
		
	}

	protected void fini_generator() throws CardException{
		shareVerification(id_card); //it can be done here or before the tally process
		cardDisconnection(0);
	}
	/**
	 * tally
	 * @param ids of SC to use 
	 * @throws CardException
	 */
	protected void useTally(Integer[] ids/*int un, int dos, int tres*/) throws CardException{
		partialreturns= new ArrayList<BigInteger>();

		generateEvaluationValues();
		generateLagrange(ids);
		
		ConcurrentTally[] tallythreads = new ConcurrentTally[ids.length];
		
		for(int i=0; i<ids.length;i++){
		
			tallythreads[i]=new ConcurrentTally(this, ids[i], cards[ids[i]], partialreturns);
			tallythreads[i].start();
		}

		for(int b=0; b<tallythreads.length;b++){
			try {
				tallythreads[b].join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		
		dec = partialreturns.get(0);
		for(int ibb=1; ibb< partialreturns.size();ibb++){
			dec = dec.multiply(partialreturns.get(ibb)).mod(p);
		}
		dec = dec.modInverse(p);
		dec = dec.multiply(z[1]).mod(p);
			       	
		System.out.println("*****************************************");
		System.out.println("missatge obtingut: " + byteArrayTohexString(dec.toByteArray()));
		System.out.println("*****************************************");
	}
	/**
	 * Connect the cards  
	 * @param id_card identifier of the card
	 * @param num_card_in_list identifier of the card in list of cards chosen
	 * @throws CardException 
	 */
	protected void cardConnection(int id_card, int num_card_in_list) throws CardException {
		System.out.println("*** CARD CONNECTION ***");
		
		if (terminal[id_card] == null){
			factory = TerminalFactory.getDefault(); //uses SunPCSC; the unique available to interact with PC/SC stack.
			terminals = factory.terminals().list();
			
	        terminal[id_card] = terminals.get(num_card_in_list);
	        
	        System.out.println(terminal[id_card].getName());
		}	
		// establish a connection with the card
		card[id_card] = terminal[id_card].connect("T=1");
		System.out.println("card: " + card);
		channel[id_card] = card[id_card].getBasicChannel();
		
		System.out.println("*****************************************");
		

	}
	/**
	 * Get number of shares
	 * @return
	 */
	protected int getNumShares(){
		return this.NUM_SHARES;
	}
	/**
	 * Get the bit length of p
	 * @return
	 */
	protected int getPbitLength(){
		return p.bitLength();
	}
	/**
	 * Get Y1 
	 * @return 
	 */
	protected BigInteger getY1total() {
		return y1total;
	}
	/**
	 * Get Y2
	 * @return
	 */
	protected BigInteger getY2total() {
		return y2total;
	}
	/**
	 * Get a list of cards connected and in use
	 * @return
	 */
	protected int[] getCards() {
		return cards;
	}
	/**
	 * Get response 
	 * @return
	 */
	protected String[] getResponsesw() {
		return responsesw;
	}
	
	/**
	 * Select the digital envelope applet. 
	 * The applet identifier of the digital envelope generation is ABCDEFFEDC151550
	 * The applet identifier of the digital envelope opening is ABCDEFFEDC151551
	 * @param is_initialized 
	 * @param id_card card identifier
	 * @return
	 * @throws CardException
	 */
	protected boolean appletSelectionInitialization(boolean is_initialized, int id_card) throws CardException{
		
		boolean ret = is_initialized;
		
		System.out.println("*** APPLET INITIALIZATION ***");
		send( "00A4040008313233343312345000", "Select the applet", id_card); //to select smartcafe expert 4
		
		if (!is_initialized){
			ret = true;
			switch(currentsizeinbits){
			case 512:
				send( "80000200", "Initialize the applet", id_card);
				break;
			case 768:
				send( "80000300", "Initialize the applet", id_card);
				break;
			case 1024:
				send( "80000400", "Initialize the applet", id_card);
				break;
			case 1280:
				send( "80000500", "Initialize the applet", id_card);
				break;
			case 1536:
				send( "80000600", "Initialize the applet", id_card);
				break;
			case 1984:
				send( "800007C0", "Initialize the applet", id_card);
				break;
			case 2048:
				send( "80000800", "Initialize the applet", id_card);
				break;		
			default: System.exit(-1);
			}
		}

		System.out.println("*****************************************");
		
		return ret;
	}

	/**
	 * Inicialization of ElGamal, send p,g,q. Futhermore if that SC is generator send the pk and sk.
	 * @param is_generator
	 * @param id_card card identifier
	 * @throws CardException
	 */
	protected void elGamalInitialization(boolean is_generator, int id_card) throws CardException {
		
		System.out.println("*** ELGAMAL INITIALIZATION ***");
		
		sendx( "01", "00", "00", byteArrayTohexString(p.toByteArray()), "Send p", id_card);
		sendx( "11", "00", "00", byteArrayTohexString(q.toByteArray()), "Send q", id_card);
		sendx( "02", "00", "00", byteArrayTohexString(g.toByteArray()), "Send g", id_card);
		
		if (is_generator){
			
			send( "80030000", "Build private key", id_card);
			send( "80040000", "Build public key", id_card);

			//send id_card
			send( "80120000010"+id_card+"00", "Save id card = 0 (it must be in 0..n)", id_card);
		}		
		System.out.println("*****************************************");
	}


	/**
	 * Threshold generation for the SC with id_card
	 * @param id_card card identifier
	 * @throws CardException
	 */
	protected void thresholdSchemeGeneration(int id_card) throws CardException {
		
		System.out.println("*** (t,n)-THRESHOLD SCHEME GENERATION ***");
		send( "801e0"+THRESHOLD+"0"+NUM_SHARES,"Save Threshold and Num_shares", id_card);
		send( "80050000", "Generate (t-1) coefficients", id_card);
		send( "80060000", "Generate (t-1) coefficients commitments", id_card);
		send( "80070000", "Generate evaluation values", id_card);
		send( "80080000", "Generate n shares", id_card);
		send( "80090000", "Generate n commitments of shares", id_card);

		System.out.println("*****************************************");
		
	}

	protected void thresholdCommonParametersBroaCasting(int id_card) throws CardException {
		
		System.out.println("*** THRESHOLD COMMON PARAMETERS BROADCASTING ***");
		
		for (int i=0;i<THRESHOLD-1;i++){
			coefs_commit[i] = send( "801B0"+i+"00", "Get coefs_commit ["+i+"] from (t-1) coefs_commit", id_card);
		}
		pk = send( "801A0000", "Get Pk", id_card);

				
		System.out.println("*****************************************");
		
	}
	/**
	 * The generator SC send the corresponding information to the receiver SC.
	 * @param id_receiver_card receiver smart card identifier
	 * @param id_generator_card generator smart card identifier
	 */	
	protected void thresholdParticularParametersBroaCasting(int id_generator_card, int id_receiver_card) throws CardException {
		
		System.out.println("*** THRESHOLD PARTICULAR PARAMETERS BROADCASTING *** FROM CARD =" + id_generator_card + " TO CARD ="+id_receiver_card);
		shares[id_receiver_card] = send( "80190"+id_receiver_card+"00", "Get share["+id_receiver_card+"] from N shares", id_generator_card);
		shares_commit[id_receiver_card] = send( "801C0"+id_receiver_card+"00", "Get share_commit["+id_receiver_card+"] from N shares_commit", id_generator_card);
		System.out.println("*****************************************");
		
	}
	/**
	 * Sending information of the SC identified by id_card parameter
	 * @param id_card card identifier
	 */
	protected void thresholdParametersReceiving(int id_card) throws CardException {
		
		System.out.println("*** THRESHOLD PARAMETERS RECEIVING ***");			
	
		send( "801e0"+THRESHOLD+"0"+NUM_SHARES,"Save Threshold and Num_shares", id_card);
		
		for (int i=0;i<THRESHOLD-1;i++){
			sendx("16","0"+i,"00", coefs_commit[i], "Save coefs_commit["+i+"] from t-1 (all) coefs_commits", id_card);
		}
		sendx("12","00","00","01","0"+id_card,"Save id card = "+id_card+" (it must be in 0..n)", id_card);

		sendx("14","00","00",shares[id_card],"Save its own share[id_card], in this case id_card = "+id_card, id_card);
		
		sendx("17","00","00",shares_commit[id_card],"Save its own share_commit[id_card], in this case id_card = "+id_card, id_card);
		
		sendx("15","00","00",pk,"Save Pk", id_card);
		
		send( "80070000", "Generate evaluation values", id_card); //it is necessary because they are not initialized yet (only in the generator case is done before here)
		
		System.out.println("*****************************************");		
	}
	/**
	 * Get threshold
	 * @return
	 */
	protected int getTHRESHOLD() {
		return THRESHOLD;
	}

	/**
	 * Verification of share with card identifier id_card
	 * @param id_card
	 * @throws CardException
	 */
	protected void shareVerification(int id_card) throws CardException {
		
		System.out.println("*** SHARE VERIFICATION ***");
		
		send( "800A0000", "Verify the received share", id_card);

		send( "800B0000", "Verify the received share commitment", id_card);

		System.out.println("*****************************************");
		
	}
	/**
	 * Share verification 
	 * @param id_card card identifier
	 * @throws CardException
	 */
	protected void share1Verification(int id_card)throws CardException{
		System.out.println("*** ONLY SHARE VERIFICATION ***");
		send( "800A0000", "Verify the received share", id_card);
		System.out.println("*****************************************");
	}
	/**
	 * Share commitment verification 
	 * @param id_card card identifier
	 * @throws CardException
	 */
	protected void sharecommitmentVerification(int id_card)throws CardException{
		System.out.println("*** SHARE COMMITMENT VERIFICATION ***");
		send( "800B0000", "Verify the received share commitment", id_card);
		System.out.println("*****************************************");
	}
	/**
	 * Encrypt the message sent in a SC identified with id_card
	 * @param id_card identifier of the SC to use for encrypt the message
	 * @param message that it is sent to encrypt in a SC.
	 * @return the result of encryption
	 * @throws CardException
	 */
	private String voting(int id_card, String message) throws CardException {
		
		System.out.println("*** VOTING ***");
		System.out.println(message);
		
		sendx("0C","00","00",message,"Send data to encrypt",id_card);
		
		String ret = send( "800D000000", "Ask for ElGamal encryption result ", id_card);
		
		System.out.println(ret.substring(0, ret.length()/2));
		System.out.println(ret.substring(ret.length()/2));
		
		z[0] = new BigInteger(ret.substring(0, ret.length()/2),16);
		z[1] = new BigInteger(ret.substring(ret.length()/2),16);
		
		System.out.println("*****************************************");
		return ret;				
	}
	/**
	 * Process of tally 
	 * @param id_card
	 * @return Result of the tally
	 * @throws CardException
	 */
	protected String tally(int id_card) throws CardException {
		
		String ret;
		
		System.out.println("*** TALLY ***");
		sendx("13", "0"+id_card, "00", byteArrayTohexString(lagrange_cef[id_card].toByteArray()), "Send lagrange_coef[id_card], in this case id_card = 1", id_card);
		sendx("1d","00","00",z[1],z[0],"Send data (y2+y1) to decrypt", id_card);
		ret = send( "800F000000", "Ask for decryption result", id_card);
		System.out.println("*****************************************");
		return ret;
	}
	/**
	 * Disconnection the card with the identifier of id_card.
	 * @param id_card card identifier 
	 * @throws CardException
	 */
	protected void cardDisconnection(int id_card) throws CardException {
		// disconnect
        card[id_card].disconnect(false);
		
	}
	/**
	 * The generation of the Lagrange coefficients.
	 * @param id_sc 
	 */
	public void generateLagrange(Integer[] id_sc){
		
		BigInteger productori = BigInteger.ONE;
		
		System.out.println("** generating Lagrange coefficients**");
		for (int i: id_sc){
			for (int j: id_sc){
				if (i!=j){								
					productori = productori.multiply(eval_values[j].multiply(((BigInteger)(eval_values[j].subtract(eval_values[i]))).modInverse(q)).mod(q)).mod(q);
				}
			}
			System.out.println(productori);
			lagrange_cef[i] = productori;
			productori=BigInteger.ONE;
		}
		
	}
	/**
	 * Generating the evaluation values
	 */
	private void generateEvaluationValues() {
		System.out.println("** generating evaluation values**");
		
		for (short i=0; i<NUM_SHARES; i++){
			eval_values[i]= new BigInteger(String.valueOf(i+1));
			System.out.println(eval_values[i]);
		}

	}
	/**
	 * Used to send the information to a SC. In this case the APDU is fractioned in the following parameters.
	 * @param INS The instruction
	 * @param P1 The parameter 1
	 * @param P2 The parameter 2 
	 * @param DATA The command data
	 * @param text The text  
	 * @param id_card The identifier of the SC
	 * @throws CardException
	 */
	private void sendx(String INS, String P1, String P2, String DATA, String text, int id_card) throws CardException{
		String CLA = "";
		String LC = "";
		String subdata = "";
		
		int index = DATA.length();
		while (index > 64){
			CLA = "90";
			LC = "20";
			subdata = CLA+INS+P1+P2+LC+DATA.substring(index-64, index)+"00";
			send(subdata, text, id_card);

			DATA = DATA.substring(0, index-64);
			index = DATA.length();
			
			
			
		}
		CLA = "80";
		LC = "20";
		while (64-DATA.length() > 0){
			DATA = "0"+DATA; //afegeix zeros per tal d'omplir els 20 bytes
		}
		subdata = CLA+INS+P1+P2+LC+DATA+"00";
		send(subdata, text, id_card);

	}
	/**
	 * Used to send the information to a SC. In this case the APDU is fractioned in the following parameters.
	 * @param INS The instruction
	 * @param P1 The parameter 1
	 * @param P2 The parameter 2 
	 * @param LC The Lc
	 * @param DATA The data 
	 * @param text The text
	 * @param id_card The identifier of the SC
	 * @throws CardException
	 */
	private void sendx(String INS, String P1, String P2, String LC, String DATA, String text, int id_card) throws CardException{
		String CLA = "80";
		String subdata = "";
		
		if (DATA.length()>64){
			System.out.println("error: data length too long");
		}else{
			subdata = CLA+INS+P1+P2+LC+DATA+"00";
			System.out.println(subdata);
			send(subdata, text, id_card);
		}
	}
	/**
	 * Used to send the information to a SC. In this case the APDU is fractioned in the following parameters.
	 * @param INS The instruction
	 * @param P1 The parameter 1
	 * @param P2 The parameter 2
	 * @param data1 The first part of data
	 * @param data2 The second part of data
	 * @param text The text
	 * @param id_card The identifier of the SC
	 * @throws CardException
	 */
	private void sendx(String INS, String P1, String P2, BigInteger data1, BigInteger data2, String text, int id_card) throws CardException{
		String CLA = "";
		String LC = "";
		String subdata = "";
		String d = "";
		
		//data1
		d = byteArrayTohexString(data1.toByteArray());
		
		
		int index = d.length();

		while (index > 64){
			CLA = "90";
			LC = "20";
			subdata = CLA+INS+P1+P2+LC+d.substring(index-64, index)+"00";
			send(subdata, text, id_card);

			d = d.substring(0, index-64);
			index = d.length();
		}
		CLA = "90";
		LC = "20";
		while (64-d.length() > 0){
			d = "0"+d; //omplir els 20 bytes
		}
		subdata = CLA+INS+P1+P2+LC+d+"00";
		send(subdata, text, id_card);
		
		//data2
		
		d = byteArrayTohexString(data2.toByteArray());
		
		index = d.length();
		while (index > 64){
			CLA = "90";
			LC = "20";
			subdata = CLA+INS+P1+P2+LC+d.substring(index-64, index)+"00";
			send(subdata, text, id_card);

			d = d.substring(0, index-64);
			index = d.length();
		}
		CLA = "80";
		LC = "20";
		while (64-d.length() > 0){
			d = "0"+d; //20bytes
		}
		subdata = CLA+INS+P1+P2+LC+d+"00";
		send(subdata, text, id_card);
	}
	/**
	 * Used to send the information to a SC. In this case the APDU is fractioned in the following parameters.
	 * @param apdu The apdu in a only block 
	 * @param text The text
	 * @param id_card The identifier of the SC
	 * @return The return message of the SC 
	 * @throws CardException
	 */
	private String send(String apdu, String text, int id_card) throws CardException {
		CommandAPDU c;
		String ret = "0";
		String sw="";
		
		if (!apdu.isEmpty()){
			System.out.println(text + ":");
			System.out.println("---"+id_card+"--> " + apdu);
			
			if (currentsizeinbits == 2048 && apdu.length() == 8 ){ //hacking per 2048 bits -> java.lang.ArrayIndexOutOfBoundsException: 4
				apdu += "00";
			}
			c = new CommandAPDU(hexStringToByteArray(apdu));

			r = channel[id_card].transmit(c);
			System.out.print("<--"+id_card+"--- ");
			sw = Integer.toHexString(r.getSW());
			responsesw[0]=sw;
			responsesw[1]=String.valueOf(id_card);
			
			System.out.println("ret(SW): "+ sw);
			if (r.getData().length > 0){
				System.out.println(r.getData());
				ret = byteArrayTohexString(r.getData());
				
				while(sw.compareTo("ffc0")==0){ //ISO7816.SW_BYTES_REMAINING_00
					System.out.println("---"+id_card+"--> " + "00c0000000");
					c = new CommandAPDU(hexStringToByteArray("00c0000000")); //send more
					r = channel[id_card].transmit(c);
					ret = byteArrayTohexString(r.getData()).concat(ret);
					sw = Integer.toHexString(r.getSW());
					this.responsesw[0]=sw;
					this.responsesw[1]=String.valueOf(id_card);
					System.out.print("<--"+id_card+"--- ");
					System.out.println("ret(SW): "+sw);
				}
				System.out.println("        Data returned: " + ret);
			}else{
				System.out.println();
			}
			System.out.println();
		}else{
			this.responsesw[0]=sw;
			this.responsesw[1]=String.valueOf(id_card);
			System.out.println(" --------------------- WARNING: apdu is empty --------------------- ");
		}
		
		return ret;
	}
	
	/**
	 * For convert a String in hexadecimal form to byte array.
	 * @param in String in hexadecimal form
	 * @return A new byte array from the String received in the parameter 
	 */
	public static byte[] hexStringToByteArray(String in) {
		
		int len = in.length()>>1;
		if (len<<1 != in.length()) len++;//odd number of hexadecimal numbers; need an extra value to fit in a byte
		byte[] out = new byte[len];
		for (int i=in.length()-1; i>0; i=i-2) {
			out[i>>1]=(byte)Integer.parseInt("0"+in.substring(i-1, i+1), 16);
		}
		return out;
	}
	/**
	 * Convert the apdu of byte array to String
	 * @param apdu The byte array of the apdu
	 * @return The String of the apdu
	 */
	public static String toString(byte[] apdu) {
		
		if (apdu == null || apdu.length ==0) {
			return "";
		}
		Formatter formatter = new Formatter();
		formatter.format("(%d)", apdu.length);
		for (int i=0; i < apdu.length; i++) {
			formatter.format("%02X", apdu[i]& 0xff);
		}
		return formatter.toString();
	}
	
	/**
	 * For convert a byte array to String.
	 * @param bytes Byte array to convert
	 * @return String of byte array
	 */
	public String byteArrayTohexString(byte[] bytes){
		
		int cBytes = bytes.length;
        	int iByte = 0;
        	String ret = "";
        	for (;;) {
            		for (int i = 0; i < 8; i++) {
                		String hex = Integer.toHexString(bytes[iByte++] & 0xff);
                		if (hex.length() == 1) {
                    		hex = "0" + hex;
                		}
                		ret = ret+hex;
                		if (iByte >= cBytes) {
                			while (ret.startsWith("0")){ //in order to remove left side zeros
                				ret = ret.substring(1);
                			}
                    			return ret;
                		}
            		}
        	}
	}	
}
