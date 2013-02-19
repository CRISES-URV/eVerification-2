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
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
/**
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló & Vicenç Creus Garcia
 *
 */ 
public class ElGamalThresholdApplet extends Applet{ 
	
	/* ************** CLASSES OF APDUs **************************/
	// CLA bytes
    static final byte ELGAMAL_CLA = (byte)0x80; //java card propietary CLA
    static final byte ELGAMAL_CLA_REC_MORE = (byte)0x90; //java card propietary CLA, used to store more bytes into smartcard
    static final byte ELGAMAL_CLA_SEND_MORE = ISO7816.CLA_ISO7816; //0x00: java card propietary CLA, used to ask more bytes from smartcard

    // INS bytes, and also values for states.
	// 0x0X: Code for INS in Command APDU.
	// 0x1X: Code not used in any Command APDU.
	
	/* States for the initialization */
	static final byte PC2SC_UNINITIALIZED = (byte)0x00;
	static final byte SC2SC_INITIALIZED = (byte)0x10;
	
	/* States for the P storage into the smartcard. */
	static final byte PC2SC_SAVING_P = (byte)0x01;
	
	/* States for the P storage into the smartcard. */
	static final byte PC2SC_SAVING_Q = (byte)0x11;
	
	/* States for the G storage into the smartcard. */
	static final byte PC2SC_SAVING_G = (byte)0x02;
	
	/* States for the G storage into the smartcard. */
	static final byte PC2SC_SAVING_T_N = (byte)0x1e;
	
	/* States for the generation of the public and private key into the smartcard. */
	static final byte PC2SC_GENERATING_PRIVATEKEY = (byte)0x03; //s -> secure random
	static final byte PC2SC_GENERATING_PUBLICKEY = (byte)0x04; //y <- g**s mod p
	
	/* States for shares generation. (t,n)-threshold scheme. */
	static final byte PC2SC_GENERATING_COEFFICIENTS = (byte)0x05; //generate (t-1) coefficients
	static final byte PC2SC_GENERATING_COEF_COMMITMENTS = (byte)0x06; //generate (t-1) commitments
	static final byte PC2SC_GENERATING_EVALUATION_VALUES = (byte)0x07; //generate n random values
	static final byte PC2SC_GENERATING_N_SHARES = (byte)0x08; //only 1 share
	static final byte PC2SC_GENERATING_SHARES_COMMITMENTS = (byte)0x09; //n commitments for n share at once (g**h mod p); discard communication costs
	
	/* States for shares verification. */
	static final byte PC2SC_VERIFY_SHARE = (byte)0x0a; // compute (g**h mod p)  and (comparison of 2 equal big integers)
	static final byte PC2SC_VERIFY_SHARE_COMMITMENT = (byte)0x0b; //compute (y* \prod_{j=1}^{t-1} B_j^{x_i^j}
	
	/* States for the encryption of data sent to the smartcard. */
	static final byte PC2SC_ENCRYPTING = (byte)0x0c;
	static final byte SC2PC_SENDING_ENC = (byte)0x0d;
	
	/* States for the decryption of data sent to the smartcard. */
	static final byte PC2SC_DECRYPTING = (byte)0x0e;
	static final byte SC2PC_SENDING_DEC =(byte)0x0f;
	
	/* APDU code for send more bytes from smartcard to PC */
	static final byte SC2PC_SENDING_MORE = (byte)0xc0;
	
	static final byte PC2SC_THRESHOLD_DECRYPTING = (byte)0x1D;
	
	/* APDU code for threshold scheme initialization */
	static final byte PC2SC_SAVING_IDCARD = (byte)0x12;
	static final byte PC2SC_SAVING_LAGRANGE = (byte)0x13;
	static final byte PC2SC_SAVING_SHARE = (byte)0x14;
	static final byte PC2SC_SAVING_PK = (byte)0x15;
	static final byte PC2SC_SAVING_COEF_COMMIT = (byte)0x16;
	static final byte PC2SC_SAVING_SHARE_COMIT = (byte)0x17;
	
	/* APDU code for sende parameters in order to initialize the other SC*/
	//static final byte SC2PC_SENDING_IDCARD = (byte)0x18;
	static final byte SC2PC_SENDING_SHARE = (byte)0x19;
	static final byte SC2PC_SENDING_PK = (byte)0x1A;
	static final byte SC2PC_SENDING_COEF_COMMIT = (byte)0x1B;
	static final byte SC2PC_SENDING_SHARE_COMIT = (byte)0x1C;
	
	
    /* END ************** CLASSES OF APDUs **************************/
	
	/* Maximum length in response APDU in bytes. */
	static final short MAX_RAPDU_LENGTH = 0xfa;
    
	//current state of the applet
	static short state;
	
    // temporary values
    static short bytesToRead, readBytes, resultSize, resultSent, indexToRead; 

    // Reference to the cipher object
    static ElGamalCipher    cipher; 
    static byte[] result;
    static short NUM_SHARES = 5;
    static short THRESHOLD = 5;
    

    static MutableBigInteger temp1, temp2, temp3; //auxiliar result
    static MutableBigInteger shares[]; //private shares = hi
    static MutableBigInteger shares_commit[];
    static MutableBigInteger eval_values[]; //evaluation values
    static MutableBigInteger coefs[]; //coefficients
    static MutableBigInteger coefs_commit[]; //coefficients commitments
    static MutableBigInteger lagrange, share, share_commit;

    static short ID_CARD = 0; //card id saved in a new process, require commincaion in share assignement
    static boolean first_time = true;
    
    /**
     * Initializes the test applet, with the current maximum number of bits
     * for the big numbers to use in the given instance.
     */
    public ElGamalThresholdApplet(short length) {
    	
    	//initialize ciphers and keys 
    	
    	state = PC2SC_UNINITIALIZED;
    	
    	cipher = ElGamalCipher.getInstance((short)length);
    	
    	result = new byte[length>>2];
    	
    	resultSize = 0;
    	//initialize MutableBigIntegers 
    	temp1 = new MutableBigInteger(true); //in RAM
    	temp2 = new MutableBigInteger(true); //in RAM
    	temp3 = new MutableBigInteger(true); //in RAM

    	coefs = new MutableBigInteger[(short)(THRESHOLD-1)];
    	coefs_commit = new MutableBigInteger[(short)(THRESHOLD-1)];
    	
    	for (short i=0; i<(short)(THRESHOLD-1); i++){
    		coefs[i] = new MutableBigInteger(false); //in RAM
    		coefs_commit[i] = new MutableBigInteger(false);  //in EPROM, it is necessary because it is used in share verification
    	}
    	
    	eval_values = new MutableBigInteger[NUM_SHARES];
    	shares = new MutableBigInteger[NUM_SHARES];
    	shares_commit = new MutableBigInteger[NUM_SHARES];
    	
    	for (short i=0; i<NUM_SHARES; i++){
    		eval_values[i] = new MutableBigInteger(false); //in EPROM, it is necessary because it is used in share verification
    		shares[i] = new MutableBigInteger(true); //in RAM because they are temporal and must be securely deleted
    		shares_commit[i] = new MutableBigInteger(false); //in EPROM because there are not enough ram memory
    	}
    	
    	share = new MutableBigInteger(false); //in EPROM
    	share_commit = new MutableBigInteger(false); //in EPROM
    	lagrange = new MutableBigInteger(true); //in RAM  because it is temporal, it is transmitted in the tally process.
    	
    	register();
    }
    
	/**
	 * Static method invoked by the JCRE (JavaCard Runtime Environment)
	 * to instantiate an applet instance and register it with the JCRE.<br>
	 * We only instantiate the applet in this method.
	 * @param buffer the array containing installation parameters.
	 * @param offset the starting offset in buffer.
	 * @param length the length in bytes of the parameter data in buffer.
	 * The maximum value of length is 32.
	 */
	public static void install(byte[] buffer, short offset, byte length) {
		new ElGamalThresholdApplet((short)2050);
	}

	/**
	 * Process the received APDU.
	 * @param apdu is the received APDU.
	 * 
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) throws ISOException { 
		// 1. test the CLASS
		// 1.1. SELECT APDU
		
		if (selectingApplet())  { 
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
			return;
		}
		
		// Gets the APDU buffer.
		byte[] buf = apdu.getBuffer(); 
		
		// 2.2. All correct; use the cipher functions.
		switch(buf[ISO7816.OFFSET_CLA]) {
		case ELGAMAL_CLA:
			switch (buf[ISO7816.OFFSET_INS]) {
			case PC2SC_UNINITIALIZED:
				cipher.initialize(Util.getShort(buf, ISO7816.OFFSET_P1)); //0x/200 = 512 bits
				return;
			//Save the prime p where p is p = 2q + 1. 
			case PC2SC_SAVING_P:
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					cipher.saveP(buf, ISO7816.OFFSET_CDATA, readBytes, true); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Save q where q is a large prime order 
			case PC2SC_SAVING_Q:
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
						//appends the data into the big number
					cipher.saveQ(buf, ISO7816.OFFSET_CDATA, readBytes, true); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}

				return;
			//Save the generator g.
			case PC2SC_SAVING_G:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					cipher.saveG(buf, ISO7816.OFFSET_CDATA, readBytes, true); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Save lagrange
			case PC2SC_SAVING_LAGRANGE:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					save(buf, ISO7816.OFFSET_CDATA, readBytes, true, lagrange); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Save share
			case PC2SC_SAVING_SHARE:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					save(buf, ISO7816.OFFSET_CDATA, readBytes, true, share); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;	
			//Save share commitment
			case PC2SC_SAVING_SHARE_COMIT:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					save(buf, ISO7816.OFFSET_CDATA, readBytes, true, share_commit); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Save coefficient commitment
			case PC2SC_SAVING_COEF_COMMIT:
				
				indexToRead = (short)(buf[ISO7816.OFFSET_P1] & 0xff);
				if (indexToRead < (short)(THRESHOLD-1)){
					bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
					readBytes = apdu.setIncomingAndReceive();
					while (readBytes > 0) {
						bytesToRead -= readBytes;
						//appends the data into the big number
						save(buf, ISO7816.OFFSET_CDATA, readBytes, true, coefs_commit[indexToRead]); //true means last portion
						readBytes = apdu.receiveBytes(bytesToRead);
					}
				}else{
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}
					
				return;	
			//Save ElGamal public key
			case PC2SC_SAVING_PK:

				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					save(buf, ISO7816.OFFSET_CDATA, readBytes, true, ((ElGamalPublicKey)cipher.getKeyPair().getPublic()).getPublicKey()); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}
					
				return;	
			//Save card identifier
			case PC2SC_SAVING_IDCARD:
					
				apdu.setIncomingAndReceive();
					ID_CARD = (short)(buf[ISO7816.OFFSET_CDATA] & 0xff);
					if (ID_CARD >= NUM_SHARES){
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					}
				return;	
			//Generate ElGamal private key
			case PC2SC_GENERATING_PRIVATEKEY:
				cipher.buildPrivateKey();
				return;
			//Generate ElGamal public key	
			case PC2SC_GENERATING_PUBLICKEY:
				cipher.buildPublicKey();
				return;
			//Save the value of threshold scheme and number of shares
			case PC2SC_SAVING_T_N:
					apdu.setIncomingAndReceive();
					THRESHOLD = (short)(buf[ISO7816.OFFSET_P1] & 0xff);
					NUM_SHARES = (short)(buf[ISO7816.OFFSET_P2] & 0xff);
					if (THRESHOLD > NUM_SHARES || NUM_SHARES > 5){
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					}
				return;
			//Generate coefficients
			case PC2SC_GENERATING_COEFFICIENTS:
				generateCoefficients();
				return;
			//Generate coefficient commitments
			case PC2SC_GENERATING_COEF_COMMITMENTS:			
				generateCoefCommitments();
				return;
			//Generate evaluation values
			case PC2SC_GENERATING_EVALUATION_VALUES:
				generateEvaluationValues();
				return;
			//Generate n shares
			case PC2SC_GENERATING_N_SHARES:
				generateShares();
				return;
			//Generate the shares commitmets
			case PC2SC_GENERATING_SHARES_COMMITMENTS:
				generateSharesCommitments();
				return;
			//Verify a share commitment
			case PC2SC_VERIFY_SHARE_COMMITMENT:
				
				if(verifyShareCommitment()==0){
					ISOException.throwIt(ISO7816.SW_NO_ERROR);
				}else{
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}

				return;
			//Verify a share	
			case PC2SC_VERIFY_SHARE:
				if(verifyShare()==0){
					ISOException.throwIt(ISO7816.SW_NO_ERROR);
				}else{
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				return;
			//Encryption
			case PC2SC_ENCRYPTING:
				encrypt(apdu, buf, false); //false means this is the last portion
				return;
			//Send encryption
			case SC2PC_SENDING_ENC:
				sendBackResult(apdu);
				return;
			//Decryption
			case PC2SC_DECRYPTING:
				decrypt(apdu, buf, false); //false means this is the last portion
				return;
			//
			case PC2SC_THRESHOLD_DECRYPTING:
				thresholdDecrypt(apdu, buf, false); //false means this is the last portion
				return;
			case SC2PC_SENDING_DEC:
				sendBackResult(apdu);
				return;
			//Send share
			case SC2PC_SENDING_SHARE:

				indexToRead = (short)(buf[ISO7816.OFFSET_P1] & 0xff);
				if (indexToRead < NUM_SHARES){
					resultSize = shares[indexToRead].len;
					resultSent = 0;
					//}
					shares[indexToRead].copyTo(result,(short)0);
					sendBackResult(apdu);
				}else{
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}

				return;
			//Send share commitment
			case SC2PC_SENDING_SHARE_COMIT:
				
				indexToRead = (short)(buf[ISO7816.OFFSET_P1] & 0xff);
				if (indexToRead < NUM_SHARES){
					resultSize = shares_commit[indexToRead].len;
					resultSent = 0;
	
					shares_commit[indexToRead].copyTo(result,(short)0);
					sendBackResult(apdu);
				}else{
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}

				return;
			//Send coefficient commitment 
			case SC2PC_SENDING_COEF_COMMIT:
				
				indexToRead = (short)(buf[ISO7816.OFFSET_P1] & 0xff);
				if (indexToRead < (short)(THRESHOLD-1)){
					resultSize = coefs_commit[indexToRead].len;
					resultSent = 0;
	
					coefs_commit[indexToRead].copyTo(result,(short)0);
					sendBackResult(apdu);
				}else{
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}
				
				return;
			//Send ElGamal public key
			case SC2PC_SENDING_PK:
				
				resultSize = cipher.getKeyPair().getPublicValue().len;
				resultSent = 0;

				cipher.getKeyPair().getPublicValue().copyTo(result,(short)0);
				sendBackResult(apdu);

				return;
			default: ISOException.throwIt(buf[ISO7816.OFFSET_INS]);
			}
			
		case ELGAMAL_CLA_REC_MORE:
			switch (buf[ISO7816.OFFSET_INS]) {
			//Receive more bytes of prime p
			case PC2SC_SAVING_P:
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					cipher.saveP(buf, ISO7816.OFFSET_CDATA, readBytes, false); //false means more portions are coming
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Receive more bytes of prime q
			case PC2SC_SAVING_Q:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					cipher.saveQ(buf, ISO7816.OFFSET_CDATA, readBytes, false); //false means more portions are coming
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Receive more bytes of generator g
			case PC2SC_SAVING_G:
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					cipher.saveG(buf, ISO7816.OFFSET_CDATA, readBytes, false); //false means more portions are coming
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Receive more bytes of lagrange
			case PC2SC_SAVING_LAGRANGE:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					save(buf, ISO7816.OFFSET_CDATA, readBytes, false, lagrange); //false means more portions are coming
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Receive more bytes of share
			case PC2SC_SAVING_SHARE:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					save(buf, ISO7816.OFFSET_CDATA, readBytes, false, share); //false means more portions are coming
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Receive more bytes of share commitment
			case PC2SC_SAVING_SHARE_COMIT:
				//received data appears in the 'incoming' number.
				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					save(buf, ISO7816.OFFSET_CDATA, readBytes, false, share_commit); //false means more portions are coming
					readBytes = apdu.receiveBytes(bytesToRead);
				}
				return;
			//Receive more bytes of coefficient commitment
			case PC2SC_SAVING_COEF_COMMIT:
				indexToRead = (short)(buf[ISO7816.OFFSET_P1] & 0xff);
				if (indexToRead < (short)(THRESHOLD-1)){
					bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
					readBytes = apdu.setIncomingAndReceive();
					while (readBytes > 0) {
						bytesToRead -= readBytes;
						//appends the data into the big number
						save(buf, ISO7816.OFFSET_CDATA, readBytes, false, coefs_commit[indexToRead]); //true means last portion
						readBytes = apdu.receiveBytes(bytesToRead);
					}
				}else{
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}
					
				return;		
			//Receive more bytes of ElGamal public key
			case PC2SC_SAVING_PK:

				bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
				readBytes = apdu.setIncomingAndReceive();
				while (readBytes > 0) {
					bytesToRead -= readBytes;
					//appends the data into the big number
					
					save(buf, ISO7816.OFFSET_CDATA, readBytes, false, ((ElGamalPublicKey)cipher.getKeyPair().getPublic()).getPublicKey()); //true means last portion
					readBytes = apdu.receiveBytes(bytesToRead);
				}	
				return;	
			
			case PC2SC_ENCRYPTING:
				encrypt(apdu, buf, true); //true means more portions are coming
				return;
				
			case PC2SC_DECRYPTING:
				decrypt(apdu, buf, true); //true means more portions are coming
				return;
				
			case PC2SC_THRESHOLD_DECRYPTING:
				thresholdDecrypt(apdu, buf, true); //false means this is the last portion
				return;
				
			default: ISOException.throwIt (ISO7816.SW_INS_NOT_SUPPORTED);
			}
			
		case ELGAMAL_CLA_SEND_MORE:
			switch (buf[ISO7816.OFFSET_INS]) {
			//Send more bytes
			case SC2PC_SENDING_MORE:
				sendBackResult(apdu);
				return;
				
			default: ISOException.throwIt (ISO7816.SW_INS_NOT_SUPPORTED);
			}
		default: ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}
	/**
	 * Generate a random 
	 * @param a variable where it generates the random
	 */
	private void generateRandom(MutableBigInteger a) {
		a.setRandomValue((short)(Configuration.currentSizeInBytes - 1));
	}
	

	/**
	 * Saves the byte array in a MutableBiginteger structure 
	 * @param buf source byte array
	 * @param off offset within source byte array to start copy from
	 * @param len byte length to be copied
	 * @param last to control if is the last part of data 
	 * @param var destination MutableBigInteger
	 */
	/* Saves the lagrange coefficients */
	public void save(byte[] buf, short off, short len, boolean last, MutableBigInteger var) {

		if (first_time){
			/* solve the problem of append in a var*/
			var.reset();
			first_time = false;
		}
		
		var.append(buf, off, len);
		
		if (last) {
			first_time = true;
			var.normalize();
		}
			
	}
	
	/**
	 * Emulation of the generation of all coefficients.
	 * Steps Section (3.2), point 4.(a).
	 */
	private void generateCoefficients() {
		for (short i=0; i<(short)(THRESHOLD-1); i++){
			generateRandom(coefs[i]);
			coefs[i].normalize(); //-> ja hi esta!
		}
	}
	
	/**
	 * Emulation of generation of the commitment of the coefficients.
	 * Steps Section (3.2), point 4.(b). 
	 */
	private void generateCoefCommitments() {
		for (short i=0; i<(short)(THRESHOLD-1); i++){
			Math.modPow(coefs_commit[i],cipher.props.g, coefs[i], cipher.props.p); //(res, base, exp, mod)
			coefs_commit[i].normalize();
		}
	}
	
	/**
	 * Emulation of the generation of the evaluation values of the secret
	 * function.
	 * Steps Section (3.2), point 4.(d).
	 */
	private void generateEvaluationValues() {
		for (short i=0; i<NUM_SHARES; i++) {
			eval_values[i].setValue((short)(i+1));
			eval_values[i].normalize();
		}
	}
	
	/**
	 * Generation of n share.
	 */
	private void generateShares() {
		
		for (short i=0; i<NUM_SHARES; i++) {
			for (short j=0; j<(short)(THRESHOLD-1); j++){
				if (j==0){
					/*temp1 is first time used*/
					Math.modMul(temp1, eval_values[i], coefs[j],  cipher.props.q); //evaluation b1*x^1
				}else{
					temp2.setValue((byte)(j+1)); //temp2 = exponent
					Math.modPow(temp3, eval_values[i], temp2, cipher.props.q); //evaluation of xi^j
					Math.modMul(temp2, temp3, coefs[j], cipher.props.q); //evaluation of bj*xi^j
					temp3.copyValue(temp1);
					Math.modAdd(temp1, temp3, temp2, cipher.props.q); //sumatori
				}
			}
			Math.modAdd(shares[i], temp1, cipher.getKeyPair().getPrivateValue(), cipher.props.q); //adds s to x^1
			shares[i].normalize();
		}
		share.clear();
		share.copyValue(shares[ID_CARD]); //save their own share
		
		temp1.clear();
		temp2.clear();
		temp3.clear();
		
		((ElGamalPrivateKey)cipher.getKeyPair().getPrivate()).clearKey(); //remove Sk
		

	}
	
	/**
	 * Generation of the commitments for all shares.
	 *
	 */
	private void generateSharesCommitments() {
		for (short i=0; i<NUM_SHARES; i++) {
			Math.modPow(shares_commit[i], cipher.props.g, shares[i], cipher.props.p);
			shares_commit[i].normalize();
		}
		
		share_commit.copyValue(shares_commit[ID_CARD]);
	}
	
	/**
	 * Verification of the generated share commitments.
	 */
	public short verifyShareCommitment() {
		
		for (short j=0; j<(short)(THRESHOLD-1); j++) {
			if (j==0){
				Math.modPow(temp1, coefs_commit[j], eval_values[ID_CARD], cipher.props.p); //evaluation B1*xi^1
				
			}else{
				temp2.setValue((short)(j+1)); //temp2 = exponent
				Math.modPow(temp3, eval_values[ID_CARD], temp2, cipher.props.q); //evaluation of xi^j  eval_values[ID_CARD]
				Math.modPow(temp2, coefs_commit[j], temp3, cipher.props.p); //evaluation B1*xi^1
				temp3.copyValue(temp1);
				
				Math.modMul(temp1, temp3, temp2, cipher.props.p); //productori, adds all intermediate results.

			}
		}
		Math.modMul(temp2, ((ElGamalPublicKey)cipher.getKeyPair().getPublic()).getPublicKey(), temp1, cipher.props.p); //evaluation of y*productori({B_j}^{x_i})
		
		return share_commit.compare(temp2); //is the same share commitment?
	}
	
	/**
	 * Verification of the share.
	 */
	public short verifyShare() {
	
		Math.modPow(temp2, cipher.props.g, share, cipher.props.p);
		return share_commit.compare(temp2);
		
	}
	
	/**
	 * Receives data to encrypt. When it is the last APDU, it starts the 
	 * encryption of all the received data.
	 * @param apdu the received command APDU. 
	 * @param buf the corresponding buffer to the given {@code apdu}.
	 * @param chaining whether the smartcard will receive more bytes.
	 */
	private void encrypt(APDU apdu, byte[] buf, boolean chaining) {
		// 0. store data
		if (state != PC2SC_ENCRYPTING) {
			temp1.clear();
			generateRandom(temp1);
			cipher.initEncrypt(temp1.data, (short)temp1.off, (short)temp1.getLength());
			state = PC2SC_ENCRYPTING;
			resultSize = 0;
			resultSent = 0;
		}
		bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
		readBytes = apdu.setIncomingAndReceive();
		while (readBytes > 0) {
			bytesToRead -= readBytes;
			//appends the data into the cipher to be encrypted. no actual encryption is processed.
			cipher.update(buf, ISO7816.OFFSET_CDATA, readBytes, result, (short)0);
			readBytes = apdu.receiveBytes(bytesToRead);
		}
		if (!chaining) { //last APDU; all data is received; ready to encrypt
			//no data is passed, but encryption is processed
			resultSize += cipher.doFinal(buf, ISO7816.OFFSET_CDATA, (short)0, result, (short)0);
			//result stored in 'result'; ready to send back the encryption.
			state = SC2SC_INITIALIZED;
		}
	}
	
	/**
	 * Receives data to decrypt. When it is the last APDU, it starts the
	 * decryption process of all the received data.
	 * @param apdu the received command APDU.
	 * @param buf the corresponding buffer to the given {@code apdu}.
	 * @param chaining whether the smartcard will receive more bytes.
	 */
	private void decrypt(APDU apdu, byte[] buf, boolean chaining) {
		// 0. store data
		if (state != PC2SC_DECRYPTING) {
			cipher.initDecrypt();
			state = PC2SC_DECRYPTING;
			resultSize = 0;
			resultSent = 0;
		}
		bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
		readBytes = apdu.setIncomingAndReceive();
		while (readBytes > 0) {
			bytesToRead -= readBytes;
			//appends the data into the cipher to be encrypted. no actual encryption is processed.
			cipher.update(buf, ISO7816.OFFSET_CDATA, readBytes, result, (short)0);
			readBytes = apdu.receiveBytes(bytesToRead);
		}
		if (!chaining) { //last APDU; all data is received; ready to decrypt
			//no data is passed, but encryption is processed
			resultSize += cipher.doFinal(buf, ISO7816.OFFSET_CDATA, (short)0, result, (short)0);
			//result stored in 'result'; ready to send back the encryption.
			state = SC2SC_INITIALIZED;
		}
	}
	
	/**
	 * Receives data to decrypt. When it is the last APDU, it starts the
	 * decryption process of all the received data.
	 * @param apdu the received command APDU.
	 * @param buf the corresponding buffer to the given {@code apdu}.
	 * @param chaining whether the smartcard will receive more bytes.
	 */
	private void thresholdDecrypt(APDU apdu, byte[] buf, boolean chaining) {
		// 0. store data
		if (state != PC2SC_THRESHOLD_DECRYPTING) {
			cipher.initDecrypt();
			state = PC2SC_THRESHOLD_DECRYPTING;
			resultSize = 0;
			resultSent = 0;
		}
		bytesToRead = (short)(buf[ISO7816.OFFSET_LC] & 0xff);
		readBytes = apdu.setIncomingAndReceive();
		while (readBytes > 0) {
			bytesToRead -= readBytes;
			//appends the data into the cipher to be encrypted. no actual encryption is processed.
			cipher.update(buf, ISO7816.OFFSET_CDATA, readBytes, result, (short)0);
			readBytes = apdu.receiveBytes(bytesToRead);
		}
		if (!chaining) { //last APDU; all data is received; ready to decrypt
			//no data is passed, but encryption is processed
			
			resultSize += cipher.doThresholdDec(buf, ISO7816.OFFSET_CDATA, (short)0, result, (short)0, share, lagrange);
			//result stored in 'result'; ready to send back the encryption.
			state = SC2SC_INITIALIZED; //state can be anyone different to PC2SC_THRESHOLD_DECRYPTING
		}
	}
	
	
	/**
	 * Sends the result of an encryption/decryption back to the PC.
	 * @param apdu received command APDU.
	 */
	private void sendBackResult(APDU apdu) {
		apdu.setOutgoing();
		// 1. the remaining content fits in a single APDU?
		if ((short)(resultSize - resultSent) > ((short)(0xff & MAX_RAPDU_LENGTH))) {
			apdu.setOutgoingLength(MAX_RAPDU_LENGTH);
			resultSent += 0xff & MAX_RAPDU_LENGTH;
			apdu.sendBytesLong(result, (short)(resultSize - resultSent), MAX_RAPDU_LENGTH);

			ISOException.throwIt((short)24832);

		} else { // last APDU
			resultSent = (short)(resultSize - resultSent); //!!!! now it is the length to send
			apdu.setOutgoingLength(resultSent);
			apdu.sendBytesLong(result, (short)0, resultSent);
			ISOException.throwIt(ISO7816.SW_NO_ERROR);	
		}
	}
	/**
	 * @see javacard.framework.AppletEvent#uninstall()
	 */
	public void uninstall() {
		cipher.uninstall();
		cipher = null;
	}
}
