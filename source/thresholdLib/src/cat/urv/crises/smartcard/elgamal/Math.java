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
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
//import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;


/**
 * This class contains the whole set of operations available for big numbers,
 * such as {@code modMul} and {@code modPow}.
 * <p>
 * All operations behave as if the big numbers were represented in two's-complement
 * notation (like Java's primitive integer types). All complex
 * operations are performed by this class, but MutableBigIngeger provides
 * basic functionality and aims to behave as a big number container with 
 * minimal functionality. 
 *  
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló 
 *
 */
public class Math {  
	
	/* The following class attributes are necessary for auxiliar and 
	 * temporary use when computing operations with big numbers. */
	
	/* Indexes for arrays. */
	private static short i, j, k; 
	/* Length indicators  */
	private static short len1, len2, len3;
	/* Storage for temporary values. */
	private static short temp, temp2;
	/* Carry value when computing operations. */
	private static byte carry;
	/* Byte values when computing operations. */
	private static byte val1, val2, val3;
	/* Reference to the byte[] */
	/* Mask for limiting byte values. */
    private final static short BYTE_MASK = 0xFF;
    /* References for byte[] */
	private static byte[] data1, data2, result;
	/* Borrow flag. */
	private static boolean borrow;
	
	/* **************** necessary to calculate modPow *************************/
	/* Key to be used to initialize as for calculate modPow using the
	 * RSA cryptosystem available in the Java Card. */
	private static RSAPublicKey key;
	/* RSA cipher abstraction necessary to compute the modPow, using the
	 * RSA cryptosystem available in the Java Card. */
	private static Cipher rsa;
	
	/* Keys for all tests. */
	private static RSAPublicKey key512;
	private static RSAPublicKey key736;
	private static RSAPublicKey key768;
	private static RSAPublicKey key896;
	private static RSAPublicKey key1024;
	private static RSAPublicKey key1280;
	private static RSAPublicKey key1536;
	private static RSAPublicKey key1984;
	private static RSAPublicKey key2048;
	/* **************** END necessary to calculate modPow *********************/ 
	
    /**
     * MutableBigInteger with one element value array with the value 1. Used by 
     * BigDecimal divideAndRound to increment the quotient. Use this constant
     * only when the method is not going to modify this object.
     */
    public static MutableBigInteger ONE = null;
    public static MutableBigInteger TWO = null; 
    
    /**
     * MutableBigInteger necessary to store temporary results.
     */
    static MutableBigInteger bnaux = null;
    static MutableBigInteger bnaux2 = null;
    static MutableBigInteger bnaux3 = null;
    
	/**
	 * Initializes the internal big numbers for temporary use to fit
	 * to the necessary bitPrecision.
	 */
	public static void init() {
		if (ONE == null) { //execute only once!!
			MutableBigInteger.init();
			ONE  = new MutableBigInteger(Configuration.inRAM);
			ONE.setValue((byte)1);
			// The 2 number, altered specifically to work with the RSA cipher.
			TWO  = new MutableBigInteger(Configuration.inRAM);
			TWO.setValue((byte)2); //fixSizeAndClear() is invoked any time when current size is updated.
			bnaux = new MutableBigInteger(Configuration.inRAM); 
			bnaux2 = new MutableBigInteger(Configuration.inRAM);
			bnaux3 = new MutableBigInteger(Configuration.inRAM);
			
			try {
				key512 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
				key736 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)736, false);
				key768 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_768, false);
				key896 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)896, false);
				key1024 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
				key1280 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)1280, false);
				key1536 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)1536, false);
				key1984 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)1984, false);
				key2048 = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
			} catch (CryptoException e) {
				ISOException.throwIt((short)0x6001);
			}
			
			rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
			
			
		}
	}

	/**
	 * Postinitialization of Math attributes, after each time the current size
	 * of big number to use is updated.
	 */
	public static void postInit() {
		//TWO.fixSizeAndClear(Configuration.currentSizeInBytes);
		switch (Configuration.currentSizeInBits) {
		case 512: 
			key = key512;
			break;
		case 736:
			key = key736;
			break;
		case 768:
			key = key768;
			break;
		case 896:
			key = key896;
			break;
		case 1024:
			key = key1024;
			break;
		case 1280:
			key = key1280;
			break;
		case 1536:
			key = key1536;
			break;
		case 1984:
			key = key1984;
			break;
		case 2048:
			key = key2048;
			break;
		default:
			ISOException.throwIt((short)0x6002);
		}
	}
	
	/* ****************************   add    **********************************/
	
	/**
	 * Calculates {@code res := (op1 + op2) mod (mod)}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand.
	 * @param op2 second operand.
	 * @param mod modulus.
	 * @throws {@code ISO7816.SW_WRONG_LENGTH} when the internal byte[] of 'res' has
	 * insufficient space for storing the result.
	 */
	public static void modAdd(MutableBigInteger res, MutableBigInteger op1, MutableBigInteger op2, MutableBigInteger mod) {
		add(res, op1, op2);
		//this is inefficient, but this bucle should be used at most once.
		while (res.compare(mod)>0) {
			selfSubtract(res, mod);
		}
	}
	
	/**
	 * Calculates {@code res := op1 + op2}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand.
	 * @param op2 second operand.
	 * @throws {@code ISO7816.SW_WRONG_LENGTH} when the internal byte[] of 'res' has
	 * insufficient space for storing the result.
	 */
	public static void add(MutableBigInteger res, MutableBigInteger op1, MutableBigInteger op2)  {
		len1 = op1.off;
		len2 = op2.off;
		i = (short)(len1 + op1.len);
        j = (short)(len2 + op2.len);
        result = res.data;
        data1 = op1.data;
        data2 = op2.data;
        k = (short)result.length;
        carry = 0;
        
        // Add common parts of both numbers
        while(i>len1 && j>len2) {
            i--; j--;k--;
            temp = (short)((data1[i] & BYTE_MASK) + (data2[j] & BYTE_MASK) + carry);
            result[k] = (byte)temp;
            carry = (byte) (temp >>> 8);
        }

        // Add remainder of the longer number
        while(i>len1) {
            i--;k--;
            temp = (short)((data1[i] & BYTE_MASK) + carry);
            result[k] = (byte)temp;
            carry = (byte) (temp >>> 8);
        }
        while(j>len2) {
            j--;k--;
            temp = (short)((data2[j] & BYTE_MASK) + carry);
            result[k] = (byte)temp;
            carry = (byte)(temp >>> 8);
        }
        
        if (carry > 0) { // Result must grow in length! 
        	if (k==0) { // Ops! It's not possible!
        		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	} else { // k>0, Ok, there is enough space!
        		result[--k] = carry;
        	} 
        }

        res.len = (short)(result.length - k);
        res.off = k;
        res.normalize(); //added
	}
	
	/**
	 * Calculates {@code res := res + op2}.
	 * Only {@code res} is modified; {@code op} remains unaltered.
	 * @param res first operand and where to store the result.
	 * @param op second operand.
	 * @throws {@code ISO7816.SW_WRONG_LENGTH} when the internal byte[] of 'res' has
	 * insufficient space for storing the result.
	 */
	public static void selfAdd(MutableBigInteger res, MutableBigInteger op)  {
		len1 = res.off;
		len2 = op.off;
		i = (short)(len1 + res.len);
        j = (short)(len2 + op.len);
        result = res.data;
        data1 = op.data;
        carry = 0;
        
        // Add common parts of both numbers
        while(i>len1 && j>len2) {
            i--; j--;
            temp = (short)((result[i] & BYTE_MASK) + (data1[j] & BYTE_MASK) + carry);
            result[i] = (byte)temp;
            carry = (byte) (temp >>> 8);
        }

        // Add remainder of the longer number
        while(i>len1 && carry > 0) {
            i--;
            temp = (short)((result[i] & BYTE_MASK) + carry);
            result[i] = (byte)temp;
            carry = (byte) (temp >>> 8); 
        }
        while(j>len2) {
            i--;j--;
            temp = (short)((data1[j] & BYTE_MASK) + carry);
            result[i] = (byte)temp;
            carry = (byte)(temp >>> 8);
        }
        
        if (carry > 0){ // Result must grow in length!
        	if (i == 0) { // Ops! It's not possible!
        		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	} else { //i>0; ok, there is enough space!
        		result[--i] = (byte)carry;
        	}
        }

        res.len = (short)(result.length - i);
        res.off = i;
        res.normalize(); //added
	}
	
	/* **************************** END add  **********************************/
	
	/* **************************** subtract **********************************/
	
	/**
	 * Calculates {@code res := op1 - op2 mod (mod)}. Both operands {@code op1} 
	 * and {@code op2} are considered positive numbers, as well as 
	 * {@code op1 &lt; (mod)} and {@code op2 &lt; (mod)}. This method compares
	 * both operands and proceed as follows:
	 * <ol>
	 *   <li><strong>{@code op1 &gt; op2}:</strong> As the result of the
	 *   operation lies in the {@code (mod)} domain (i.e., 
	 *   {@code 0 &le; op1 - op2 &le; (mod)}), nothing else is required.</li>
	 *   <li><strong>{@code op1 == op2}:</strong> Zero is returned.</li>
	 *   <li><strong>{@code op1 &lt; op2}:</strong> As the result is negative,
	 *   and the subtract operation always must return a positive result, this
	 *   method uses a workaround to use always positive numbers. That is,
	 *   {@code op1 &lt; op2 AND op1 - op2 mod (mod) &lt;==&gt;
	 *   (mod) - (op2 - op1) mod (mod)}. Actually, {@code (mod) - (op2 - op1)}
	 *   and its intermediate results always lie within the {@code (mod)} domain.
	 *   </li> 
	 * </ol>
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand, greater than {@code op2}.
	 * @param op2 second operand, smaller than {@code op1}.
	 * @param mod modulus.
	 */
	public static void modSubtract(MutableBigInteger res, MutableBigInteger op1, MutableBigInteger op2, MutableBigInteger mod) {
		temp = op1.compare(op2);
		if (temp>0) {
			subtract(res, op1, op2);
		} else if (temp == 0) {
			res.clear();
		} else { //op1 < op2: op1 - op2 mod (mod) <=> (mod) - (op2 - op1) mod (mod)
			subtract(bnaux3, op2, op1);
			subtract(res, mod, bnaux3);
		}
		res.normalize(); //added
	}
	
	/**
	 * Calculates {@code res := op1 - op2}. Both operands are considered positive numbers,
	 * and {@code op1} greater than {@code op2}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand, greater than {@code op2}.
	 * @param op2 second operand, smaller than {@code op1}.
	 */
	public static void subtract(MutableBigInteger res, MutableBigInteger op1, MutableBigInteger op2) {
        len1 = op1.off;
        len2 = op2.off;
		i = (short)(op1.len + len1); //longer length
		j = (short)(op2.len + len2); //shorter length
        result = res.data;
		k = (short)(result.length);
        data1 = op1.data;
        data2 = op2.data;
        res.len = op1.len;
        res.off = (short)(result.length-op1.len);
        temp = 0;

        // Subtract common parts of both numbers
        while(j > len2) {
            temp = (short)((data1[--i] & BYTE_MASK) - 
                         ((data2[--j] & BYTE_MASK) +
                         ((temp >> 8) & 1)));
            result[--k] = (byte)temp;
        }
        
        // Subtract remainder of longer number while borrow propagates
        borrow = (temp >> 8 != 0);
        while (i >= len1 && borrow)
            borrow = ((result[--k] = (byte)(data1[--i] - 1)) == -1);

        // Copy remainder of longer number
        while (i > len1)
            result[--k] = data1[--i];
        
        // Update offset within the big number
        res.normalize();
	}
	
	/**
	 * Calculates {@code res := res - op2}. Both operands are considered positive numbers,
	 * and {@code res} greater than {@code op}.
	 * Only {@code res} is modified; {@code op} remains unaltered.
	 * @param res first operand and where the operation result will be stored.
	 * @param op2 second operand, smaller than {@code res}.
	 */
	public static void selfSubtract(MutableBigInteger res, MutableBigInteger op) {
		i = (short)(res.len + res.off); //longer length
		j = (short)(op.len + op.off); //shorter length 
        result = res.data;
        data1 = res.data;
        data2 = op.data;
        len1 = res.off;
        temp = 0;

        // Subtract common parts of both numbers
        while(j > len1) {
            temp = (short)((data1[--i] & BYTE_MASK) - 
                         ((data2[--j] & BYTE_MASK) +
                         ((temp >> 8) & 1)));
            result[i] = (byte)temp;
        }
        
        // Subtract remainder of longer number while borrow propagates
        borrow = (temp >> 8 != 0);
        while (i > 0 && borrow)
            borrow = ((result[--i] = (byte)(data1[i] - 1)) == -1);

        // Copy remainder of longer number
        while (i > len1)
            result[--i] = data1[i];
        
        // Update offset within the big number
        res.normalize();
	}
	
	/**
	 * Calculates {@code res := res - op}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res source value where the operation result will be stored.
	 * @param op second operand.
	 */
	public static void selfSubtractByte(MutableBigInteger res, byte op) { 
        result = res.data;
        len1 = res.off;
        i = (short)(res.len+res.off);

        // Subtract the given byte value
        temp = (short)((result[--i] & BYTE_MASK) - (op & BYTE_MASK));
        result[i] = (byte)temp;
        
        // Subtract remainder of longer number while borrow propagates
        borrow = (temp >> 8 != 0);
        while (i > len1 && borrow)
            borrow = ((result[--i] -= 1) == -1);
       
        // Update offset within the big number
        res.normalize();
	}
	
	/* ************************ END subtract **********************************/
	
	/* ************************ multiplication ********************************/
	
	/**
	 * Calculates {@code res := op1 * op2}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand.
	 * @param op2 second operand.
	 * @throws {@code ISO7816.SW_WRONG_LENGTH} when the big number {@code res} has 
	 * insufficient space for storing the operation result.
	 */
	public static void multiply(MutableBigInteger res, MutableBigInteger op1, MutableBigInteger op2) {
		len1 = op1.off;
        len2 = op2.off;
        len3 = (short)(op1.len + op2.len);

        if (res.data.length < len3)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // The first iteration is hoisted out of the loop to avoid extra add
        result = res.data;
        data1 = op1.data;
        data2 = op2.data;
        res.off = (short)(result.length - len3);
        res.len = len3;
        carry = 0;
        
        //i index for data1, j index for data2, k index for result
        temp2 = (short)(data2[(short)(op2.len+len2-1)] & BYTE_MASK);
        for (i=(short)(op1.len+len1-1), k=(short)(result.length-1); i >= len1; i--, k--) {
            temp = (short)((data1[i] & BYTE_MASK) * temp2 + carry);
            result[k] = (byte)(temp & BYTE_MASK);
            carry = (byte)(temp >>> 8);
        }
        result[k] = (byte)carry;

        // Perform the multiplication word by word
        for (j = (short)(op2.len + len2 - 2); j >= len2; j--) {
            carry = 0;
            temp2 = (short)(op2.len+len2 - j);
            for (i=(short)(op1.len+len1-1), k=(short)(result.length-temp2); i >= len1; i--, k--) {
                temp = (short)((data1[i] & BYTE_MASK) *
                               (data2[j] & BYTE_MASK) +
                               (result[k] & BYTE_MASK) + carry);
                result[k] = (byte)(temp & BYTE_MASK);
                carry = (byte)(temp >>> 8);
            }
            result[k] = (byte)carry;
        }

        // Remove leading zeros from product
        res.normalize();
	}
	
	/**
	 * Calculates {@code res := op1 * op2}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand.
	 * @param op2 second operand.
	 * @throws {@code ISO7816.SW_WRONG_LENGTH} when the big number {@code res} has 
	 * insufficient space for storing the operation result.
	 */
	public static void multiplyByte(MutableBigInteger res, MutableBigInteger op1, byte op2) {
        len1 = op1.len;
        len2 = (short)(len1 + 1);
        len3 = (short)res.data.length;

        if (len3 < len2)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        res.off = (short)(len3 - len2);
        res.len = len2;

        //this multiplication will have only 1 iteration
        carry = 0;
        result = res.data;
        data1 = op1.data;
        temp2 = (short)(op2 & BYTE_MASK);
        len3 = op1.off;
        for (j=(short)(len1-1), k=(short)(len2-1); j >= 0; j--, k--) {
            temp = (short)((data1[(short)(j+len3)] & BYTE_MASK) * temp2 + carry);
            result[(short)(k+res.off)] = (byte)(temp & BYTE_MASK);
            carry = (byte)(temp >>> 8);
        }
        result[(short)(k+res.off)] = (byte)carry;
 
        // Remove leading zeros from product
        res.normalize();
	}
	
	/**
	 * Calculates {@code res := (op1 * op2) mod mod}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand.
	 * @param op2 second operand.
	 * @param mod modulus magnitude.
	 */
	/*public static void modMulMontgomery(MutableBigInteger res, MutableBigInteger op1, MutableBigInteger op2, MutableBigInteger mod) {
		qM = mod.data[(short)(mod.data.length-1)];
		len4 = (short)(res.data.length-1);
		off = op2.off;
		res.clear();
		for (i=(short)(op2.len + op2.off - 1); i>=off; i--) {
			Math.multiplyByte(bnaux, op1, op2.data[i]);
			Math.selfAdd(res, bnaux);
			if (qM == (byte)1) {
				val1 = (byte)-res.data[len4];
			} else if (qM == (byte)-1) {
				val1 = res.data[len4];
			}
			Math.multiplyByte(bnaux, mod, val1);
			Math.selfAdd(res, bnaux);
			Math.selfShiftRight(res, (short)8);
		}
		if (res.compare(mod)==1) {
			Math.selfSubtract(res, mod);
		}
	}*/
	
	
	/**
	 * Calculates {@code res := (op1 * op2) mod mod}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op1 first operand.
	 * @param op2 second operand.
	 * @param mod modulus magnitude.
	 */
	public static void modMul(MutableBigInteger res, MutableBigInteger op1, MutableBigInteger op2, MutableBigInteger mod) {
		// Using the binomial theorem.
		// (op1 + op2)**2 - (op1 - op2)**2 = 4 * op1 * op2 mod (mod)
		// 0. resets to zero the result
		res.clear();
		// 1. (op1 + op2) mod (mod)
		modAdd(res, op1, op2, mod);
		// 2. ((op1 + op2) mod (mod))**2 mod (mod)
		//res.fixSizeAndClear(mod.len); //this task is done into modPow.
		modPow(bnaux, res, TWO, mod);
		// 3. (op1 - op2) mod (mod)
		modSubtract(res, op1, op2, mod);
		// 4. ((op1 - op2) mod (mod))**2 mod (mod)
		//res.fixSizeAndClear(mod.len); //this task is done into modPow.
		modPow(bnaux2, res, TWO, mod);
		// 5. ({step 2} - {step 4})/4 mod (mod)
		// Note: bnaux and bnaux2 lie within [0..(mod)-1]
		// KEY ISSUE: divide by 4 BEFORE applying modulus
		/*if (bnaux.compare(bnaux2)>0) {
			subtract(res, bnaux, bnaux2);
			selfModShiftRight(res, (short)2, mod);
		} else {
			subtract(res, bnaux2, bnaux);
			bnaux.copyValue(res);
			selfModShiftRight(bnaux, (short)2, mod);
			subtract(res, mod, bnaux);
		}*/
		
		
		modSubtract(res,bnaux,bnaux2,mod);
		
		//a = p+1/2 <- 2a = kp +1 , a=1/2
		add(bnaux2, mod, ONE);
		selfShiftRight(bnaux2, (short)1);
		
		for (short i=0; i<2;i++){
			if (res.isOdd()){
				//when (op1 + op2)**2 - (op1 - op2)**2 is odd, we compute
				//(op1 + op2)**2 - (op1 - op2)**2 +1 = 4 * op1 * op2 +1/4  or
				//(op1 + op2)**2 - (op1)**2 - (op2)**2 = 2 * op1 * op2) +1/2
				add(bnaux, res, ONE); //lef side +1
				selfShiftRight(bnaux, (short)1); //division like a even number
				modSubtract(res, bnaux, bnaux2, mod); //lef side -1 (-a)
				
			}else{
				//even
				selfModShiftRight(res, (short)1, mod);
			}
		}
		
		op1.normalize(); //added
		op2.normalize(); //added
		bnaux.normalize(); //added
		bnaux2.normalize(); //added
		res.normalize(); //added
		//RESULT: res = op1 * op2 mod (mod)
		
	}
	
	
	/* ********************** END multiplication ******************************/

	/* ***********************  shiftRight, shiftLeft *************************/
	/**
     * Left shift this MutableBigInteger n bits. 
     * @param res big number where to store de result.
     * @param op big number to shift n bits (remains unaltered).
     * @param n number of bits to shift.
	 * @throws {@code ISO7816.SW_WRONG_LENGTH} when big number 'res' has insufficient
	 * length to fit the memory space requirements of the operation.
     */
    public static void shiftLeft(MutableBigInteger res, MutableBigInteger op, short n) {
        /*
         * If there is enough storage space in this MutableBigInteger already
         * the available space will be used. Space to the right of the used
         * bytes in the 'data' array is faster to utilize, so the extra space
         * will be taken from the right if possible.
         */
        if (op.len == 0) {
        	res.clear();
           	return;
    	}
        result = res.data;
        len1 = (short)(n >>> 3); //number of bytes (positions) to shift
        val1 = (byte)(n&0x07); //number of bits to shift
        val2 = MutableBigInteger.bitLength(op.data[op.off]);
        
        // If shift can be done without moving words, do so
        if (n <= (8-val2)) {
            primitiveLeftShift(res, op, val1);
            return;
        }

        len3 = (short)(op.len + len1 + 1);
        if (val1 <= (8-val2))
            len3--;
        /* The backend will always have the necessary size. 
         * Throws exception.
         */
        if (result.length < len3) 
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        len1 = op.len;
        len2 = (short)(result.length - len3);
        res.off = len2;
        res.len = len3;
        len3 = op.off;
        /* copy values */
        for (i = 0; i < len1; i++)
        	result[(short)(len2+i)] = op.data[(short)(len3+i)];
        
        len1 = (short)(res.len - op.len);
        len2 = (short)(res.off + op.len);
        /* ensure reseted positions */
        for (i = 0; i < len1; i++)
        	result[(short)(len2+i)] = 0;
        
        if (val1 == 0)
            return;
        if (val1 <= (8-val2))
            selfPrimitiveLeftShift(res, val1);
        else
            selfPrimitiveRightShift(res, (byte)(8 - val1));
        
        res.normalize(); //added
    }
    
	/**
	 * Calculates {@code res := op >> shift}.
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param op value to be shifted.
	 * @param shift number of bits to shift. 
	 */
	public static void shiftRight(MutableBigInteger res, MutableBigInteger op, short shift) {
		if (op.len == 0) {
			res.clear();
			return;
		}
        res.len = (short)(op.len - (shift >>> 3)); //current length - number of bytes to shift
        if (res.len <= 0) { //shift all bytes, result zero
        	res.clear();
        	return;
        }
        val1 = (byte)(shift & 0x07); //number of bits to shift
        if (val1 == 0)
            return;
        val2 = MutableBigInteger.bitLength(op.data[op.off]);
        if (val1 >= val2) {
            primitiveLeftShift(res, op, (byte)(8 - val1));
            res.len--;
        } else {
            primitiveRightShift(res, op, val1);
        }
        
        res.normalize(); //added
	}
	
    /**
     * Right shift the 'op' MutableBigInteger n bits, where n is
     * less than 8, storing the result in 'res'.
     * Assumes that len > 0, n > 0 for speed
     * @param res big number where to store the result.
     * @param op big number to shift 'n' bits (remains unaltered).
     * @param n number of bits to shift.
     */
    protected static final void primitiveRightShift(MutableBigInteger res, MutableBigInteger op, byte n) {
        val1 = (byte)(8 - n);
        for (i=(short)(op.off+op.len-1), j=(short)(res.data.length-1), val2=op.data[i]; i>op.off; i--, j--) {
            val3 = val2;
            val2 = (byte)op.data[(short)(i-1)];
            res.data[j] = (byte)((val2 << val1) | ((val3 & BYTE_MASK) >>> n));
        }
        res.data[j]= (byte)((op.data[op.off] & BYTE_MASK) >>> n);
        res.off = (short)j;
        
        res.normalize(); //added
    }

    /**
     * Left shift the op MutableBigInteger n bits, where n is
     * less than 8, storing the result in 'res'.
     * Assumes that len > 0, n > 0 for speed
     * @param res big number where to store the result.
     * @param op big number to shift 'n' bits (remains unaltered).
     * @param n number of bits to shift.
     */
    protected static final void primitiveLeftShift(MutableBigInteger res, MutableBigInteger op, byte n) {
        val1 = (byte)(8 - n);
        res.off = (short)(res.len-res.data.length);
        for (i=op.off, j=res.off, val2=op.data[i], len1=(short)(op.off+op.len-1); i<len1; i++, j++) {
            val3 = val2;
            val2 = op.data[(short)(i+1)];
            res.data[j] = (byte)((val3 << n) | (val2 & BYTE_MASK >>> val1));
        }
        res.data[(short)(res.off+res.len-1)] = (byte) (op.data[(short)(op.off+op.len-1)] << n);
        
        res.normalize(); //added
    }
	
    /* ******************* END shiftRight *************************************/
    
    /* ***************** selfShiftRight, selfShiftRight ***********************/
    
    public static void selfModShiftRight(MutableBigInteger res, short shift, MutableBigInteger mod) {
    	for (; shift>0; shift--) { 
    		if (res.isOdd()) {
    			selfAdd(res, mod);
    		}
			selfShiftRight(res, (short)1);
    	}
    	
    	res.normalize(); //added
    }
    
	/**
	 * Calculates {@code res := res >> shift}.
	 * The {@code res} is updated shifting 'shift' bits.
	 * @param res initial operand and where the operation result will be stored.
	 * @param shift number of bits to shift. 
	 */
	public static void selfShiftRight(MutableBigInteger res, short shift) {
		if (res.len == 0)
            return;
        res.len -= (short)(shift >>> 3); //current length - number of bytes to shift
        if (res.len <= 0) { //shift all bytes, result zero
        	res.clear();
        	return;
        }
        val1 = (byte)(shift & 0x07); //number of bits to shift
        if (val1 == 0)
            return;
        val2 = MutableBigInteger.bitLength(res.data[res.off]);
        if (val1 >= val2) {
            selfPrimitiveLeftShift(res, (byte)(8 - val1));
            res.len--;
        } else {
            selfPrimitiveRightShift(res, val1);
        }
        res.normalize(); //added
	}
	
	/**
     * Left shift the 'res' MutableBigInteger n bits to the left. 
     * @param res big number where to store de result.
     * @param n number of bits to shift.
     * @throws {@code ISO7816.SW_WRONG_LENGTH} when the {@code res} big number
     * has insufficient space to fit the resulting big number.
     */
    public static void selfShiftLeft(MutableBigInteger res, short n) {
        /*
         * If there is enough storage space in this MutableBigInteger already
         * the available space will be used. Space to the right of the used
         * bytes in the 'data' array is faster to utilize, so the extra space
         * will be taken from the right if possible.
         */
        if (res.len == 0)
           return;
        result = res.data;
        len1 = (short)(n >>> 3); //number of bytes (positions) to shift
        val1 = (byte)(n&0x07); //number of bits to shift
        val2 = MutableBigInteger.bitLength(result[res.off]);
        
        
        // If shift can be done without moving words, do so
        if (n <= (8-val2)) {
            selfPrimitiveLeftShift(res, val1);
            return;
        }

        len3 = (short)(res.len + len1 + 1);
        if (val1 <= (8-val2))
            len3--;
        /* The backend will always have the necessary size. 
         * Throws exception.
         */
        if (res.data.length < len3) 
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if ((short)(res.data.length - res.off) >= len3) {
            // Use space on right
        	len1 = (short)(res.off + res.len);
        	len2 = (short)(len3-res.len);
            for(i=0; i<len2; i++)
                result[(short)(len1+i)] = 0;
        } else {
            // Must use space on left
        	len1 = res.len;
        	len2 = res.off;
            for (i=0; i<len1; i++)
                result[i] = result[(short)(len2+i)];
            for (i=len1; i<len3; i++)
                result[i] = 0;
            res.off = 0;
        }
        res.len = len3;
        if (val1 == 0)
            return;
        if (val1 <= (8-val2))
            selfPrimitiveLeftShift(res, val1);
        else
            selfPrimitiveRightShift(res, (byte)(8 - val1));
        
        res.normalize(); //added
    }
	
	/**
     * Right shift the 'res' MutableBigInteger n bits, where n is
     * less than 8.
     * Assumes that len > 0, n > 0 for speed
     * @param res big number to shift 'n' bits.
     * @param n number of bits to shift.
     */
    protected static final void selfPrimitiveRightShift(MutableBigInteger res, byte n) {
        val1 = (byte)(8 - n);
        result = res.data;
        for (i=(short)(res.off+res.len-1), val2=result[i]; i>res.off; i--) {
            val3 = val2;
            val2 = result[(short)(i-1)];
            result[i] = (byte)((val2 << val1) | ((val3 & BYTE_MASK) >> n));
        }
        result[res.off]= (byte)((result[res.off] & BYTE_MASK) >>> n);
        
        res.normalize(); //added
    }

    /**
     * Left shift the 'res' MutableBigInteger n bits, where n is
     * less than 8.
     * Assumes that len > 0, n > 0 for speed
     * @param res big number to shift 'n' bits. 
     * @param n number of bits to shift.
     */
    protected static final void selfPrimitiveLeftShift(MutableBigInteger res, byte n) {
        val1 = (byte)(8 - n);
        result = res.data;
        for (i=res.off, val2=result[i], len1=(short)(res.off+res.len-1); i<len1; i++) {
            val3 = val2;
            val2 = result[(short)(i+1)];
            result[i] = (byte)((val3 << n) | ((val2 & BYTE_MASK) >>> val1));
        }
        result[(short)(res.off+res.len-1)] <<= n;
        
        res.normalize(); //added
    }
    
    /* ****************** END selfShiftRight ***********************************/
	
	/**
	 * Calculates {@code res := base ** exp mod mod}. 
	 * Only {@code res} is modified; the rest of parameters remain unaltered.
	 * @param res where the operation result will be stored.
	 * @param base base magnitude for the exponentiation.
	 * @param exp exponent magnitude for the exponentiation.
	 * @param mod modulus magnitude.
	 * @throws {@code ISO7816.SW_WRONG_LENGTH} when the resulting big number has 
	 * insufficient memory space to fit the operation requirements.
	 */  
	public static void modPow(MutableBigInteger res, MutableBigInteger base, MutableBigInteger exp, MutableBigInteger mod) {
		
		// 0. initialize key with current values
		key.clearKey();
		exp.fixSizeAndClear(Configuration.currentSizeInBytes);
		mod.fixSizeAndClear(Configuration.currentSizeInBytes);
		try {
			key.setExponent(exp.data, exp.off, exp.len);
		} catch (NullPointerException e) {
			ISOException.throwIt((short)0x6600);
		} catch (CryptoException e) {
			Debug.showCase(e, (short)0x6600);
		} catch (Exception e) {
			ISOException.throwIt((short)0x6602);
		}
		
		try {
			key.setModulus(mod.data, mod.off, mod.len);
		} catch (NullPointerException e) {
			ISOException.throwIt((short)0x6700);
		} catch (CryptoException e) {
			Debug.showCase(e, (short)0x6700);
		} catch (Exception e) {
			ISOException.throwIt((short)0x6702);
		}
		
		// 1. must initialize cipher with new key
		rsa.init(key, Cipher.MODE_ENCRYPT);
//		2. calculate res := base ** exp mod mod
		res.off = (short)(res.data.length - mod.len);

		base.fixSizeAndClear(mod.len); //base must have the same size than the modulus.

		
		try{
			res.len = rsa.doFinal(base.data, base.off, base.len, res.data, res.off);
			
		} catch (NullPointerException e) {
			ISOException.throwIt((short)0x6800);
		} catch (CryptoException e) {
			Debug.showCase(e, (short)0x6800);
		} catch (ArrayIndexOutOfBoundsException e) {
			ISOException.throwIt((short)0x6803);
//		} catch (Exception e) {
//			ISOException.throwIt((short)0x6802);
		}
		exp.normalize();
		base.normalize();
		mod.normalize();
		res.normalize();

	}
	
	public static void uninstall() {
		key = null;
		rsa = null;
		ONE = null;
		bnaux = null;
		data1 = null;
		data2 = null;
		result = null;
	}
	
}
