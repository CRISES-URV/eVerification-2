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
import javacard.framework.JCSystem;
import javacard.framework.Util;

/** 
 * Arbitrary-precision integers. A class used to represent multiprecision 
 * integers that makes efficient use of allocated space by allowing a number to 
 * occupy only part of an array. The current implementation does not
 * reallocate the internal representation of the big number.
 * Therefore, whenever an operation result does not fit in a
 * MutableBigInteger, the operation will throw an 
 * {@link cat.urv.crises.javacard.math.InsufficientPrecisionException}. 
 * A mutable number allows calculations to occur on the 
 * same number without having to create a new number for every step of the 
 * calculation. 
 * <p>
 * All operations behave as if the big numbers were represented in two's-complement
 * notation (like Java's primitive integer types). MutableBigIngeger provides
 * basic functionality and aims to behave as a big number container. All complex
 * operations are performed through the use of {@link cat.urv.crises.javacard.math.Math}.
 * <p>
 * This implementation is inspired on the java.math.BigInteger implementation,
 * but updated to use the limited data structure types in JavaCards.
 * 
 * @author Roger Jardí Cedó & Jordi Pujol Ahulló 
 */

public class MutableBigInteger {
    /**
     * Holds the magnitude of this MutableBigInteger in big endian order.
     * The magnitude may start at an offset into the value array, and it may
     * end before the length of the value array.
     */
    byte[] data;
    /**
     * The number of bytes of the value array that are currently used
     * to hold the magnitude of this MutableBigInteger. The magnitude starts
     * at an offset and off + len may be less than value.length.
     */
    short len;
    /**
     * The offset into the value array where the magnitude of this
     * MutableBigInteger begins.
     */ 
    short off = 0;
    /**
     * Number of precision bits that can contain this big number. That is,
     * this big number can represent values in the range {@code [0 .. 2**size)}.
     * This size is set in the constructor to take the {@code bitPrecision}'s 
     * value; otherwise, it takes the capacity of the internal {@code byte[]} (i.e., 
     * {@code size = data.length *8}).
     */
    //short size;
    /**
     * Flag denoting whether the byte[] backend must be stored in EEPROM (when false),
     * or in RAM (when true, the default).
     */
    boolean inRAM = true;
    
    
    /** Mask for limiting byte values. */
    final static short BYTE_MASK = 0xFF; 
    /** Number of extra bytes to add to the byte[] backend for operational purposes. */
    static short LENGTH = -1;
    
    //attributes for use once at a time
    /** Index for loops. */
    short i, j;
    /** Temporal values. */
    byte val1, val2;
    /** Length indicator.*/
    short len1, len2;
    /** Copy of an array. */
    byte[] result;
    

    public static void init() {
    	if (LENGTH == -1) {
    		LENGTH = (short)(Configuration.maxSizeInBytes + 8);
    	}
    }
    
    // Constructors
    
    /**
     * Construct a new MutableBigInteger in RAM with a magnitude such that it is
     * able to represent a number of 
     * {@link cat.urv.crises.smartcard.elgamal.Configuration#maxSizeInBits} bits. 
     */
    public MutableBigInteger() {
    	// 1. instantiate array
        data = JCSystem.makeTransientByteArray(LENGTH, JCSystem.CLEAR_ON_DESELECT);
        // 2. clear the big number to zero
        len = 0;
        //off = (short)(data.length - 1);
        off = LENGTH;
        for (i=0; i < LENGTH; i++)
        	data[0] = 0;
    }
    
    /**
     * Construct a new MutableBigInteger in RAM (if {@code inRAM==true}),
     * or in EEPROM (if {@code inRAM==false}), with a magnitude such that it is
     * able to represent a number of 
     * {@link cat.urv.crises.smartcard.elgamal.Configuration#maxSizeInBits} bits. 
     */
    public MutableBigInteger(boolean inRAM) {
    	// 1. instantiate array
    	this.inRAM = inRAM;
    	if (inRAM)
    		data = JCSystem.makeTransientByteArray(LENGTH, JCSystem.CLEAR_ON_DESELECT);
    	else
    		data = new byte[LENGTH];
        // 2. clear the big number to zero
        len = 0;
        //off = (short)(data.length - 1);
        off = LENGTH;
        for (i=0; i < LENGTH; i++)
        	data[0] = 0;
    }

    /**
     * Construct a new MutableBigInteger in RAM with the specified value array
     * up to the length of the array supplied.
     */
    public MutableBigInteger(byte[] val) {
    	data = JCSystem.makeTransientByteArray(LENGTH, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopy(val, (short)0, data, (short)(LENGTH - val.length), (short)val.length);
        off = this.findFirstNonZero();
        len = (short)(LENGTH - off);
    }
    
    /**
     * Construct a new MutableBigInteger in RAM (if {@code inRAM==true}),
     * or in EEPROM (if {@code inRAM==false}), with the specified value array
     * up to the length of the array supplied.
     */
    public MutableBigInteger(byte[] val, boolean inRAM) {
    	this.inRAM = inRAM; 
    	if (inRAM)
    		data = JCSystem.makeTransientByteArray(LENGTH, JCSystem.CLEAR_ON_DESELECT);
    	else
    		data = new byte[LENGTH];
        Util.arrayCopy(val, (short)0, data, (short)(LENGTH - val.length), (short)val.length);
        off = this.findFirstNonZero();
        len = (short)(LENGTH - off);
    }
    
    /**
     * Construct a new MutableBigInteger in RAM with a magnitude specified by
     * the byte[] val.
     */
    /*public MutableBigInteger(byte[] val, short bitPrecision) {
    	// 0. calculate byte[] length
    	len1 = (short)(bitPrecision/8);
    	if (bitPrecision % 8 > 0)
    		len1++;
    	len1 += EXTRA_LENGTH;
    	// 1. instantiate array
    	data = JCSystem.makeTransientByteArray(len1, JCSystem.CLEAR_ON_DESELECT);
        // 2. set the big number value to val
    	Util.arrayCopy(val, (short)0, data, (short)(EXTRA_LENGTH -1), (short)val.length);
    	off = this.findFirstNonZero();
    	len = (short)(data.length - off - 1);
    }*/
    
    /**
     * Construct a new MutableBigInteger in RAM with a magnitude specified by
     * the {@code byte[] val}. Use this constructor iff {@code val} contains
     * all useful values (do not contain trailing 'empty' positions, as may
     * happen in MutableBigInteger). 
     */
    /*public MutableBigInteger(byte[] val, short bitPrecision, boolean inRAM) {
    	// 0. calculate byte[] length
    	len1 = (short)(bitPrecision>>3);
    	if ((bitPrecision & 0x111) > 0)
    		len1++;
    	len1 += EXTRA_LENGTH;
    	// 1. instantiate array
    	this.inRAM = inRAM; 
    	if (inRAM)
    		data = JCSystem.makeTransientByteArray(len1, JCSystem.CLEAR_ON_DESELECT);
    	else
    		data = new byte[len1];
        // 2. set the big number value to val 
    	Util.arrayCopy(val, (short)0, data, (short)(EXTRA_LENGTH -1), (short)val.length);
    	off = this.findFirstNonZero();
    	len = (short)(data.length - off - 1);
        size = bitPrecision;
    }*/
    
    /**
     * Construct a new MutableBigInteger with a magnitude equal to the
     * specified MutableBigInteger, stored in the same way than {@code val} (i.e.,
     * this big number is stored in RAM if {@code val} does, or in EEPROM otherwise).
     */
    public MutableBigInteger(MutableBigInteger val) {
    	inRAM = val.inRAM;
        len = val.len;
        off = val.off;
        if (inRAM)
        	data = JCSystem.makeTransientByteArray(LENGTH, JCSystem.CLEAR_ON_DESELECT);
        else
        	data = new byte[LENGTH];
        Util.arrayCopy(val.data, off, data, off, len);
    }
    
    /**
     * Construct a new MutableBigInteger with a magnitude equal to the
     * specified MutableBigInteger. This big number is stored in RAM if 
     * {@code inRAM==true}, or in EEPROM otherwise.
     */
    public MutableBigInteger(MutableBigInteger val, boolean inRAM) {
    	this.inRAM = inRAM;
        len = val.len;
        off = val.off;
        if (inRAM)
        	data = JCSystem.makeTransientByteArray(LENGTH, JCSystem.CLEAR_ON_DESELECT);
        else
        	data = new byte[LENGTH];
        Util.arrayCopy(val.data, off, data, off, len);
    }
    
    /**
     * Clear out a MutableBigInteger for reuse (its internal value becomes 0).
     */
    public void clear() {
    	//len1=(short)data.length;
        //off = (short)(len1 - 1);
    	off = LENGTH;
        len = 0;
        for (i=0; i < LENGTH; i++)
            data[i] = 0;
    }

    /**
     * Set a MutableBigInteger to zero, removing its offset.
     * The internal content is unaltered.
     */
    protected void reset() {
        off = LENGTH;
        len = 0;
    }


    /**
     * Ensure that the MutableBigInteger is in normal form, specifically
     * making sure that there are no leading zeros, and that if the
     * magnitude is zero, then len is zero.
     */
    protected final void normalize() {
        if (len == 0) {
            off = LENGTH;
            //ISOException.throwIt((short)0x01);
            return;
        }

        i = off;
        if (data[i] != 0){
        	//ISOException.throwIt((short)0x02);
            return;
        }
        
        len1 = (short)(i+len);
        do {
            i++;
        } while(i < len1 && data[i]==0);

        len1 = (short)(i - off);
        len -= len1;
        off = (len==0 ?  (short)data.length : (short)(off+len1));
        //ISOException.throwIt((short)0x03);
    }
    
    /**
     * Fix the internal size to {@code size} bytes, setting a zero to the MSBs
     * when the current representation is lesser than {@code size} bytes. This 
     * operation is needed when the smart card co-processor is used to perform
     * specific operations (such as modpow). 
     * @param size Number of bytes to fit.
     */
    protected final void fixSizeAndClear(short size) {
    	len1 = (short)(off - (size - len)); //size >= len!!
    	for (i=len1; i<off; i++) {
    		data[i]=0;
    	}
    	off = len1;
    	len = size;
    }

    /**
     * Sets this MutableBigInteger's value array as a copy of the specified
     * big number. The {@code len} is set to the length of the new array.
     * @param src copies the {@code src}'s internal content to this big number.
     * @throws {@code ISO7816.SW_WRONG_LENGTH} when this big number has an internal byte[]
     * length less than the 'src' one.
     */
    public void copyValue(MutableBigInteger src) {
        len1 = src.len;
        
        if (data.length < len1)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            //data = new byte[len1];
        off = (short)(data.length - len1);
        len = len1;
        Util.arrayCopy(src.data, src.off, data, off, len1);
    } 

    /**
     * Sets this MutableBigInteger's value array as a copy of the specified
     * array. The {@code len} is set to the length of the specified array.
     * @throws {@code ISO7816.SW_WRONG_LENGTH} when this big number has an internal byte[]
     * length less than the 'val' one.
     */
    public void copyValue(byte[] val) {
        len1 = (short) (data.length);
        len2 = (short)(val.length);
        if (len1 < len2)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            //data = new byte[len1];
        off = (short)(len1 - len2);
        len = len2;
        Util.arrayCopy(val, (short)0, data, off, len2);
    }
    
    /**
     * Sets this MutableBigInteger's value array as a copy of the specified
     * array, from the specific {@code offset} (included) to {@code offset+length} (excluded). 
     * @throws {@code ISO7816.SW_WRONG_LENGTH} when this big number has an internal byte[]
     * length less than the 'val' one.
     */
    public void copyValue(byte[] val, short offset, short length) {
        len1 = (short) (data.length);
        if (len1 < length)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        off = (short)(len1 - length);
        len = length;
        Util.arrayCopy(val, offset, data, off, length);
    }
    
    /**
     * This method allows append to the MSB part the data contained in {@code val}.
     * Before appending the first portion of a big number, this instance must
     * be {@link #clear()}ed.
     * @param val array from where to copy the values.
     * @param offset index from where to start copying.
     * @param length number of bytes to copy.
     */
    public void append(byte[] val, short offset, short length) {
    	if (length == 0) return;
    	if (off <  length)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	off -= length;
    	len += length;
    	Util.arrayCopy(val, offset, data, off, length);
    }
    
    /**
     * Copies the internal representation of this big number to the given
     * {@code byte[]}, starting at the offset {@code offset}.
     * When copying, this method ensures that all necessary left-hand zeros
     * are inserted when the length of the internal representation is
     * lesser than {@link cat.urv.crises.smartcard.elgamal.Configuration#currentSizeInBytes}.
     * @param val buffer where to copy the internal representation of this big number.
     * @param offset offset from within {@code} where to start copying the internal
     * representation.
     */
    public short copyTo(byte[] val, short offset) {
    	// 1. ensure the magnitude at 'val' by preceding zeros when necessary
    	len1 = (short)(Configuration.currentSizeInBytes - len);
    	len2 = (short)(offset + len1);
    	for (i=offset; i < len2; i++)
    		val[i] = 0;
    	// 2. copy the actual content
        Util.arrayCopy(data, off, val, len2, len);
        return Configuration.currentSizeInBytes;
    }

    /**
     * Returns true iff this MutableBigInteger has a value of one.
     */
    public boolean isOne() {
        return (len == 1) && (data[off] == 1);
    }

    /**
     * Returns true iff this MutableBigInteger has a value of zero.
     */
    public boolean isZero() {
        return (len == 0);
    }

    /**
     * Returns true iff this MutableBigInteger is even.
     */
    public boolean isEven() {
        return (len == 0) || ((data[(short)(off + len - 1)] & 1) == 0);
    }

    /**
     * Returns true iff this MutableBigInteger is odd.
     */
    public boolean isOdd() {
        return isZero() ? false : ((data[(short)(off + len - 1)] & 1) == 1);
    }

    /**
     * Returns true iff this MutableBigInteger is in normal form. A
     * MutableBigInteger is in normal form if it has no leading zeros
     * after the offset, and intLen + offset <= value.length.
     */
    public boolean isNormal() {
        if ((short)(len + off) > data.length)
            return false;
        if (len ==0)
            return true;
        return (data[off] != 0);
    }
    
    /**
     * Gets the number of bits that this big number is able to represent.
     * @return the number of bits that this big number is able to represent.
     */
    /*public short getSize() {
    	return size;
    }*/
    
    /**
     * Gets the number of bytes necessary to represent this positive big number.
     * @return the number of bytes necessary to represent this positive big number.
     */
    public short getLength() {
    	return len;
    }
    
    /**
     * Resets this big number to the value val. The rest of the positions
     * are set to zero.
     * @param val value to be set.
     */
    public void resetValueTo(byte val) {
    	// 1. updates internal data structure
    	off = (short)(data.length-1);
    	data[off] = val;
    	len = 1;
    	// 2. resets the rest of the positions to zero
    	for (i=0; i < off; i++)
    		data[i]=0;
    }
    
    /**
     * Sets this big number to the value val. The rest of the positions
     * are unmodified.
     * @param val value to be set.
     */
    public void setValue(byte val) {
    	// 1. updates internal data structure
    	off = (short)(data.length-1);
    	data[off] = val;
    	len = 1;
    }
    
    /**
     * Sets this big number to the value val. It occupies the last two positions
     * of the byte[] backend. The rest of the positions are unmodified.
     * @param val value to be set.
     */
    public void setValue(short val) {
    	// 1. updates internal data structure
    	off = (short)(data.length-2);
    	data[(short)(off+1)] = (byte)val; //LSB
    	data[off] = (byte)(val>>8); //MSB
    	len = 2;
    }
 
    public void setRandomValue(short max_size) {
		this.clear();
		while (this.isZero() || this.isOne() || len < max_size){ //this.compare(cipher.props.p1)>0) 
			Configuration.random.generateData(data, (short)(data.length-max_size), max_size); //Configuration.currentSizeInBytes
			off = this.findFirstNonZero();
			len = max_size;//Configuration.currentSizeInBytes;
		}
		this.normalize();
    }

    /**
     * Version of compareTo that ignores sign.
     */
    protected final short compare(MutableBigInteger val) {
    	result = val.data;
        if (len < val.len)
            return -1;
        if (len > val.len)
            return 1;
        len1 = (short)(off + len);
        len2 = (short)(val.off + val.len);
        for (i = off, j=val.off; i < len1; i++,j++) {
            val1 = data[i]; 
            val2 = result[j];
            if (val1 != val2) {
                return (short)(((val1 & BYTE_MASK) < (val2 & BYTE_MASK))? -1 : 1);
            }
        }
        return 0;
    }
    
    /**
     * Returns the number of zero bits preceding the highest-order
     * ("leftmost") one-bit in the two's complement binary representation
     * of the specified <tt>byte</tt> value.  Returns 8 if the
     * specified value has no one-bits in its two's complement representation,
     * in other words if it is equal to zero.
     *
     * <p>Note that this method is closely related to the logarithm base 2.
     * For all positive <tt>byte</tt> values x:
     * <ul>
     * <li>floor(log<sub>2</sub>(x)) = <tt>7 - numberOfLeadingZeros(x)</tt>
     * <li>ceil(log<sub>2</sub>(x)) = <tt>8 - numberOfLeadingZeros(x - 1)</tt>
     * </ul>
     *
     * @return the number of zero bits preceding the highest-order
     *     ("leftmost") one-bit in the two's complement binary representation
     *     of the specified <tt>byte</tt> value, or 8 if the value
     *     is equal to zero.
     */
    protected static byte numberOfLeadingZeros(byte i) {
        if (i == 0)
            return 8;
        byte x = (byte)1;
        if ((short)(i >>> 4) == 0) { x +=  (short)4; i <<=  4; }
        if ((short)(i >>> 6) == 0) { x +=  (short)2; i <<=  2; }
        x -= (byte)(i >>> 7 & 0x01);
        return x;
    }
    
    /**
     * Number of bits necessary to represent the number 'n'.
     * 
     */
    protected static byte bitLength(byte n) {
        return (byte)(8 - numberOfLeadingZeros(n));
    }

    /**
	 * Returns the first index from the 'data' array of a non-zero byte.
	 * @return the first index from the 'data' array of a non-zero byte.
	 */
	protected short findFirstNonZero() {
		i=0;
		len1= (short) data.length;
		while (i<len1 && data[i]==0) i++;
		return i;
	}
    
    /* ******************** METHODS FOR DEBUGGING ****************************/
    
    /**
     * Returns the backend byte array of this MutableBigInteger. 
     */
    public byte[] getData() {
    	return data;
    }
}
