/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.asn1;

import static org.wildfly.security.asn1.ASN1.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;

import org.wildfly.security.sasl.util.ByteStringBuilder;
import org.wildfly.security.util.ByteIterator;

/**
 * A class used to encode ASN.1 values using the Distinguished Encoding Rules (DER), as specified
 * in <a href="http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf">ITU-T X.690</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class DEREncoder implements ASN1Encoder {
    private static final int[] BITS = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    private static final long LARGEST_UNSHIFTED_LONG = Long.MAX_VALUE / 10L;
    private static final byte[] NULL_CONTENTS = new byte[0];

    private ArrayDeque<EncoderState> states = new ArrayDeque<EncoderState>();
    private ArrayList<ByteStringBuilder> buffers = new ArrayList<ByteStringBuilder>();
    private ByteStringBuilder currentBuffer;
    private int currentBufferPos = -1;
    private ByteStringBuilder target;
    private final TagComparator TAG_COMPARATOR = new TagComparator();
    private final LexicographicComparator LEXICOGRAPHIC_COMPARATOR = new LexicographicComparator();
    private int implicitTag = -1;

    /**
     * Create a DER encoder that writes its output to the given {@code ByteStringBuilder}.
     *
     * @param target the {@code ByteStringBuilder} to which the DER encoded values are written
     */
    public DEREncoder(ByteStringBuilder target) {
        this.target = target;
        currentBuffer = target;
    }

    @Override
    public void startSequence() {
        startConstructedElement(SEQUENCE_TYPE);
    }

    @Override
    public void startSet() {
        startConstructedElement(SET_TYPE);
    }

    @Override
    public void startSetOf() {
        startSet();
    }

    @Override
    public void startExplicit(int number) {
        startExplicit(CONTEXT_SPECIFIC_MASK, number);
    }

    @Override
    public void startExplicit(int clazz, int number) {
        int explicitTag = clazz | CONSTRUCTED_MASK | number;
        startConstructedElement(explicitTag);
    }

    private void startConstructedElement(int tag) {
        EncoderState lastState = states.peekLast();
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            updateCurrentBuffer();
            lastState.addChildElement(tag, currentBufferPos);
        }
        writeTag(tag, currentBuffer);
        if (tag != SET_TYPE) {
            updateCurrentBuffer();
        }
        states.add(new EncoderState(tag, currentBufferPos));
    }

    @Override
    public void endSequence() throws IllegalStateException {
        EncoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SEQUENCE_TYPE)) {
            throw new IllegalStateException("No sequence to end");
        }
        endConstructedElement();
    }

    @Override
    public void endExplicit() throws IllegalStateException {
        EncoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() == SEQUENCE_TYPE)
                || (lastState.getTag() == SET_TYPE) || ((lastState.getTag() & CONSTRUCTED_MASK) == 0)) {
            throw new IllegalStateException("No explicitly tagged element to end");
        }
        endConstructedElement();
    }

    private void endConstructedElement() {
        ByteStringBuilder dest;
        if (currentBufferPos > 0) {
            // Output the element to its parent buffer
            dest = buffers.get(currentBufferPos - 1);
        } else {
            // Output the element directly to the target destination
            dest = target;
        }
        int length = currentBuffer.length();
        int numLengthOctets = writeLength(length, dest);
        dest.append(currentBuffer);
        currentBuffer.setLength(0);
        currentBuffer = dest;
        currentBufferPos -= 1;
        states.removeLast();

        // If this element's parent element is a set element, update the parent's accumulated length
        EncoderState lastState = states.peekLast();
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            lastState.addChildLength(1 + numLengthOctets + length);
        }
    }

    @Override
    public void endSet() throws IllegalStateException {
        endSet(TAG_COMPARATOR);
    }

    @Override
    public void endSetOf() throws IllegalStateException {
        endSet(LEXICOGRAPHIC_COMPARATOR);
    }

    private void endSet(Comparator comparator) {
        EncoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SET_TYPE)) {
            throw new IllegalStateException("No set to end");
        }

        // The child elements of a set must be encoded in ascending order by tag
        LinkedList<EncoderState> childElements = lastState.getSortedChildElements(comparator);
        int setBufferPos = lastState.getBufferPos();
        ByteStringBuilder dest;
        if (setBufferPos >= 0) {
            dest = buffers.get(setBufferPos);
        } else {
            dest = target;
        }

        ByteStringBuilder contents;
        int childLength = lastState.getChildLength();
        int numLengthOctets = writeLength(lastState.getChildLength(), dest);
        for (EncoderState element : childElements) {
            contents = buffers.get(element.getBufferPos());
            dest.append(contents);
            contents.setLength(0);
        }
        currentBuffer = dest;
        currentBufferPos = setBufferPos;
        states.removeLast();

        // If this set's parent element is a set element, update the parent's accumulated length
        lastState = states.peekLast();
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            lastState.addChildLength(1 + numLengthOctets + childLength);
        }
    }

    @Override
    public void encodeOctetString(String str) {
        encodeOctetString(str.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void encodeOctetString(byte[] str) {
        writeElement(OCTET_STRING_TYPE, str);
    }

    @Override
    public void encodeOctetString(ByteStringBuilder str) {
        writeElement(OCTET_STRING_TYPE, str);
    }

    @Override
    public void encodeIA5String(String str) {
        encodeIA5String(str.getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public void encodeIA5String(byte[] str) {
        writeElement(IA5_STRING_TYPE, str);
    }

    @Override
    public void encodeIA5String(ByteStringBuilder str) {
        writeElement(IA5_STRING_TYPE, str);
    }

    @Override
    public void encodeBitString(byte[] str) {
        encodeBitString(str, 0); // All bits will be used
    }

    @Override
    public void encodeBitString(byte[] str, int numUnusedBits) {
        byte[] contents = new byte[str.length + 1];
        contents[0] = (byte) numUnusedBits;
        System.arraycopy(str, 0, contents, 1, str.length);
        writeElement(BIT_STRING_TYPE, contents);
    }

    @Override
    public void encodeBitString(String binaryStr) {
        int numBits = binaryStr.length();
        int numBytes = numBits >> 3;
        int remainder = numBits % 8;
        int numUnusedBits = 0;

        if (remainder != 0) {
            numBytes = numBytes + 1;
            numUnusedBits = 8 - remainder;
        }

        byte[] contents = new byte[numBytes + 1];
        contents[0] = (byte) numUnusedBits;
        for (int i = 1; i <= numBytes; i++) {
            contents[i] = (byte) 0;
        }

        char[] binaryStrChars = binaryStr.toCharArray();
        int index = 0;
        for (int i = 1; i <= numBytes && index < numBits; i++) {
            for (int bit = 7; bit >= 0 && index < numBits; bit--) {
                if ((i == numBytes) && (bit < numUnusedBits)) {
                    continue;
                }
                if (binaryStrChars[index++] == '1') {
                    contents[i] |= BITS[bit];
                }
            }
        }
        writeElement(BIT_STRING_TYPE, contents);
    }

    @Override
    public void encodeObjectIdentifier(String objectIdentifier) throws ASN1Exception {
        int len = objectIdentifier.length();
        if (len == 0) {
            throw new ASN1Exception("OID must have at least 2 components");
        }

        int offs = 0;
        int idx = 0;
        long t = 0L;
        char c;
        int numComponents = 0;
        int first = -1;
        ByteStringBuilder contents = new ByteStringBuilder();

        a: for (;;) {
            c = objectIdentifier.charAt(offs + idx ++);
            if (Character.isDigit(c)) {
                int digit = Character.digit(c, 10);
                if (t > LARGEST_UNSHIFTED_LONG) {
                    BigInteger bi = BigInteger.valueOf(t).multiply(BigInteger.TEN).add(digits[digit]);
                    t = 0L;
                    for (;;) {
                        c = objectIdentifier.charAt(offs + idx ++);
                        if (Character.isDigit(c)) {
                            digit = Character.digit(c, 10);
                            bi = bi.multiply(BigInteger.TEN).add(digits[digit]);
                        } else if (c == '.') {
                            if (numComponents == 0) {
                                first = validateFirstOIDComponent(bi);
                            } else {
                                encodeOIDComponent(bi, contents, numComponents, first);
                            }
                            numComponents++;
                            continue a;
                        } else {
                            throw new ASN1Exception("Invalid OID character");
                        }
                        if (idx == len) {
                            if (numComponents == 0) {
                                throw new ASN1Exception("OID must have at least 2 components");
                            }
                            encodeOIDComponent(bi, contents, numComponents, first);
                            writeElement(OBJECT_IDENTIFIER_TYPE, contents);
                            return;
                        }
                    }
                } else {
                    t = 10L * t + (long) digit;
                }
            } else if (c == '.') {
                if (numComponents == 0) {
                    first = validateFirstOIDComponent(t);
                } else {
                    encodeOIDComponent(t, contents, numComponents, first);
                }
                numComponents++;
                t = 0L;
            } else {
                throw new ASN1Exception("Invalid OID character");
            }
            if (idx == len) {
                if (c == '.') {
                    throw new ASN1Exception("Invalid OID character");
                }
                if (numComponents == 0) {
                    throw new ASN1Exception("OID must have at least 2 components");
                }
                encodeOIDComponent(t, contents, numComponents, first);
                writeElement(OBJECT_IDENTIFIER_TYPE, contents);
                return;
            }
        }
    }

    @Override
    public void encodeNull() {
        writeElement(NULL_TYPE, NULL_CONTENTS);
    }

    @Override
    public void encodeImplicit(int number) {
        encodeImplicit(CONTEXT_SPECIFIC_MASK, number);
    }

    @Override
    public void encodeImplicit(int clazz, int number) {
        if (implicitTag == -1) {
            implicitTag = clazz | number;
        }
    }

    @Override
    public void writeEncoded(byte[] encoded) {
        EncoderState lastState = states.peekLast();
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            updateCurrentBuffer();
            lastState.addChildElement(encoded[0], currentBufferPos);
        }

        currentBuffer.append(encoded);

        // If this element's parent element is a set element, update the parent's accumulated length
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            lastState.addChildLength(currentBuffer.length());
        }
    }

    @Override
    public void flush() {
        while (states.size() != 0) {
            EncoderState lastState = states.peekLast();
            if (lastState.getTag() == SEQUENCE_TYPE) {
                endSequence();
            } else if (lastState.getTag() == SET_TYPE) {
                endSet();
            }
        }
    }

    private int validateFirstOIDComponent(long value) throws ASN1Exception {
        if (value < 0 || value > 2) {
            throw new ASN1Exception("Invalid value for first OID component; expected 0, 1, or 2");
        }
        return (int) value;
    }

    private int validateFirstOIDComponent(BigInteger value) throws ASN1Exception  {
        if ((value.compareTo(BigInteger.valueOf(0)) == -1)
                || (value.compareTo(BigInteger.valueOf(2)) == 1)) {
            throw new ASN1Exception("Invalid value for first OID component; expected 0, 1, or 2");
        }
        return value.intValue();
    }

    private void validateSecondOIDComponent(long second, int first) throws ASN1Exception  {
        if ((first < 2) && (second > 39)) {
            throw new ASN1Exception("Invalid value for second OID component; expected a value between 0 and 39 (inclusive)");
        }
    }

    private void validateSecondOIDComponent(BigInteger second, int first) throws ASN1Exception {
        if ((first < 2) && (second.compareTo(BigInteger.valueOf(39)) == 1)) {
            throw new ASN1Exception("Invalid value for second OID component; expected a value between 0 and 39 (inclusive)");
        }
    }

    private void checkNumComponents(int numComponents) throws ASN1Exception {
        if (numComponents < 2) {
            throw new ASN1Exception("OID must have at least 2 components");
        }
    }

    private void encodeOIDComponent(long value, ByteStringBuilder contents,
            int numComponents, int first) throws ASN1Exception {
         if (numComponents == 1) {
            validateSecondOIDComponent(value, first);
            encodeOIDComponent(value + (40 * first), contents);
        } else {
            encodeOIDComponent(value, contents);
        }
    }

    private void encodeOIDComponent(BigInteger value, ByteStringBuilder contents,
            int numComponents, int first) throws ASN1Exception {
         if (numComponents == 1) {
            validateSecondOIDComponent(value, first);
            encodeOIDComponent(value.add(BigInteger.valueOf(40 * first)), contents);
        } else {
            encodeOIDComponent(value, contents);
        }
    }

    private void encodeOIDComponent(long value, ByteStringBuilder contents) {
        int shift = 56;
        int octet;
        while (shift > 0) {
            if (value >= (1L << shift)) {
                octet = (int) ((value >>> shift) | 0x80);
                contents.append((byte) octet);
            }
            shift = shift - 7;
        }
        octet = (int) (value & 0x7f);
        contents.append((byte) octet);
    }

    private void encodeOIDComponent(BigInteger value, ByteStringBuilder contents) {
        int numBytes = (value.bitLength() + 6) / 7;
        if (numBytes == 0) {
            contents.append((byte) 0);
        } else {
            byte[] result = new byte[numBytes];
            BigInteger currValue = value;
            for (int i = numBytes - 1; i >= 0; i--) {
                result[i] = (byte) ((currValue.intValue() & 0x7f) | 0x80);
                currValue = currValue.shiftRight(7);
            }
            result[numBytes - 1] &= 0x7f;
            contents.append(result);
        }
    }

    private static final BigInteger[] digits = {
        BigInteger.ZERO,
        BigInteger.ONE,
        BigInteger.valueOf(2),
        BigInteger.valueOf(3),
        BigInteger.valueOf(4),
        BigInteger.valueOf(5),
        BigInteger.valueOf(6),
        BigInteger.valueOf(7),
        BigInteger.valueOf(8),
        BigInteger.valueOf(9),
    };

    private void writeTag(int tag, ByteStringBuilder dest) {
        int constructed = tag & CONSTRUCTED_MASK;
        if (implicitTag != -1) {
            tag = implicitTag | constructed;
            implicitTag = -1;
        }
        int tagClass = tag & CLASS_MASK;
        int tagNumber = tag & TAG_NUMBER_MASK;
        if (tagNumber < 31) {
            dest.append((byte) (tagClass | constructed | tagNumber));
        } else {
            // High-tag-number-form
            dest.append((byte) (tagClass | constructed | 0x1f));
            if (tagNumber < 128) {
                dest.append((byte) tagNumber);
            } else {
                int shift = 28;
                int octet;
                while (shift > 0) {
                    if (tagNumber >= (1 << shift)) {
                        octet = (int) ((tagNumber >>> shift) | 0x80);
                        dest.append((byte) octet);
                    }
                    shift = shift - 7;
                }
                octet = (int) (tagNumber & 0x7f);
                dest.append((byte) octet);
            }
        }
    }

    private int writeLength(int length, ByteStringBuilder dest) throws ASN1Exception {
        int numLengthOctets = 0;
        if (length < 0) {
            throw new ASN1Exception("Invalid length");
        } else if (length <= 127) {
            // Short form
            numLengthOctets = 1;
        } else {
            // Long form
            numLengthOctets = 1;
            int value = length;
            while ((value >>>= 8) != 0) {
                numLengthOctets += 1;
            }
        }
        if (length > 127) {
            dest.append((byte) (numLengthOctets | 0x80));
        }
        for (int i = (numLengthOctets - 1) * 8; i >= 0; i -= 8) {
            dest.append((byte) (length >> i));
        }
        return numLengthOctets;
    }

    private void updateCurrentBuffer() {
        currentBufferPos += 1;
        if (currentBufferPos < buffers.size()) {
            currentBuffer = buffers.get(currentBufferPos);
        } else {
            ByteStringBuilder buffer = new ByteStringBuilder();
            buffers.add(buffer);
            currentBuffer = buffer;
        }
    }

    private void writeElement(int tag, byte[] contents) {
        EncoderState lastState = states.peekLast();
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            updateCurrentBuffer();
            lastState.addChildElement(tag, currentBufferPos);
        }

        writeTag(tag, currentBuffer);
        writeLength(contents.length, currentBuffer);
        currentBuffer.append(contents);

        // If this element's parent element is a set element, update the parent's accumulated length
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            lastState.addChildLength(currentBuffer.length());
        }
    }

    private void writeElement(int tag, ByteStringBuilder contents) {
        EncoderState lastState = states.peekLast();
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            updateCurrentBuffer();
            lastState.addChildElement(tag, currentBufferPos);
        }

        writeTag(tag, currentBuffer);
        writeLength(contents.length(), currentBuffer);
        currentBuffer.append(contents);

        // If this element's parent element is a set element, update the parent's accumulated length
        if ((lastState != null) && (lastState.getTag() == SET_TYPE)) {
            lastState.addChildLength(currentBuffer.length());
        }
    }

    /**
     * A class used to maintain state information during DER encoding.
     */
    private class EncoderState {
        private final int tag;
        private final int bufferPos;
        private LinkedList<EncoderState> childElements = new LinkedList<EncoderState>();
        private int childLength = 0;

        public EncoderState(int tag, int bufferPos) {
            this.tag = tag;
            this.bufferPos = bufferPos;
        }

        public int getTag() {
            return tag;
        }

        public int getBufferPos() {
            return bufferPos;
        }

        public int getChildLength() {
            return childLength;
        }

        public LinkedList<EncoderState> getSortedChildElements(Comparator<EncoderState> comparator) {
            Collections.sort(childElements, comparator);
            return childElements;
        }

        public void addChildElement(int tag, int bufferPos) {
            childElements.add(new EncoderState(tag, bufferPos));
        }

        public void addChildLength(int length) {
            childLength += length;
        }
    }

    /**
     * A class that compares DER encodings based on their tags.
     */
    private class TagComparator implements Comparator<EncoderState> {
        @Override
        public int compare(EncoderState state1, EncoderState state2) {
            // Ignore the constructed bit when comparing tags
            return (state1.getTag() | CONSTRUCTED_MASK) - (state2.getTag() | CONSTRUCTED_MASK);
        }
    }

    /**
     * A class that compares DER encodings using lexicographic order.
     */
    private class LexicographicComparator implements Comparator<EncoderState> {
        @Override
        public int compare(EncoderState state1, EncoderState state2) {
            ByteStringBuilder bytes1 = buffers.get(state1.getBufferPos());
            ByteStringBuilder bytes2 = buffers.get(state2.getBufferPos());
            ByteIterator bi1 = bytes1.iterate();
            ByteIterator bi2 = bytes2.iterate();

            // Scan the two encodings from left to right until a difference is found
            int diff;
            while (bi1.hasNext() && bi2.hasNext()) {
                diff = (bi1.next() & 0xff) - (bi2.next() & 0xff);
                if (diff != 0) {
                    return diff;
                }
            }

            // The longer encoding is considered to be the bigger-valued encoding
            return bytes1.length() - bytes2.length();
        }
    }
}
