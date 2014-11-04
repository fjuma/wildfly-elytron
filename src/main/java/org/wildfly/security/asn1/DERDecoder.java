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
import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;

import org.wildfly.security.util.PosByteArrayInputStream;

/**
 * A class used to decode ASN.1 values that have been encoded using the Distinguished Encoding Rules (DER).
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class DERDecoder implements ASN1Decoder {

    private PosByteArrayInputStream src;
    private LinkedList<DecoderState> states = new LinkedList<DecoderState>();

    /**
     * Create a DER decoder that will decode values from the given byte array.
     *
     * @param buf the byte array to decode
     */
    public DERDecoder(byte[] buf) {
        this.src = new PosByteArrayInputStream(buf);
    }

    /**
     * Create a DER decoder that will decode values from the given byte array.
     *
     * @param buf the byte array to decode
     * @param offset the offset in the byte array of the first byte to read
     * @param the maximum number of bytes to read from the byte array
     */
    public DERDecoder(byte[] buf, int offset, int length) {
        this.src = new PosByteArrayInputStream(buf, offset, length);
    }

    /**
     * Create a DER decoder that will decode values from the given {@code PosByteArrayInputStream}.
     *
     * @param src the {@code PosByteArrayInputStream} from which DER encoded values will be decoded
     */
    public DERDecoder(PosByteArrayInputStream src) {
        this.src = src;
    }

    @Override
    public void startSequence() throws IOException, ASN1Exception {
        readTag(SEQUENCE_TYPE);
        int length = readLength();
        states.add(new DecoderState(SEQUENCE_TYPE, src.getPos() + length));
    }

    @Override
    public void endSequence() throws IOException {
        DecoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SEQUENCE_TYPE)) {
            throw new IllegalStateException("No sequence to end");
        }
        endConstructedElement(lastState.getNextElementIndex());
        states.removeLast();
    }

    @Override
    public void startSet() throws IOException, ASN1Exception {
        readTag(SET_TYPE);
        int length = readLength();
        states.add(new DecoderState(SET_TYPE, src.getPos() + length));
    }

    @Override
    public void endSet() throws IOException {
        DecoderState lastState = states.peekLast();
        if ((lastState == null) || (lastState.getTag() != SET_TYPE)) {
            throw new IllegalStateException("No set to end");
        }
        endConstructedElement(lastState.getNextElementIndex());
        states.removeLast();
    }

    private void endConstructedElement(int nextElementIndex) throws IOException {
        int pos = src.getPos();
        if (pos < nextElementIndex) {
            long skipped = src.skip(nextElementIndex - pos);
            if (skipped != (nextElementIndex - pos)) {
                throw log.unexpectedEof();
            }
        } else if (pos > nextElementIndex) {
            // Shouldn't happen
            throw new IllegalStateException();
        }
    }

    @Override
    public byte[] decodeOctetString() throws IOException {
        readTag(OCTET_STRING_TYPE);
        int length = readLength();
        byte[] result = new byte[length];
        if ((length != 0) && (src.read(result, 0, length) != length)) {
            throw log.unexpectedEof();
        }
        return result;
    }

    @Override
    public String decodeOctetStringAsString() throws IOException {
        return decodeOctetStringAsString(StandardCharsets.UTF_8.name());
    }

    @Override
    public String decodeOctetStringAsString(String charSet) throws IOException {
        readTag(OCTET_STRING_TYPE);
        int length = readLength();
        byte[] octets = new byte[length];
        if ((length != 0) && (src.read(octets, 0, length) != length)) {
            throw log.unexpectedEof();
        }
        return new String(octets, charSet);
    }

    @Override
    public String decodeIA5String() throws IOException {
        byte[] octets = decodeIA5StringAsBytes();
        return new String(octets, StandardCharsets.US_ASCII);
    }

    @Override
    public byte[] decodeIA5StringAsBytes() throws IOException {
        readTag(IA5_STRING_TYPE);
        int length = readLength();
        byte[] result = new byte[length];
        if ((length != 0) && (src.read(result, 0, length) != length)) {
            throw log.unexpectedEof();
        }
        return result;
    }

    @Override
    public byte[] decodeBitString() throws IOException, ASN1Exception {
        readTag(BIT_STRING_TYPE);
        int length = readLength();
        int numUnusedBits;
        byte[] result = new byte[length - 1];

        numUnusedBits = src.read();
        if (numUnusedBits == -1) {
            throw log.unexpectedEof();
        } else if (numUnusedBits < 0 || numUnusedBits > 7) {
            throw new ASN1Exception("Invalid number of unused bits");
        }

        int next;
        if (numUnusedBits == 0) {
            for (int i = 0; i < (length -1); i++) {
                if ((next = src.read()) == -1) {
                    throw log.unexpectedEof();
                }
                result[i] = (byte) next;
            }
        } else {
            // Any unused bits will be removed
            int leftShift = 8 - numUnusedBits;
            int previous = 0;
            for (int i = 0; i < (length -1); i++) {
                if ((next = src.read()) == -1) {
                    throw log.unexpectedEof();
                }
                if (i == 0) {
                    result[i] = (byte) (next >>> numUnusedBits);
                } else {
                    result[i] = (byte) ((next >>> numUnusedBits) | (previous << leftShift));
                }
                previous = next;
            }
        }
        return result;
    }

    @Override
    public String decodeBitStringAsString() throws IOException, ASN1Exception {
        readTag(BIT_STRING_TYPE);
        int length = readLength();
        int numUnusedBits;
        if ((numUnusedBits = src.read()) == -1) {
            throw log.unexpectedEof();
        } else if (numUnusedBits < 0 || numUnusedBits > 7) {
            throw new ASN1Exception("Invalid number of unused bits");
        }

        int k = 0, next;
        int numBits = (length - 1) * 8 - numUnusedBits;
        StringBuilder result = new StringBuilder(numBits);
        for (int i = 0; i < (length - 1); i++) {
            if ((next = src.read()) == -1) {
                throw log.unexpectedEof();
            }
            for (int j = 7; j >= 0 && k < numBits; j--) {
                if ((next & (1 << j)) != 0) {
                    result.append("1");
                } else {
                    result.append("0");
                }
                k += 1;
            }
        }
        return result.toString();
    }

    @Override
    public String decodeObjectIdentifier() throws IOException {
        readTag(OBJECT_IDENTIFIER_TYPE);
        int length = readLength();
        int octet;
        long value = 0;
        BigInteger bi = null;
        boolean processedFirst = false;
        StringBuffer objectIdentifierStr = new StringBuffer();

        for (int i = 0; i < length; i++) {
            if ((octet = src.read()) == -1) {
                throw log.unexpectedEof();
            }
            if (value < 0x80000000000000L) {
                value = (value << 7) + (octet & 0x7f);
                if ((octet & 0x80) == 0) {
                    // Reached the end of a component value
                    if (!processedFirst) {
                        int first = ((int) value / 40);
                        if (first == 0) {
                            objectIdentifierStr.append("0");
                        } else if (first == 1) {
                            value = value - 40;
                            objectIdentifierStr.append("1");
                        } else if (first == 2) {
                            value = value - 80;
                            objectIdentifierStr.append("2");
                        }
                        processedFirst = true;
                    }
                    objectIdentifierStr.append('.');
                    objectIdentifierStr.append(value);

                    // Reset for the next component value
                    value = 0;
                }
            } else {
                if (bi == null) {
                    bi = BigInteger.valueOf(value);
                }
                bi = bi.shiftLeft(7).add(BigInteger.valueOf(octet & 0x7f));
                if ((octet & 0x80) == 0) {
                    // Reached the end of a component value
                    objectIdentifierStr.append('.');
                    objectIdentifierStr.append(bi);

                    // Reset for the next component value
                    bi = null;
                    value = 0;
                }
            }
        }
        return objectIdentifierStr.toString();
    }

    @Override
    public void decodeNull() throws IOException, ASN1Exception {
        readTag(NULL_TYPE);
        int length = readLength();
        if (length != 0) {
            throw new ASN1Exception("Non-zero length encountered for null type tag");
        }
    }

    @Override
    public int peekType() throws IOException {
        src.mark(0);
        int tag = readTag();
        src.reset();
        return tag;
    }

    @Override
    public void skipElement() throws IOException {
        readTag();
        int length = readLength();
        long skipped = src.skip(length);
        if (skipped != length) {
            throw log.unexpectedEof();
        }
    }

    @Override
    public boolean hasNextElement() {
        boolean hasNext = false;
        src.mark(0);
        try {
            int tag = readTag();
            int length = readLength();
            if (length <= src.available()) {
                hasNext = true;
            }
        } catch (IOException e) {
            hasNext = false;
        }
        src.reset();
        return hasNext;
    }

    private int readTag() throws IOException, ASN1Exception {
        int tag;
        if ((tag = src.read()) == -1) {
            throw log.unexpectedEof();
        }
        int constructed = tag & CONSTRUCTED_MASK;
        int tagNumber = tag & TAG_NUMBER_MASK;
        if (tagNumber == 0x1f) {
            // High-tag-number form
            tagNumber = 0;
            int octet = src.read();
            if ((octet & 0x7f) == 0) {
                // Bits 7 to 1 of the first subsequent octet cannot be 0
                throw new ASN1Exception("Invalid high-tag-number form");
            }
            while ((octet >= 0) && ((octet & 0x80) != 0)) {
                tagNumber |= (octet & 0x7f);
                tagNumber <<= 7;
                octet = src.read();
            }
            if (octet == -1) {
                throw log.unexpectedEof();
            }
            tagNumber |= (octet & 0x7f);
        }
        return (constructed | tagNumber);
    }

    private void readTag(int expectedTag) throws IOException, ASN1Exception {
        src.mark(0);
        int actualTag = readTag();
        if (actualTag != expectedTag) {
            src.reset();
            throw new ASN1Exception("Unexpected ASN.1 tag encountered");
        }
    }

    private int readLength() throws IOException, ASN1Exception {
        int length;
        if ((length = src.read()) == -1) {
            throw log.unexpectedEof();
        }
        if (length > 127) {
            // Long form
            int numOctets = length & 0x7f;
            if (numOctets > 4) {
                throw new ASN1Exception("Length encoding exceeds 4 bytes");
            }
            length = 0;
            int nextOctet;
            for (int i = 0; i < numOctets; i++) {
                if ((nextOctet = src.read()) == -1) {
                    throw log.unexpectedEof();
                }
                length = (length << 8) + nextOctet;
            }
        }
        return length;
    }

    /**
     * A class used to maintain state information during DER decoding.
     */
    private class DecoderState {
        // Tag number for a constructed element
        private final int tag;

        // The position of the first character in the encoded buffer that occurs after
        // the encoding of the constructed element
        private final int nextElementIndex;

        public DecoderState(int tag, int nextElementIndex) {
            this.tag = tag;
            this.nextElementIndex = nextElementIndex;
        }

        public int getTag() {
            return tag;
        }

        public int getNextElementIndex() {
            return nextElementIndex;
        }
    }
}
