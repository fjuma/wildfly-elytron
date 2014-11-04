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

package org.wildfly.security.util;

import java.io.ByteArrayInputStream;

/**
 * A {@code ByteArrayInputStream} that provides access to the index of the next character
 * to be read from the input stream buffer.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class PosByteArrayInputStream extends ByteArrayInputStream {

    /**
     * Create a new {@code PosByteArrayInputStream} that uses the given byte array as
     * its buffer array.
     *
     * @param buf the input buffer
     */
    public PosByteArrayInputStream(byte[] buf) {
        super(buf);
    }

    /**
     * Create a new {@code PosByteArrayInputStream} that uses the given byte array as
     * its buffer array.
     *
     * @param buf the input buffer
     * @param offset the offset in the buffer that indicates the first byte to read
     * @param length the maximum number of bytes to read from the buffer
     */
    public PosByteArrayInputStream(byte[] buf, int offset, int length) {
        super(buf, offset, length);
    }

    /**
     * Get the index of the next character that will be read from the input stream buffer.
     *
     * @return the index of the next character that will be read from the input stream buffer
     */
    public int getPos() {
        return pos;
    }
}
