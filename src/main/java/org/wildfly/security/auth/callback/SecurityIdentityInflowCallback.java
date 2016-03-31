/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.callback;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.evidence.Evidence;

import javax.security.auth.callback.Callback;

/**
 * A {@link Callback} for use where inflowing an established security identity is required.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class SecurityIdentityInflowCallback implements ExtendedCallback {

    private final SecurityIdentity securityIdentity;
    private boolean inflowed;

    /**
     * Construct a new instance of this {@link Callback}.
     *
     * @param securityIdentity the established security identity to be inflowed
     */
    public SecurityIdentityInflowCallback(final SecurityIdentity securityIdentity) {
        this.securityIdentity = securityIdentity;
    }

    /**
     * Get the security identity being inflowed.
     *
     * @return the security identity being inflowed
     */
    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    /**
     * Set if the security identity referenced here has been inflowed.
     *
     * @param inflowed whether the security identity has been inflowed
     */
    public void setInflowed(final boolean inflowed) {
        this.inflowed = inflowed;
    }

    /**
     * Check if the security identity referenced here has been inflowed.
     *
     * @return {@code true} if the security identity has been inflowed, {@code false} otherwise
     */
    public boolean isInflowed() {
        return inflowed;
    }

    public boolean isOptional() {
        return false;
    }

    public boolean needsInformation() {
        return true;
    }

}
