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

package org.wildfly.security.auth.server;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.Credential;

/**
 * The public or private credentials retained by an identity, which can be used for authentication forwarding.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface IdentityCredentials {
    /**
     * Determine whether a given credential type is definitely obtainable, possibly obtainable, or definitely not
     * obtainable for this identity.
     *
     * @param credentialType the exact credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does
     * not support algorithm names
     * @return the level of support for this credential type
     */
    default SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) {
        return getCredential(credentialType, algorithmName) != null ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    /**
     * Acquire a credential of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param <C> the credential type
     * @return the credential, or {@code null} if no such credential exists
     */
    default <C extends Credential> C getCredential(Class<C> credentialType) {
        return getCredential(credentialType, null);
    }

    /**
     * Acquire a credential of the given type and algorithm name.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if no such credential exists
     */
    <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName);

    /**
     * Return a copy of this credential set, but with the given credential appended to it.
     *
     * @param credential the credential to append (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    default IdentityCredentials withCredential(final Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return new IdentityCredentials() {
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) {
                final C result = credential.castAs(credentialType, algorithmName);
                return result != null ? result : IdentityCredentials.this.getCredential(credentialType, algorithmName);
            }
        };
    }

    /**
     * Return a copy of this credential set with the given credential set appended to it.
     *
     * @param other the credential set to append (must not be {@code null})
     * @return the new credential set (not {@code null})
     */
    default IdentityCredentials with(final IdentityCredentials other) {
        Assert.checkNotNullParam("other", other);
        return other == NONE ? this : new IdentityCredentials() {
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) {
                final C credential = IdentityCredentials.this.getCredential(credentialType, algorithmName);
                return credential != null ? credential : other.getCredential(credentialType, algorithmName);
            }
        };
    }

    /**
     * The empty credentials object.
     */
    IdentityCredentials NONE = new IdentityCredentials() {
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) {
            return null;
        }

        public IdentityCredentials with(final IdentityCredentials other) {
            return other;
        }
    };
}
