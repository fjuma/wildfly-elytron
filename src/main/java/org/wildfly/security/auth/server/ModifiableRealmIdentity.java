/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.util.List;

import org.wildfly.security.authz.Attributes;

/**
 * A realm identity which is modifiable.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface ModifiableRealmIdentity extends RealmIdentity {

    /**
     * Delete this realm identity.  After this call, {@link #exists()} will return {@code false}.  If the identity
     * does not exist, an exception is thrown.
     *
     * @throws RealmUnavailableException if deletion fails for some reason
     */
    void delete() throws RealmUnavailableException;

    /**
     * Create this realm identity.  After this call, {@link #exists()} will return {@code true} and the credentials
     * and role sets will be empty.  If the identity already exists, an exception is thrown.
     *
     * @throws RealmUnavailableException if creation fails for some reason
     */
    void create() throws RealmUnavailableException;

    /**
     * Replace list of credentials of this identity.  If the identity does not exist, an exception is thrown.
     *
     * @param credentials the new list of credentials
     * @throws RealmUnavailableException if updating the credentials fails for some reason
     */
    void setCredentials(List<Object> credentials) throws RealmUnavailableException;

    /**
     * Set a credential of the given type for this identity. If a credential of the given type already exists, it is
     * replaced. The credential type is defined by its {@code Class} and an optional {@code algorithmName}. If the
     * identity does not exist, an exception is thrown.
     *
     * @param credentialType the credential type class
     * @param algorithmName the optional algorithm name for the credential type
     * @param newCredential the new credential
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    void setCredential(Class<?> credentialType, String algorithmName, Object newCredential) throws RealmUnavailableException;

    /**
     * Modify the attributes collection of this identity.  If the identity does not exist, an exception is thrown.
     *
     * @param attributes the new attributes collection
     * @throws RealmUnavailableException if updating the attributes collection fails for some reason
     */
    void setAttributes(Attributes attributes) throws RealmUnavailableException;
}
