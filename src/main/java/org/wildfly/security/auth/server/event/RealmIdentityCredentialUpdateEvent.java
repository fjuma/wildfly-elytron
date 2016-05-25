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

package org.wildfly.security.auth.server.event;

import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.credential.Credential;

/**
 * An event indicating a credential change for a realm identity.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class RealmIdentityCredentialUpdateEvent extends RealmEvent {
    private final RealmIdentity realmIdentity;
    private final Credential credential;

    /**
     * Construct a new instance.
     *
     * @param realmIdentity the realm identity
     * @param credential the new credential for the given realm identity
     */
    public RealmIdentityCredentialUpdateEvent(final RealmIdentity realmIdentity, final Credential credential) {
        this.realmIdentity = realmIdentity;
        this.credential = credential;
    }

    /**
     * Get the realm identity.
     *
     * @return the realm identity
     */
    public RealmIdentity getRealmIdentity() {
        return realmIdentity;
    }

    /**
     * Get the new credential.
     *
     * @return the new credential
     */
    public Credential getCredential() {
        return credential;
    }

    public <P, R> R accept(final RealmEventVisitor<P, R> visitor, final P param) throws RealmUnavailableException {
        return visitor.handleIdentityCredentialUpdateEvent(this, param);
    }
}
