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

package org.wildfly.security.auth.server.event;

import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * An authentication event with a definite outcome.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class RealmDefiniteOutcomeAuthenticationEvent extends RealmAuthenticationEvent {

    /**
     * Construct a new instance.
     *
     * @param realmIdentity the authenticated realm identity
     * @param credential the actual credential value from the authentication (may be {@code null} if not known)
     * @param evidence the evidence used to authenticate (may be {@code null} if not known or not applicable)
     */
    protected RealmDefiniteOutcomeAuthenticationEvent(final RealmIdentity realmIdentity, final Credential credential, final Evidence evidence) {
        super(realmIdentity, credential, evidence);
    }

    public <P, R> R accept(final RealmEventVisitor<P, R> visitor, final P param) throws RealmUnavailableException {
        return visitor.handleDefiniteOutcomeAuthenticationEvent(this, param);
    }

    public final boolean isFailure() {
        return ! isSuccess();
    }
}
