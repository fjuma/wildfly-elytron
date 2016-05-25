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

import java.util.Collections;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.event.RealmEventVisitor;
import org.wildfly.security.auth.server.event.RealmIdentityCredentialUpdateEvent;
import org.wildfly.security.credential.Credential;

/**
 * A {@link RealmEventVisitor} implementation for a modifiable realm.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ModifiableRealmEventVisitor extends RealmEventVisitor<Void, Void> {

    /**
     * Construct a new instance.
     */
    protected ModifiableRealmEventVisitor() {
    }

    @Override
    public Void handleIdentityCredentialUpdateEvent(final RealmIdentityCredentialUpdateEvent event, final Void param) throws RealmUnavailableException {
        // Make sure the realm is modifiable and then update the stored credential
        final RealmIdentity realmIdentity = event.getRealmIdentity();
        if (! (realmIdentity instanceof ModifiableRealmIdentity)) {
            throw ElytronMessages.log.realmIsNotModifiable();
        }
        final ModifiableRealmIdentity modifiableRealmIdentity = (ModifiableRealmIdentity) realmIdentity;
        final Credential credential = event.getCredential();
        // todo: Is there a way to just replace a single credential instead?
        modifiableRealmIdentity.setCredentials(Collections.singletonList(credential));
        return null;
    }

}
