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

package org.wildfly.security.auth.callback;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.verifier.Verifier;

/**
 * A callback handler for a {@link CredentialVerifyCallback}.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class CredentialVerifyCallbackHandler implements CallbackHandler {

    private final Verifier verifier;

    /**
     * Construct a new instance.
     *
     * @param verifier the verifier to use
     */
    public CredentialVerifyCallbackHandler(final Verifier verifier) {
        // TODO: determine details of the verifier since the org.wildfly.security.auth.verifier package will likely be removed
        // (the main idea is to have a CertificateVerifier(TrustManager trustManager) and a
        // SignatureVerifier(byte[] data, X509Certificate certificate, String algorithm) that both have a
        // verify(Object credential) method that returns true if the credential was verified and false otherwise)
        this.verifier = verifier;
    }

    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback current : callbacks) {
            if (current instanceof CredentialVerifyCallback) {
                CredentialVerifyCallback cvc = (CredentialVerifyCallback) current;
                Object credential = cvc.getCredential();

                // TODO: determine details of the verifier as described above
                // cvc.setVerified(verifier.verify(credential));
            } else {
                throw new UnsupportedCallbackException(current);
            }
        }
    }
}
