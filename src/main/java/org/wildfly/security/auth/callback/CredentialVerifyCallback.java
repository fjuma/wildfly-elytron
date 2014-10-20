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

/**
 * A callback used to verify a credential instead of acquire a credential.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class CredentialVerifyCallback extends AbstractExtendedCallback {

    private Object credential;
    private boolean verified = false;

    /**
     * Construct a new instance.
     *
     * @param credential the credential to verify
     */
    public CredentialVerifyCallback(final Object credential) {
        this.credential = credential;
    }

    /**
     * Get the credential.
     *
     * @return the credential
     */
    public Object getCredential() {
        return credential;
    }

    /**
     * Set whether or not the credential was verified.
     *
     * @param verified {@code true} if the credential was verified and {@code false} otherwise
     */
    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    /**
     * Determine if the credential was verified.
     *
     * @return {@code true} if the credential was verified and {@code false} otherwise
     */
    public boolean isVerified() {
        return verified;
    }
}
