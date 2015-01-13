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

import javax.net.ssl.TrustManager;


/**
 * An callback used to acquire a trust manager for making trust decisions. The supplied trust
 * manager should be of a <em>supported</em> type; the {@link #isTrustManagerSupported(TrustManager)}
 * and {@link #isTrustManagerTypeSupported(Class)} methods can be used to query the types that are
 * supported. If no trust manager is available, {@code null} is set. If an unsupported trust manager
 * type is set, authentication may fail.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class TrustManagerCallback extends AbstractExtendedCallback {

    private static final long serialVersionUID = 7599358804463975572L;

    private final Class<? extends TrustManager>[] allowedTypes;
    private TrustManager trustManager;

    /**
     * Construct a new instance.
     *
     * @param allowedTypes the allowed types of trust manager
     */
    public TrustManagerCallback(final Class<? extends TrustManager>... allowedTypes) {
        this.allowedTypes = allowedTypes;
    }

    /**
     * Construct a new instance.
     *
     * @param trustManager the default trust manager, if any
     * @param allowedTypes the allowed types of trust manager
     */
    public TrustManagerCallback(final TrustManager trustManager, final Class<? extends TrustManager>... allowedTypes) {
        this.allowedTypes = allowedTypes;
        this.trustManager = trustManager;
    }

    /**
     * Get the trust manager.
     *
     * @return the trust manager, or {@code null} if it hasn't been set yet
     */
    public TrustManager getTrustManager() {
        return trustManager;
    }

    /**
     * Set the trust manager.
     *
     * @param trustManager the trust manager, or {@code null} if no trust manager is available
     */
    public void setTrustManager(final TrustManager trustManager) {
        this.trustManager = trustManager;
    }

    /**
     * Determine whether a trust manager would be supported by the authentication.
     *
     * @param trustManager the trust manager to test
     * @return {@code true} if the trust manager is non-{@code null} and supported, {@code false} otherwise
     */
    public boolean isTrustManagerSupported(final TrustManager trustManager) {
        for (final Class<?> allowedType : allowedTypes) {
            if (allowedType.isInstance(trustManager)) return true;
        }
        return false;
    }

    /**
     * Determine whether a trust manager type would be supported by the authentication.
     *
     * @param trustManager the trust manager type to test
     * @return {@code true} if the trust manager type is supported, {@code false} otherwise
     */
    public boolean isTrustManagerTypeSupported(final Class<? extends TrustManager> trustManagerType) {
        for (final Class<? extends TrustManager> allowedType : allowedTypes) {
            if (allowedType.isAssignableFrom(trustManagerType)) return true;
        }
        return false;
    }

    public boolean isOptional() {
        return trustManager != null;
    }

    public boolean needsInformation() {
        return true;
    }
}
