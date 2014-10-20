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
 * A callback to acquire a trust manager for trust verification.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class TrustManagerCallback implements ExtendedCallback {

    private TrustManager trustManager;

    /**
     * Construct a new instance.
     */
    public TrustManagerCallback() {
    }

    /**
     * Get the trust manager.  If none was set, {@code null} is returned.
     *
     * @return the trust manager, or {@code null} if none was set
     */
    public TrustManager getTrustManager() {
        return trustManager;
    }

    /**
     * Set the trust manager.
     *
     * @param trustManager the trust manager
     */
    public void setTrustManager(final TrustManager trustManager) {
        this.trustManager = trustManager;
    }

    public boolean isOptional() {
        return true;
    }

    public boolean needsInformation() {
        return true;
    }
}
