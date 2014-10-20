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

package org.wildfly.security.auth;

import java.io.IOException;

import javax.net.ssl.TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.TrustManagerCallback;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetTrustManagerAuthenticationConfiguration extends AuthenticationConfiguration {

    private final TrustManager trustManager;

    SetTrustManagerAuthenticationConfiguration(final AuthenticationConfiguration parent, final TrustManager trustManager) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class));
        this.trustManager = trustManager;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetTrustManagerAuthenticationConfiguration(newParent, trustManager);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof TrustManagerCallback) {
            TrustManagerCallback trustManagerCallback = (TrustManagerCallback) callback;
            trustManagerCallback.setTrustManager(trustManager);
            return;
        }
        super.handleCallback(callbacks, index);
    }
}
