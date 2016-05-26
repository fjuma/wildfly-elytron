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

package org.wildfly.security.auth.client;

import static org.wildfly.security.sasl.otp.OTP.PasswordFormat;

import java.io.IOException;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.ExtendedChoiceCallback;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetOneTimePasswordAuthenticationConfiguration extends AuthenticationConfiguration {

    private final char[] password;
    private final PasswordFormat passwordFormat;

    SetOneTimePasswordAuthenticationConfiguration(final AuthenticationConfiguration parent, final char[] password, final PasswordFormat passwordFormat) {
        super(parent.without(SetPasswordAuthenticationConfiguration.class).without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetKeyStoreCredentialAuthenticationConfiguration.class).without(SetAnonymousAuthenticationConfiguration.class).without(SetGSSCredentialAuthenticationConfiguration.class).without(SetKeyManagerCredentialAuthenticationConfiguration.class).without(SetCertificateCredentialAuthenticationConfiguration.class));
        this.password = password;
        this.passwordFormat = passwordFormat;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        Callback callback = callbacks[index];
        if (callback instanceof ExtendedChoiceCallback) {
            ExtendedChoiceCallback extendedChoiceCallback = (ExtendedChoiceCallback) callback;
            String[] choices = extendedChoiceCallback.getChoices();
            for (int i = 0; i < choices.length; i++) {
                if (passwordFormat.name().equals(choices[i])) {
                    extendedChoiceCallback.setSelectedIndex(i);
                    return;
                }
            }
        } else if (callback instanceof PasswordCallback) {
            ((PasswordCallback) callback).setPassword(password);
            return;
        }
        super.handleCallback(callbacks, index);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        Set<Class<? extends Credential>> types = SaslMechanismInformation.getSupportedClientCredentialTypes(mechanismName);
        return types == null || types.contains(PasswordCredential.class) || super.filterOneSaslMechanism(mechanismName);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetOneTimePasswordAuthenticationConfiguration(newParent, password, passwordFormat);
    }
}
