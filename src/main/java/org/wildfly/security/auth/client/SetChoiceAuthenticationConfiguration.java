/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.security.auth.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.ExtendedChoiceCallback;

/**
 * @author <a href="mailto:kkhan@redhat.com">Kabir Khan</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetChoiceAuthenticationConfiguration extends AuthenticationConfiguration {
    private final String choice;

    SetChoiceAuthenticationConfiguration(final AuthenticationConfiguration parent, final String choice) {
        super(parent);
        this.choice = choice;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof ExtendedChoiceCallback) {
            //TODO handle multiple choices etc.
            ExtendedChoiceCallback extendedChoiceCallback = (ExtendedChoiceCallback) callback;
            if (choice == null) {
                extendedChoiceCallback.setSelectedIndex(extendedChoiceCallback.getDefaultChoice());
                return;
            } else {
                String[] choices = extendedChoiceCallback.getChoices();
                for (int i = 0; i < choices.length; i++) {
                    if (choice.equals(choices[i])) {
                        extendedChoiceCallback.setSelectedIndex(i);
                        return;
                    }
                }
            }
        }
        super.handleCallback(callbacks, index);
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new SetChoiceAuthenticationConfiguration(newParent, choice);
    }
}
