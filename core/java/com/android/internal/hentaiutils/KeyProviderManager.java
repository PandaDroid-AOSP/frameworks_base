/*
 * Copyright (C) 2024 Paranoid Android
 * Copyright (C) 2024 The hentaiOS Project and its Proprietors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.internal.hentaiutils;

import android.app.ActivityThread;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.util.Log;

import com.android.internal.R;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Manager class for handling keybox providers.
 * @hide
 */
public final class KeyProviderManager {
    private static final String TAG = "KeyProviderManager";

    private static final IKeyboxProvider PROVIDER = new DefaultKeyboxProvider();

    private KeyProviderManager() {
    }

    public static IKeyboxProvider getProvider() {
        return PROVIDER;
    }

    public static boolean isKeyboxAvailable() {
        return PROVIDER.hasKeybox();
    }

    private static class DefaultKeyboxProvider implements IKeyboxProvider {
        private final Map<String, String> keyboxData = new HashMap<>();

        private DefaultKeyboxProvider() {
            Context context = getApplicationContext();
            if (context == null) {
                Log.e(TAG, "Failed to get application context");
                return;
            }

            String[] keybox = hentaiResourceUtils.loadArrayFromResources(context, hentaiResourceUtils.PACKAGE_SECRET, "certifiedKeybox");

            Arrays.stream(keybox)
                    .map(entry -> entry.split(":", 2))
                    .filter(parts -> parts.length == 2)
                    .forEach(parts -> keyboxData.put(parts[0], parts[1]));

            if (!hasKeybox()) {
                Log.w(TAG, "Incomplete keybox data loaded");
            }
        }

        private static Context getApplicationContext() {
            try {
                return ActivityThread.currentApplication().getApplicationContext();
            } catch (Exception e) {
                Log.e(TAG, "Error getting application context", e);
                return null;
            }
        }

        @Override
        public boolean hasKeybox() {
            return Arrays.asList("EC.PRIV", "EC.CERT_1", "EC.CERT_2", "EC.CERT_3",
                    "RSA.PRIV", "RSA.CERT_1", "RSA.CERT_2", "RSA.CERT_3")
                    .stream()
                    .allMatch(keyboxData::containsKey);
        }

        @Override
        public String getEcPrivateKey() {
            return keyboxData.get("EC.PRIV");
        }

        @Override
        public String getRsaPrivateKey() {
            return keyboxData.get("RSA.PRIV");
        }

        @Override
        public String[] getEcCertificateChain() {
            return getCertificateChain("EC");
        }

        @Override
        public String[] getRsaCertificateChain() {
            return getCertificateChain("RSA");
        }

        private String[] getCertificateChain(String prefix) {
            return new String[]{
                    keyboxData.get(prefix + ".CERT_1"),
                    keyboxData.get(prefix + ".CERT_2"),
                    keyboxData.get(prefix + ".CERT_3")
            };
        }
    }
}
