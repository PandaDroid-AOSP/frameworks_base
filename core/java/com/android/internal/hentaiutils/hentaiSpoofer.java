/*
 * Copyright (C) 2021 The Android Open Source Project
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

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.Field;
import java.util.Arrays;

/** @hide */
public final class hentaiSpoofer {
    private static final String TAG = "hentaiSpoofer";

    // Default package names
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PROCESS_UNSTABLE = "com.google.android.gms.unstable";

    // Initialize the values we should cache
    private static volatile String[] sSpoofProps = null;
    private static volatile String[] sCertifiedProps = null;
    private static volatile String[] sProductSpoofProps = null;

    private static volatile boolean sIsSvt = false;
    private static volatile boolean sIsGms = false;
    private static volatile boolean sIsFinsky = false;
    private static volatile boolean sDevicePackageSpoof = false;

    // Spoofing blacklist
    private static final String[] PROCESSES_BLACKLISTED = {
        // Thermometer for guides
        "com.google.android.apps.pixel.health",
        // GMS Unstable (This cannot be spoofed because of PI)
        "com.google.android.gms.unstable",
        // Google Camera
        "com.google.android.GoogleCamera",
        "com.google.android.GoogleCameraEng",
        "com.google.android.apps.googlecamera.fishfood",
        // Pixel Camera Services
        "com.google.android.apps.camera.services",
    };

    // Spoof every google app
    private static final String[] PACKAGES_SPOOF = {
        // Every google app known to man
        "com.google.",
        // Play Store
        "com.android.vending",
    };

    // Product Spoofing
    private static final String[] PACKAGES_SPT = {
        // Google
        "com.google.android.googlequicksearchbox",
        // Photos
        "com.google.android.apps.photos",
        // Pixel Launcher
        "com.google.android.apps.nexuslauncher",
        // Wallpaper & style
        "com.google.android.apps.wallpaper",
        // Pixel Live Wallpaper
        "com.google.pixel.livewallpaper",
    };

    // Generic Build Proprieties list
    private static final String[] buildProperties = {
        "MODEL",
        "DEVICE",
        "PRODUCT",
        "BRAND",
        "MANUFACTURER",
        "FINGERPRINT",
        "TYPE",
        "TAGS"
    };

    private hentaiSpoofer() { }

    private static void setBuildField(String key, String value) {
        try {
            // Unlock
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);

            // Edit
            field.set(null, value);

            // Lock
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to spoof Build." + key, e);
        }
    }

    private static boolean isBlacklisted(String processName) {
        for (String blacklisted : PROCESSES_BLACKLISTED) {
            if (processName.startsWith(blacklisted)) {
                return true;
            }
        }
        return false;
    }

    private static boolean spoofPackage(String packageName, String processName, String[] spoofProcesses) {
        if (isBlacklisted(processName)) {
            return false;
        }

        for (String spoofProcess : spoofProcesses) {
            if (packageName.startsWith(spoofProcess)) {
                return true;
            }
        }
        return false;
    }

    // Spoof for device features
    private static void spoofProductPackages(Context context) {
        if (sProductSpoofProps == null) {
            sProductSpoofProps = hentaiResourceUtils.loadArrayFromResources(context, hentaiResourceUtils.PACKAGE_DEVICE, "buildProperties");
        }

        if (sProductSpoofProps.length > 0) {
            sDevicePackageSpoof = true;
            for (int i = 0; i < buildProperties.length && i < sProductSpoofProps.length; i++) {
                if (sProductSpoofProps[i] != null && !sProductSpoofProps[i].isEmpty()) {
                    setBuildField(buildProperties[i], sProductSpoofProps[i]);
                }
            }
        }
    }

    // Play Integrity
    private static void spoofGmsAttest(Context context) {
        if (sCertifiedProps == null) {
            sCertifiedProps = hentaiResourceUtils.loadArrayFromResources(context, hentaiResourceUtils.PACKAGE_DEVICE, "certifiedBuildProperties");
        }

        if (sCertifiedProps.length > 0) {
            sIsSvt = true;

            for (int i = 0; i < buildProperties.length && i < sCertifiedProps.length; i++) {
                if (sCertifiedProps[i] != null && !sCertifiedProps[i].isEmpty()) {
                    setBuildField(buildProperties[i], sCertifiedProps[i]);
                }
            }
        }
    }

    // Product Spoofing
    private static void spoofGms(Context context) {
        if (sSpoofProps == null) {
            sSpoofProps = hentaiResourceUtils.loadArrayFromResources(context, hentaiResourceUtils.PACKAGE_SPT, "buildProperties");
        }

        if (sSpoofProps.length > 0) {
            for (int i = 0; i < buildProperties.length && i < sSpoofProps.length; i++) {
                if (sSpoofProps[i] != null && !sSpoofProps[i].isEmpty()) {
                    setBuildField(buildProperties[i], sSpoofProps[i]);
                }
            }
        }
    }

    public static void initApplicationBeforeOnCreate(Context context) {
        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || processName == null) {
            return;
        }

        // Play Integrity
        if (packageName.equals(PACKAGE_GMS) &&
                processName.equals(PROCESS_UNSTABLE)) {
            sIsGms = true;
            spoofGmsAttest(context);
        }

        if (packageName.equals(PACKAGE_FINSKY)) {
            sIsFinsky = true;
        }

        // Device Spoofing
        if (spoofPackage(packageName, processName, PACKAGES_SPOOF)) {
            spoofProductPackages(context);
        }

        // Product Spoofing
        if (!sDevicePackageSpoof) {
            if (spoofPackage(packageName, processName, PACKAGES_SPT)) {
                spoofGms(context);
            }
        }
    }

    private static boolean isCallerSafetyNet() {
        return sIsGms && Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard"));
    }

    public static void onEngineGetCertificateChain() {
        // If a keybox is found, don't block key attestation
        if (KeyProviderManager.isKeyboxAvailable()) {
            Log.d(TAG, "Key attestation blocking is disabled because a keybox is present");
            return;
        }

        // Check stack for SafetyNet or Play Integrity
        if (sIsSvt && (isCallerSafetyNet() || sIsFinsky)) {
            Log.i(TAG, "Blocked key attestation sIsGms=" + sIsGms + " sIsFinsky=" + sIsFinsky);
            throw new UnsupportedOperationException();
        }
    }
}
