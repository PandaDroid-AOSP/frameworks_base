/*
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

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.util.Log;

public final class hentaiResourceUtils {
    private static final String TAG = "hentaiResourceUtils";

    // Common package names we use
    public static final String PACKAGE_SPT = "com.helluva.product.spt";
    public static final String PACKAGE_DEVICE = "com.helluva.product.device";
    public static final String PACKAGE_SECRET = "com.helluva.product.secret";

    public static String[] loadArrayFromResources(Context context, String appName, String arrayName) {
        PackageManager pm = context.getPackageManager();

        try {
            Resources resources = pm.getResourcesForApplication(appName);
            int resourceId = resources.getIdentifier(arrayName, "array", appName);

            if (resourceId != 0) {
                return resources.getStringArray(resourceId);
            } else {
                Log.d(TAG, "Resource ID is not found");
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.i(TAG, "Error accessing resources for '" + appName + "': " + e.getMessage());
            return new String[0];
        }

        return new String[0];
    }
}
