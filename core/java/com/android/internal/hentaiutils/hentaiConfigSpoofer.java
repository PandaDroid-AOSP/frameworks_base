/*
 * Copyright (C) 2024 The hentaiOS Project and its Proprietors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.hentaiutils;

import android.content.res.Resources;
import android.content.Context;
import android.util.Log;
import java.util.Arrays;

public final class hentaiConfigSpoofer {
    private static final String TAG = "hentaiConfigSpoofer";

    private hentaiConfigSpoofer() { }

    private static String[] getDeviceConfigsOverride(Context context) {
        return hentaiResourceUtils.loadArrayFromResources(context, hentaiResourceUtils.PACKAGE_SPT, "deviceConfig");
    }

    public static String setOverriddenValue(Context context, String namespace, String name) {
        for (String p : getDeviceConfigsOverride(context)) {
            String[] kv = p.split("=");
            String fullKey = kv[0];
            String[] nsKey = fullKey.split("/");
            if (nsKey.length == 2 && nsKey[0].equals(namespace) && nsKey[1].equals(name)) {
                return kv[1];
            }
        }
        return null;
    }
}
