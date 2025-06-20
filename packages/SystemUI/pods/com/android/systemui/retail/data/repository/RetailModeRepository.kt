/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.systemui.retail.data.repository

import kotlinx.coroutines.flow.StateFlow

/** Repository to track if the device is in Retail mode */
public interface RetailModeRepository {
    /** Flow of whether the device is currently in retail mode. */
    public val retailMode: StateFlow<Boolean>

    /** Last value of whether the device is in retail mode. */
    public val inRetailMode: Boolean
        get() = retailMode.value
}
