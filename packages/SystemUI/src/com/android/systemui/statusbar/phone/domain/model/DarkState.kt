/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.systemui.statusbar.phone.domain.model

import android.graphics.Rect

/** Dark mode visual states. */
data class DarkState(
    /** Areas on screen that require a dark-mode adjustment. */
    val areas: Collection<Rect>,
    /** Tint color to apply to UI elements that fall within [areas]. */
    val tint: Int,
    /** _How_ dark the area is. Less than 0.5 is dark, otherwise light */
    val darkIntensity: Float,
)
