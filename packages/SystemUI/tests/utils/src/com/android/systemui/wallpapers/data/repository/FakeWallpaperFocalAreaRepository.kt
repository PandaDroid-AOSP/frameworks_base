/*
 * Copyright (C) 2025 The Android Open Source Project
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

package com.android.systemui.wallpapers.data.repository

import android.graphics.PointF
import android.graphics.RectF
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class FakeWallpaperFocalAreaRepository : WallpaperFocalAreaRepository {
    private val _shortcutAbsoluteTop = MutableStateFlow(0F)
    override val shortcutAbsoluteTop = _shortcutAbsoluteTop.asStateFlow()

    private val _notificationStackAbsoluteBottom = MutableStateFlow(0F)
    override val notificationStackAbsoluteBottom = _notificationStackAbsoluteBottom.asStateFlow()

    private val _wallpaperFocalAreaBounds = MutableStateFlow(RectF(0F, 0F, 0F, 0F))
    override val wallpaperFocalAreaBounds: StateFlow<RectF> =
        _wallpaperFocalAreaBounds.asStateFlow()

    private val _wallpaperFocalAreaTapPosition = MutableStateFlow(PointF(0F, 0F))
    val wallpaperFocalAreaTapPosition: StateFlow<PointF> =
        _wallpaperFocalAreaTapPosition.asStateFlow()

    private val _notificationDefaultTop = MutableStateFlow(0F)
    override val notificationDefaultTop: StateFlow<Float> = _notificationDefaultTop.asStateFlow()

    private val _hasFocalArea = MutableStateFlow(false)
    override val hasFocalArea: StateFlow<Boolean> = _hasFocalArea.asStateFlow()

    override fun setShortcutAbsoluteTop(top: Float) {
        _shortcutAbsoluteTop.value = top
    }

    override fun setNotificationStackAbsoluteBottom(bottom: Float) {
        _notificationStackAbsoluteBottom.value = bottom
    }

    override fun setNotificationDefaultTop(top: Float) {
        _notificationDefaultTop.value = top
    }

    override fun setWallpaperFocalAreaBounds(bounds: RectF) {
        _wallpaperFocalAreaBounds.value = bounds
    }

    override fun setTapPosition(tapPosition: PointF) {
        _wallpaperFocalAreaTapPosition.value = tapPosition
    }
}
