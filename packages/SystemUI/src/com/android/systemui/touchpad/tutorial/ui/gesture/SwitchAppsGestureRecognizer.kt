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

package com.android.systemui.touchpad.tutorial.ui.gesture

import android.util.MathUtils
import android.view.MotionEvent
import com.android.systemui.touchpad.tutorial.ui.gesture.GestureState.InProgress

/** Recognizes Quickswitch gesture i.e. using four fingers on touchpad, swiping to right. */
class SwitchAppsGestureRecognizer(private val gestureDistanceThresholdPx: Int) : GestureRecognizer {

    private val distanceTracker = DistanceTracker()
    private var gestureStateChangedCallback: (GestureState) -> Unit = {}

    override fun addGestureStateCallback(callback: (GestureState) -> Unit) {
        gestureStateChangedCallback = callback
    }

    override fun clearGestureStateCallback() {
        gestureStateChangedCallback = {}
    }

    override fun accept(event: MotionEvent) {
        if (!isMultifingerTouchpadSwipe(event)) return
        if (!isFourFingerTouchpadSwipe(event)) {
            if (event.actionMasked == MotionEvent.ACTION_UP) {
                gestureStateChangedCallback(GestureState.Error)
            }
            return
        }
        val gestureState = distanceTracker.processEvent(event)
        updateGestureState(
            gestureStateChangedCallback,
            gestureState,
            isFinished = { it.deltaX >= gestureDistanceThresholdPx },
            progress = { InProgress(MathUtils.saturate(it.deltaX / gestureDistanceThresholdPx)) },
        )
    }
}
