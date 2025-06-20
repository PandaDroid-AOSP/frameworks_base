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

package com.android.systemui.shade

import android.content.Context
import android.view.GestureDetector
import android.view.GestureDetector.SimpleOnGestureListener
import android.view.MotionEvent
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Main
import javax.inject.Inject

/** Accepts touch events, detects long press, and calls ShadeViewController#onStatusBarLongPress. */
@SysUISingleton
class StatusBarLongPressGestureDetector
@Inject
constructor(
    // TODO b/383125226 - Make this class per-display
    @Main context: Context,
    val shadeViewController: ShadeViewController,
) {
    val gestureDetector =
        GestureDetector(
            context,
            object : SimpleOnGestureListener() {
                override fun onLongPress(event: MotionEvent) {
                    shadeViewController.onStatusBarLongPress(event)
                }
            },
        )

    /** Accepts touch events to detect long presses. */
    fun handleTouch(ev: MotionEvent) {
        gestureDetector.onTouchEvent(ev)
    }
}
