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

package com.android.systemui.statusbar.notification.stack

import android.util.IndentingPrintWriter
import com.android.systemui.statusbar.notification.stack.shared.model.AccessibilityScrollEvent
import com.android.systemui.statusbar.notification.stack.shared.model.ShadeScrimShape
import com.android.systemui.statusbar.notification.stack.shared.model.ShadeScrollState
import com.android.systemui.util.printSection
import com.android.systemui.util.println
import java.util.function.Consumer

/**
 * This is a state holder object used by [NSSL][NotificationStackScrollLayout] to contain states
 * provided by the `NotificationScrollViewBinder` to the `NotificationScrollView`.
 *
 * Unlike AmbientState, no class other than NSSL should ever have access to this class in any way.
 * These fields are effectively NSSL's private fields.
 */
class ScrollViewFields {
    /** Used to produce the clipping path */
    var clippingShape: ShadeScrimShape? = null

    /** Used to produce a negative clipping path */
    var negativeClippingShape: ShadeScrimShape? = null

    /** Scroll state of the notification shade. */
    var scrollState: ShadeScrollState = ShadeScrollState()

    /**
     * Height in view pixels at which the Notification Stack would like to be laid out, including
     * Notification rows, paddings the Shelf and the Footer.
     */
    var intrinsicStackHeight: Int = 0

    /**
     * When internal NSSL expansion requires the stack to be scrolled (e.g. to keep an expanding
     * notification in view), that scroll amount can be sent here and it will be handled by the
     * placeholder
     */
    var syntheticScrollConsumer: Consumer<Float>? = null

    /**
     * When the NSSL navigates through the notifications with TalkBack, it can send scroll events
     * here, to be able to browse through the whole list of notifications in the shade.
     */
    var accessibilityScrollEventConsumer: Consumer<AccessibilityScrollEvent>? = null

    /**
     * When a gesture is consumed internally by NSSL but needs to be handled by other elements (such
     * as the notif scrim) as overscroll, we can notify the placeholder through here.
     */
    var currentGestureOverscrollConsumer: Consumer<Boolean>? = null
    /**
     * When a gesture is on open notification guts, which means scene container should not close the
     * guts off of this gesture, we can notify the placeholder through here.
     */
    var currentGestureInGutsConsumer: Consumer<Boolean>? = null

    /**
     * When a notification begins remote input, its bottom Y bound is sent to the placeholder
     * through here in order to adjust to accommodate the IME.
     */
    var remoteInputRowBottomBoundConsumer: Consumer<Float?>? = null

    /** send the [syntheticScroll] to the [syntheticScrollConsumer], if present. */
    fun sendSyntheticScroll(syntheticScroll: Float) =
        syntheticScrollConsumer?.accept(syntheticScroll)

    /** send [isCurrentGestureOverscroll] to the [currentGestureOverscrollConsumer], if present. */
    fun sendCurrentGestureOverscroll(isCurrentGestureOverscroll: Boolean) =
        currentGestureOverscrollConsumer?.accept(isCurrentGestureOverscroll)

    /** send [isCurrentGestureInGuts] to the [currentGestureInGutsConsumer], if present. */
    fun sendCurrentGestureInGuts(isCurrentGestureInGuts: Boolean) =
        currentGestureInGutsConsumer?.accept(isCurrentGestureInGuts)

    /** send [bottomY] to the [remoteInputRowBottomBoundConsumer], if present. */
    fun sendRemoteInputRowBottomBound(bottomY: Float?) =
        remoteInputRowBottomBoundConsumer?.accept(bottomY)

    /** send an [AccessibilityScrollEvent] to the [accessibilityScrollEventConsumer] if present */
    fun sendAccessibilityScrollEvent(event: AccessibilityScrollEvent) {
        accessibilityScrollEventConsumer?.accept(event)
    }

    fun dump(pw: IndentingPrintWriter) {
        pw.printSection("StackViewStates") {
            pw.println("scrimClippingShape", clippingShape)
            pw.println("negativeClippingShape", negativeClippingShape)
            pw.println("scrollState", scrollState)
        }
    }
}
