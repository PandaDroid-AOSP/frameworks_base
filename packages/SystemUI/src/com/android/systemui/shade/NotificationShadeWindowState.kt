/*
 * Copyright (C) 2022 The Android Open Source Project
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

import com.android.systemui.common.buffer.RingBuffer
import com.android.systemui.dump.DumpsysTableLogger
import com.android.systemui.dump.Row
import com.android.systemui.shade.NotificationShadeWindowState.Buffer
import com.android.systemui.statusbar.StatusBarState

/**
 * Represents state of shade window, used by [NotificationShadeWindowControllerImpl]. Contains
 * nested class [Buffer] for pretty table logging in bug reports.
 */
class NotificationShadeWindowState(
    @JvmField var keyguardShowing: Boolean = false,
    @JvmField var keyguardOccluded: Boolean = false,
    @JvmField var keyguardNeedsInput: Boolean = false,
    @JvmField var panelVisible: Boolean = false,
    /** shade panel is expanded (expansion fraction > 0) */
    @JvmField var shadeOrQsExpanded: Boolean = false,
    @JvmField var notificationShadeFocusable: Boolean = false,
    @JvmField var bouncerShowing: Boolean = false,
    @JvmField var glanceableHubShowing: Boolean = false,
    @JvmField var glanceableHubOrientationAware: Boolean = false,
    @JvmField var keyguardFadingAway: Boolean = false,
    @JvmField var keyguardGoingAway: Boolean = false,
    @JvmField var qsExpanded: Boolean = false,
    @JvmField var headsUpNotificationShowing: Boolean = false,
    @JvmField var lightRevealScrimOpaque: Boolean = false,
    @JvmField var isSwitchingUsers: Boolean = false,
    @JvmField var forceWindowCollapsed: Boolean = false,
    @JvmField var forceDozeBrightness: Boolean = false,
    // TODO: forceUserActivity seems to be unused, delete?
    @JvmField var forceUserActivity: Boolean = false,
    @JvmField var launchingActivityFromNotification: Boolean = false,
    @JvmField var mediaBackdropShowing: Boolean = false,
    @JvmField var windowNotTouchable: Boolean = false,
    @JvmField var componentsForcingTopUi: MutableSet<String> = mutableSetOf(),
    @JvmField var forceOpenTokens: MutableSet<Any> = mutableSetOf(),
    /** one of [StatusBarState] */
    @JvmField var statusBarState: Int = 0,
    @JvmField var remoteInputActive: Boolean = false,
    @JvmField var forcePluginOpen: Boolean = false,
    @JvmField var dozing: Boolean = false,
    @JvmField var dreaming: Boolean = false,
    @JvmField var scrimsVisibility: Int = 0,
    @JvmField var backgroundBlurRadius: Int = 0,
    @JvmField var communalVisible: Boolean = false,
) {

    fun isKeyguardShowingAndNotOccluded(): Boolean {
        return keyguardShowing && !keyguardOccluded
    }

    fun isCommunalVisibleAndNotOccluded(): Boolean {
        return communalVisible && !keyguardOccluded
    }

    /** List of [String] to be used as a [Row] with [DumpsysTableLogger]. */
    val asStringList: List<String> by lazy {
        listOf(
            keyguardShowing.toString(),
            keyguardOccluded.toString(),
            keyguardNeedsInput.toString(),
            panelVisible.toString(),
            shadeOrQsExpanded.toString(),
            notificationShadeFocusable.toString(),
            bouncerShowing.toString(),
            glanceableHubShowing.toString(),
            glanceableHubOrientationAware.toString(),
            keyguardFadingAway.toString(),
            keyguardGoingAway.toString(),
            qsExpanded.toString(),
            headsUpNotificationShowing.toString(),
            lightRevealScrimOpaque.toString(),
            isSwitchingUsers.toString(),
            forceWindowCollapsed.toString(),
            forceDozeBrightness.toString(),
            forceUserActivity.toString(),
            launchingActivityFromNotification.toString(),
            mediaBackdropShowing.toString(),
            windowNotTouchable.toString(),
            componentsForcingTopUi.toString(),
            forceOpenTokens.toString(),
            StatusBarState.toString(statusBarState),
            remoteInputActive.toString(),
            forcePluginOpen.toString(),
            dozing.toString(),
            scrimsVisibility.toString(),
            backgroundBlurRadius.toString(),
            communalVisible.toString(),
        )
    }

    /**
     * [RingBuffer] to store [NotificationShadeWindowState]. After the buffer is full, it will
     * recycle old events.
     */
    class Buffer(capacity: Int) {

        private val buffer = RingBuffer(capacity) { NotificationShadeWindowState() }

        /** Insert a new element in the buffer. */
        fun insert(
            keyguardShowing: Boolean,
            keyguardOccluded: Boolean,
            keyguardNeedsInput: Boolean,
            panelVisible: Boolean,
            panelExpanded: Boolean,
            notificationShadeFocusable: Boolean,
            glanceableHubShowing: Boolean,
            glanceableHubOrientationAware: Boolean,
            bouncerShowing: Boolean,
            keyguardFadingAway: Boolean,
            keyguardGoingAway: Boolean,
            qsExpanded: Boolean,
            headsUpShowing: Boolean,
            lightRevealScrimOpaque: Boolean,
            isSwitchingUsers: Boolean,
            forceCollapsed: Boolean,
            forceDozeBrightness: Boolean,
            forceUserActivity: Boolean,
            launchingActivity: Boolean,
            backdropShowing: Boolean,
            notTouchable: Boolean,
            componentsForcingTopUi: MutableSet<String>,
            forceOpenTokens: MutableSet<Any>,
            statusBarState: Int,
            remoteInputActive: Boolean,
            forcePluginOpen: Boolean,
            dozing: Boolean,
            scrimsVisibility: Int,
            backgroundBlurRadius: Int,
            communalVisible: Boolean,
        ) {
            buffer.advance().apply {
                this.keyguardShowing = keyguardShowing
                this.keyguardOccluded = keyguardOccluded
                this.keyguardNeedsInput = keyguardNeedsInput
                this.panelVisible = panelVisible
                this.shadeOrQsExpanded = panelExpanded
                this.notificationShadeFocusable = notificationShadeFocusable
                this.glanceableHubShowing = glanceableHubShowing
                this.glanceableHubOrientationAware = glanceableHubOrientationAware
                this.bouncerShowing = bouncerShowing
                this.keyguardFadingAway = keyguardFadingAway
                this.keyguardGoingAway = keyguardGoingAway
                this.qsExpanded = qsExpanded
                this.headsUpNotificationShowing = headsUpShowing
                this.lightRevealScrimOpaque = lightRevealScrimOpaque
                this.isSwitchingUsers = isSwitchingUsers
                this.forceWindowCollapsed = forceCollapsed
                this.forceDozeBrightness = forceDozeBrightness
                this.forceUserActivity = forceUserActivity
                this.launchingActivityFromNotification = launchingActivity
                this.mediaBackdropShowing = backdropShowing
                this.windowNotTouchable = notTouchable
                this.componentsForcingTopUi.clear()
                this.componentsForcingTopUi.addAll(componentsForcingTopUi)
                this.forceOpenTokens.clear()
                this.forceOpenTokens.addAll(forceOpenTokens)
                this.statusBarState = statusBarState
                this.remoteInputActive = remoteInputActive
                this.forcePluginOpen = forcePluginOpen
                this.dozing = dozing
                this.scrimsVisibility = scrimsVisibility
                this.backgroundBlurRadius = backgroundBlurRadius
                this.communalVisible = communalVisible
            }
        }

        /**
         * Returns the content of the buffer (sorted from latest to newest).
         *
         * @see [NotificationShadeWindowState.asStringList]
         */
        fun toList(): List<Row> {
            return buffer.map { it.asStringList }
        }
    }

    companion object {
        /** Headers for dumping a table using [DumpsysTableLogger]. */
        @JvmField
        val TABLE_HEADERS =
            listOf(
                "keyguardShowing",
                "keyguardOccluded",
                "keyguardNeedsInput",
                "panelVisible",
                "panelExpanded",
                "notificationShadeFocusable",
                "glanceableHubShowing",
                "glanceableHubOrientationAware",
                "bouncerShowing",
                "keyguardFadingAway",
                "keyguardGoingAway",
                "qsExpanded",
                "headsUpShowing",
                "lightRevealScrimOpaque",
                "isSwitchingUsers",
                "forceCollapsed",
                "forceDozeBrightness",
                "forceUserActivity",
                "launchingActivity",
                "backdropShowing",
                "notTouchable",
                "componentsForcingTopUi",
                "forceOpenTokens",
                "statusBarState",
                "remoteInputActive",
                "forcePluginOpen",
                "dozing",
                "scrimsVisibility",
                "backgroundBlurRadius",
                "communalVisible",
            )
    }
}
