/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.systemui.statusbar

import android.app.PendingIntent
import com.android.systemui.log.dagger.NotifInteractionLog
import com.android.systemui.log.LogBuffer
import com.android.systemui.log.core.LogLevel
import com.android.systemui.statusbar.notification.collection.NotificationEntry
import javax.inject.Inject

/**
 * Logger class for events related to the user clicking on notification actions
 */
class ActionClickLogger @Inject constructor(
    @NotifInteractionLog private val buffer: LogBuffer
) {
    fun logInitialClick(
        entry: String?,
        index: Integer?,
        pendingIntent: PendingIntent
    ) {
        buffer.log(TAG, LogLevel.DEBUG, {
            str1 = entry
            str3 = pendingIntent.toString()
            int1 = index?.toInt() ?: Int.MIN_VALUE
        }, {
            "ACTION CLICK $str1 for pending intent $str3 at index $int1"
        })
    }

    fun logRemoteInputWasHandled(
        entry: String?,
        index: Int?
    ) {
        buffer.log(TAG, LogLevel.DEBUG, {
            str1 = entry
            int1 = index ?: Int.MIN_VALUE
        }, {
            "  [Action click] Triggered remote input (for $str1) at index $int1"
        })
    }

    fun logStartingIntentWithDefaultHandler(
        entry: String?,
        pendingIntent: PendingIntent,
        index: Int?
    ) {
        buffer.log(TAG, LogLevel.DEBUG, {
            str1 = entry
            str2 = pendingIntent.toString()
            int1 = index ?: Int.MIN_VALUE
        }, {
            "  [Action click] Launching intent $str2 via default handler (for $str1 at index $int1)"
        })
    }

    fun logWaitingToCloseKeyguard(
        pendingIntent: PendingIntent,
        index: Int?
    ) {
        buffer.log(TAG, LogLevel.DEBUG, {
            str1 = pendingIntent.toString()
            int1 = index ?: Int.MIN_VALUE
        }, {
            "  [Action click] Intent $str1 at index $int1 launches an activity, dismissing " +
                    "keyguard first..."
        })
    }

    fun logKeyguardGone(
        pendingIntent: PendingIntent,
        index: Int?
    ) {
        buffer.log(TAG, LogLevel.DEBUG, {
            str1 = pendingIntent.toString()
            int1 = index ?: Int.MIN_VALUE
        }, {
            "  [Action click] Keyguard dismissed, calling default handler for intent $str1 at " +
                    "index $int1"
        })
    }
}

private const val TAG = "ActionClickLogger"