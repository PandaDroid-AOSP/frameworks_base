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

package com.android.systemui.statusbar.notification.headsup

import com.android.systemui.log.LogBuffer
import com.android.systemui.log.core.LogLevel.INFO
import com.android.systemui.log.core.LogLevel.VERBOSE
import com.android.systemui.log.dagger.NotificationHeadsUpLog
import com.android.systemui.statusbar.notification.collection.NotificationEntry
import com.android.systemui.statusbar.notification.logKey
import javax.inject.Inject

/** Logger for [HeadsUpManager]. */
class HeadsUpManagerLogger
@Inject
constructor(@NotificationHeadsUpLog private val buffer: LogBuffer) {
    fun logPackageSnoozed(snoozeKey: String) {
        buffer.log(TAG, INFO, { str1 = snoozeKey }, { "package snoozed $str1" })
    }

    fun logPackageUnsnoozed(snoozeKey: String) {
        buffer.log(TAG, INFO, { str1 = snoozeKey }, { "package unsnoozed $str1" })
    }

    fun logIsSnoozedReturned(snoozeKey: String) {
        buffer.log(TAG, INFO, { str1 = snoozeKey }, { "package snoozed when queried $str1" })
    }

    fun logReleaseAllImmediately() {
        buffer.log(TAG, INFO, {}, { "release all immediately" })
    }

    fun logShowNotificationRequest(entry: NotificationEntry, isPinnedByUser: Boolean) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry.logKey
                bool1 = isPinnedByUser
            },
            { "request: show notification $str1. isPinnedByUser=$bool1" },
        )
    }

    fun logAvalancheUpdate(
        caller: String,
        isEnabled: Boolean,
        notifEntryKey: String,
        outcome: String,
    ) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = caller
                str2 = notifEntryKey
                str3 = outcome
                bool1 = isEnabled
            },
            { "$str1\n=> AC[enabled:$bool1] update: $str2\n=> $str3" },
        )
    }

    fun logAvalancheDelete(
        caller: String,
        isEnabled: Boolean,
        notifEntryKey: String,
        outcome: String,
    ) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = caller
                str2 = notifEntryKey
                str3 = outcome
                bool1 = isEnabled
            },
            { "$str1\n=> AC[enabled:$bool1] delete: $str2\n=> $str3" },
        )
    }

    fun logAvalancheStage(stage: String, key: String) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = stage
                str2 = key
            },
            { "[AC] $str1 $str2" },
        )
    }

    fun logAvalancheDuration(
        thisKey: String,
        duration: RemainingDuration,
        reason: String,
        nextKey: String,
    ) {
        val durationMs =
            when (duration) {
                is RemainingDuration.UpdatedDuration -> duration.duration
                is RemainingDuration.HideImmediately -> 0
            }
        buffer.log(
            TAG,
            INFO,
            {
                str1 = thisKey
                int1 = durationMs
                str2 = reason
                str3 = nextKey
            },
            { "[AC] $str1 | $int1 ms | $str2 $str3" },
        )
    }

    fun logShowNotification(entry: NotificationEntry, isPinnedByUser: Boolean) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry.logKey
                bool1 = isPinnedByUser
            },
            { "show notification $str1. isPinnedByUser=$bool1" },
        )
    }

    fun logAutoRemoveScheduled(entry: NotificationEntry, delayMillis: Long, reason: String) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry.logKey
                long1 = delayMillis
                str2 = reason
            },
            { "schedule auto remove of $str1 in $long1 ms reason: $str2" },
        )
    }

    fun logAutoRemoveRequest(entry: NotificationEntry, reason: String) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry.logKey
                str2 = reason
            },
            { "request: reschedule auto remove of $str1 reason: $str2" },
        )
    }

    fun logAutoRemoveRescheduled(entry: NotificationEntry, delayMillis: Long, reason: String) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry.logKey
                long1 = delayMillis
                str2 = reason
            },
            { "reschedule auto remove of $str1 in $long1 ms reason: $str2" },
        )
    }

    fun logAutoRemoveCancelRequest(entry: NotificationEntry, reason: String?) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry.logKey
                str2 = reason ?: "unknown"
            },
            { "request: cancel auto remove of $str1 reason: $str2" },
        )
    }

    fun logAutoRemoveCanceled(entry: NotificationEntry?, reason: String?) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry?.logKey
                str2 = reason ?: "unknown"
            },
            { "cancel auto remove of $str1 reason: $str2" },
        )
    }

    fun logRemoveEntryRequest(key: String, reason: String, isWaiting: Boolean) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = logKey(key)
                str2 = reason
                bool1 = isWaiting
            },
            { "request: $str2 => remove entry $str1 isWaiting: $isWaiting" },
        )
    }

    fun logRemoveEntry(key: String, reason: String, isWaiting: Boolean) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = logKey(key)
                str2 = reason
                bool1 = isWaiting
            },
            { "$str2 => remove entry $str1 isWaiting: $isWaiting" },
        )
    }

    fun logUnpinEntryRequest(key: String) {
        buffer.log(TAG, INFO, { str1 = logKey(key) }, { "request: unpin entry $str1" })
    }

    fun logUnpinEntry(key: String) {
        buffer.log(TAG, INFO, { str1 = logKey(key) }, { "unpin entry $str1" })
    }

    fun logRemoveNotification(
        key: String,
        releaseImmediately: Boolean,
        isWaiting: Boolean,
        reason: String,
    ) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = logKey(key)
                bool1 = releaseImmediately
                bool2 = isWaiting
                str2 = reason
            },
            {
                "remove notification $str1 releaseImmediately: $bool1 isWaiting: $bool2 " +
                    "reason: $str2"
            },
        )
    }

    fun logNullEntry(key: String, reason: String) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = logKey(key)
                str2 = reason
            },
            { "remove notification $str1 when headsUpEntry is null, reason: $str2" },
        )
    }

    fun logNotificationActuallyRemoved(entry: NotificationEntry) {
        buffer.log(TAG, INFO, { str1 = entry.logKey }, { "notification removed $str1 " })
    }

    fun logUpdateNotificationRequest(
        key: String,
        requestedPinnedStatus: PinnedStatus,
        hasEntry: Boolean,
    ) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = logKey(key)
                bool1 = hasEntry
                str2 = requestedPinnedStatus.name
            },
            { "request: update notification $str1. hasEntry: $bool1. requestedPinnedStatus: $str2" },
        )
    }

    fun logUpdateNotification(key: String, requestedPinnedStatus: PinnedStatus, hasEntry: Boolean) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = logKey(key)
                bool1 = hasEntry
                str2 = requestedPinnedStatus.name
            },
            { "update notification $str1. hasEntry: $bool2. requestedPinnedStatus: $str2" },
        )
    }

    fun logUpdateEntry(entry: NotificationEntry, updatePostTime: Boolean, reason: String?) {
        buffer.log(
            TAG,
            INFO,
            {
                str1 = entry.logKey
                bool1 = updatePostTime
                str2 = reason ?: "unknown"
            },
            { "update entry $str1 updatePostTime: $bool1 reason: $str2" },
        )
    }

    fun logSnoozeLengthChange(packageSnoozeLengthMs: Int) {
        buffer.log(
            TAG,
            INFO,
            { int1 = packageSnoozeLengthMs },
            { "snooze length changed: ${int1}ms" },
        )
    }

    fun logSetEntryPinned(entry: NotificationEntry, pinnedStatus: PinnedStatus, reason: String) {
        buffer.log(
            TAG,
            VERBOSE,
            {
                str1 = entry.logKey
                str2 = reason
                str3 = pinnedStatus.name
            },
            { "$str2 => set entry pinned $str1 pinned: $str3" },
        )
    }

    fun logUpdatePinnedMode(
        hasPinnedNotification: Boolean,
        pinnedNotificationStatus: PinnedStatus,
    ) {
        buffer.log(
            TAG,
            INFO,
            {
                bool1 = hasPinnedNotification
                str1 = pinnedNotificationStatus.name
            },
            { "has pinned notification changed to $bool1, status=$str1" },
        )
    }

    fun logRemoveEntryAfterExpand(entry: NotificationEntry) {
        buffer.log(TAG, VERBOSE, { str1 = entry.logKey }, { "remove entry after expand: $str1" })
    }

    fun logDroppedHuns(entryList: String) {
        buffer.log(TAG, VERBOSE, { str1 = entryList }, { "[AC] dropped:\n $str1" })
    }
}

private const val TAG = "HeadsUpManager"
