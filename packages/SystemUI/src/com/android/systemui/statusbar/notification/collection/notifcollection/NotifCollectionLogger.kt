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

package com.android.systemui.statusbar.notification.collection.notifcollection

import android.os.RemoteException
import android.service.notification.NotificationListenerService
import android.service.notification.NotificationListenerService.RankingMap
import android.service.notification.StatusBarNotification
import com.android.systemui.log.dagger.NotificationLog
import com.android.systemui.log.LogBuffer
import com.android.systemui.log.core.LogLevel.DEBUG
import com.android.systemui.log.core.LogLevel.ERROR
import com.android.systemui.log.core.LogLevel.INFO
import com.android.systemui.log.core.LogLevel.WARNING
import com.android.systemui.log.core.LogLevel.WTF
import com.android.systemui.statusbar.notification.collection.GroupEntry
import com.android.systemui.statusbar.notification.collection.NotifCollection
import com.android.systemui.statusbar.notification.collection.NotifCollection.CancellationReason
import com.android.systemui.statusbar.notification.collection.NotifCollection.FutureDismissal
import com.android.systemui.statusbar.notification.collection.NotificationEntry
import com.android.systemui.statusbar.notification.logKey
import javax.inject.Inject

fun cancellationReasonDebugString(@CancellationReason reason: Int) =
    "$reason:" + when (reason) {
        -1 -> "REASON_NOT_CANCELED" // NotifCollection.REASON_NOT_CANCELED
        NotifCollection.REASON_UNKNOWN -> "REASON_UNKNOWN"
        NotificationListenerService.REASON_CLICK -> "REASON_CLICK"
        NotificationListenerService.REASON_CANCEL -> "REASON_CANCEL"
        NotificationListenerService.REASON_CANCEL_ALL -> "REASON_CANCEL_ALL"
        NotificationListenerService.REASON_ERROR -> "REASON_ERROR"
        NotificationListenerService.REASON_PACKAGE_CHANGED -> "REASON_PACKAGE_CHANGED"
        NotificationListenerService.REASON_USER_STOPPED -> "REASON_USER_STOPPED"
        NotificationListenerService.REASON_PACKAGE_BANNED -> "REASON_PACKAGE_BANNED"
        NotificationListenerService.REASON_APP_CANCEL -> "REASON_APP_CANCEL"
        NotificationListenerService.REASON_APP_CANCEL_ALL -> "REASON_APP_CANCEL_ALL"
        NotificationListenerService.REASON_LISTENER_CANCEL -> "REASON_LISTENER_CANCEL"
        NotificationListenerService.REASON_LISTENER_CANCEL_ALL -> "REASON_LISTENER_CANCEL_ALL"
        NotificationListenerService.REASON_GROUP_SUMMARY_CANCELED -> "REASON_GROUP_SUMMARY_CANCELED"
        NotificationListenerService.REASON_GROUP_OPTIMIZATION -> "REASON_GROUP_OPTIMIZATION"
        NotificationListenerService.REASON_PACKAGE_SUSPENDED -> "REASON_PACKAGE_SUSPENDED"
        NotificationListenerService.REASON_PROFILE_TURNED_OFF -> "REASON_PROFILE_TURNED_OFF"
        NotificationListenerService.REASON_UNAUTOBUNDLED -> "REASON_UNAUTOBUNDLED"
        NotificationListenerService.REASON_CHANNEL_BANNED -> "REASON_CHANNEL_BANNED"
        NotificationListenerService.REASON_SNOOZED -> "REASON_SNOOZED"
        NotificationListenerService.REASON_TIMEOUT -> "REASON_TIMEOUT"
        NotificationListenerService.REASON_CHANNEL_REMOVED -> "REASON_CHANNEL_REMOVED"
        NotificationListenerService.REASON_CLEAR_DATA -> "REASON_CLEAR_DATA"
        NotificationListenerService.REASON_ASSISTANT_CANCEL -> "REASON_ASSISTANT_CANCEL"
        else -> "unknown"
    }

class NotifCollectionLogger @Inject constructor(
    @NotificationLog private val buffer: LogBuffer
) {
    fun logNotifPosted(entry: NotificationEntry) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
        }, {
            "POSTED $str1"
        })
    }

    fun logNotifGroupPosted(groupKey: String, batchSize: Int) {
        buffer.log(TAG, INFO, {
            str1 = logKey(groupKey)
            int1 = batchSize
        }, {
            "POSTED GROUP $str1 ($int1 events)"
        })
    }

    fun logNotifUpdated(entry: NotificationEntry) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
        }, {
            "UPDATED $str1"
        })
    }

    fun logNotifRemoved(sbn: StatusBarNotification, @CancellationReason reason: Int) {
        buffer.log(TAG, INFO, {
            str1 = sbn.logKey
            int1 = reason
        }, {
            "REMOVED $str1 reason=${cancellationReasonDebugString(int1)}"
        })
    }

    fun logNotifReleased(entry: NotificationEntry) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
        }, {
            "RELEASED $str1"
        })
    }

    fun logLocallyDismissed(entry: NotificationEntry, index: Int, count: Int) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            int1 = index
            int2 = count
        }, {
            "LOCALLY DISMISSED $str1 ($int1/$int2)"
        })
    }

    fun logDismissNonExistentNotif(entryKey: String, index: Int, count: Int) {
        buffer.log(TAG, INFO, {
            str1 = logKey(entryKey)
            int1 = index
            int2 = count
        }, {
            "DISMISS Non Existent $str1 ($int1/$int2)"
        })
    }

    fun logLocallyDismissedChild(
            child: NotificationEntry,
            parent: NotificationEntry,
            parentIndex: Int,
            parentCount: Int
    ) {
        buffer.log(TAG, DEBUG, {
            str1 = child.logKey
            str2 = parent.logKey
            int1 = parentIndex
            int2 = parentCount
        }, {
            "LOCALLY DISMISSED CHILD (inferred): $str1 of parent $str2 ($int1/$int2)"
        })
    }

    fun logDismissAll(userId: Int) {
        buffer.log(TAG, INFO, {
            int1 = userId
        }, {
            "DISMISS ALL notifications for user $int1"
        })
    }

    fun logLocallyDismissedAlreadyCanceledEntry(entry: NotificationEntry) {
        buffer.log(TAG, DEBUG, {
            str1 = entry.logKey
        }, {
            "LOCALLY DISMISSED Already Canceled $str1. Trying to remove."
        })
    }

    fun logNotifDismissedIntercepted(entry: NotificationEntry, index: Int, count: Int) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            int1 = index
            int2 = count
        }, {
            "DISMISS INTERCEPTED $str1 ($int1/$int2)"
        })
    }

    fun logNotifClearAllDismissalIntercepted(entry: NotificationEntry, index: Int, count: Int) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            int1 = index
            int2 = count
        }, {
            "CLEAR ALL DISMISSAL INTERCEPTED $str1 ($int1/$int2)"
        })
    }

    fun logNotifInternalUpdate(entry: NotificationEntry, name: String, reason: String) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            str2 = name
            str3 = reason
        }, {
            "UPDATED INTERNALLY $str1 BY $str2 BECAUSE $str3"
        })
    }

    fun logNotifInternalUpdateFailed(sbn: StatusBarNotification, name: String, reason: String) {
        buffer.log(TAG, INFO, {
            str1 = sbn.logKey
            str2 = name
            str3 = reason
        }, {
            "FAILED INTERNAL UPDATE $str1 BY $str2 BECAUSE $str3"
        })
    }

    fun logNoNotificationToRemoveWithKey(
        sbn: StatusBarNotification,
        @CancellationReason reason: Int
    ) {
        buffer.log(TAG, ERROR, {
            str1 = sbn.logKey
            int1 = reason
        }, {
            "No notification to remove with key $str1 reason=${cancellationReasonDebugString(int1)}"
        })
    }

    fun logMissingRankings(
        newlyInconsistentEntries: List<NotificationEntry>,
        totalInconsistent: Int,
        rankingMap: RankingMap
    ) {
        buffer.log(TAG, WARNING, {
            int1 = totalInconsistent
            int2 = newlyInconsistentEntries.size
            str1 = newlyInconsistentEntries.joinToString { it.logKey ?: "null" }
        }, {
            "Ranking update is missing ranking for $int1 entries ($int2 new): $str1"
        })
        buffer.log(TAG, DEBUG, {
            str1 = rankingMap.orderedKeys.map { logKey(it) ?: "null" }.toString()
        }, {
            "Ranking map contents: $str1"
        })
    }

    fun logRecoveredRankings(newlyConsistentKeys: List<String>, totalInconsistent: Int) {
        buffer.log(TAG, INFO, {
            int1 = totalInconsistent
            int1 = newlyConsistentKeys.size
            str1 = newlyConsistentKeys.joinToString { logKey(it) ?: "null" }
        }, {
            "Ranking update now contains rankings for $int1 previously inconsistent entries: $str1"
        })
    }

    fun logMissingNotifications(
        newlyMissingKeys: List<String>,
        totalMissing: Int,
    ) {
        buffer.log(TAG, WARNING, {
            int1 = totalMissing
            int2 = newlyMissingKeys.size
            str1 = newlyMissingKeys.joinToString { logKey(it) ?: "null" }
        }, {
            "Collection missing $int1 entries in ranking update. Just lost $int2: $str1"
        })
    }

    fun logFoundNotifications(
        newlyFoundKeys: List<String>,
        totalMissing: Int,
    ) {
        buffer.log(TAG, INFO, {
            int1 = totalMissing
            int2 = newlyFoundKeys.size
            str1 = newlyFoundKeys.joinToString { logKey(it) ?: "null" }
        }, {
            "Collection missing $int1 entries in ranking update. Just found $int2: $str1"
        })
    }

    fun logRemoteExceptionOnNotificationClear(
            entry: NotificationEntry,
            index: Int,
            count: Int,
            e: RemoteException
    ) {
        buffer.log(TAG, WTF, {
            str1 = entry.logKey
            int1 = index
            int2 = count
            str2 = e.toString()
        }, {
            "RemoteException while attempting to clear $str1 ($int1/$int2):\n$str2"
        })
    }

    fun logRemoteExceptionOnClearAllNotifications(e: RemoteException) {
        buffer.log(TAG, WTF, {
            str1 = e.toString()
        }, {
            "RemoteException while attempting to clear all notifications:\n$str1"
        })
    }

    fun logLifetimeExtended(entry: NotificationEntry, extender: NotifLifetimeExtender) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            str2 = extender.name
        }, {
            "LIFETIME EXTENDED: $str1 by $str2"
        })
    }

    fun logLifetimeExtensionEnded(
        entry: NotificationEntry,
        extender: NotifLifetimeExtender,
        totalExtenders: Int
    ) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            str2 = extender.name
            int1 = totalExtenders
        }, {
            "LIFETIME EXTENSION ENDED for $str1 by '$str2'; $int1 remaining extensions"
        })
    }

    fun logIgnoredError(message: String?) {
        buffer.log(TAG, ERROR, {
            str1 = message
        }, {
            "ERROR suppressed due to initialization forgiveness: $str1"
        })
    }

    fun logEntryBeingExtendedNotInCollection(
        entry: NotificationEntry,
        extender: NotifLifetimeExtender,
        collectionEntryIs: String
    ) {
        buffer.log(TAG, WARNING, {
            str1 = entry.logKey
            str2 = extender.name
            str3 = collectionEntryIs
        }, {
            "While ending lifetime extension by $str2 of $str1, entry in collection is $str3"
        })
    }

    fun logFutureDismissalReused(dismissal: FutureDismissal) {
        buffer.log(TAG, INFO, {
            str1 = dismissal.label
        }, {
            "Reusing existing registration: $str1"
        })
    }

    fun logFutureDismissalRegistered(dismissal: FutureDismissal) {
        buffer.log(TAG, DEBUG, {
            str1 = dismissal.label
        }, {
            "Registered: $str1"
        })
    }

    fun logFutureDismissalDoubleCancelledByServer(dismissal: FutureDismissal) {
        buffer.log(TAG, WARNING, {
            str1 = dismissal.label
        }, {
            "System server double cancelled: $str1"
        })
    }

    fun logFutureDismissalDoubleRun(dismissal: FutureDismissal) {
        buffer.log(TAG, WARNING, {
            str1 = dismissal.label
        }, {
            "Double run: $str1"
        })
    }

    fun logFutureDismissalAlreadyCancelledByServer(dismissal: FutureDismissal) {
        buffer.log(TAG, DEBUG, {
            str1 = dismissal.label
        }, {
            "Ignoring: entry already cancelled by server: $str1"
        })
    }

    fun logFutureDismissalGotSystemServerCancel(
        dismissal: FutureDismissal,
        @CancellationReason cancellationReason: Int
    ) {
        buffer.log(TAG, DEBUG, {
            str1 = dismissal.label
            int1 = cancellationReason
        }, {
            "SystemServer cancelled: $str1 reason=${cancellationReasonDebugString(int1)}"
        })
    }

    fun logFutureDismissalDismissing(dismissal: FutureDismissal, type: String) {
        buffer.log(TAG, DEBUG, {
            str1 = dismissal.label
            str2 = type
        }, {
            "Dismissing $str2 for: $str1"
        })
    }

    fun logFutureDismissalMismatchedEntry(
        dismissal: FutureDismissal,
        type: String,
        latestEntry: NotificationEntry?
    ) {
        buffer.log(TAG, WARNING, {
            str1 = dismissal.label
            str2 = type
            str3 = latestEntry.logKey
        }, {
            "Mismatch: current $str2 is $str3 for: $str1"
        })
    }

    fun logDismissAlreadyDismissedNotif(entry: NotificationEntry, index: Int, count: Int) {
        buffer.log(TAG, DEBUG, {
            str1 = entry.logKey
            int1 = index
            int2 = count
        }, {
            "DISMISS Already Dismissed $str1 ($int1/$int2)"
        })
    }

    private fun getParentLogKey(childEntry: NotificationEntry): String {
        return if (childEntry.parent is GroupEntry) {
            (childEntry.parent as? GroupEntry)?.summary?.logKey ?: "(null)"
        } else {
            "(null)"
        }
    }

    fun logDismissAlreadyParentDismissedNotif(
            childEntry: NotificationEntry,
            childIndex: Int,
            childCount: Int
    ) {
        buffer.log(TAG, DEBUG, {
            str1 = childEntry.logKey
            int1 = childIndex
            int2 = childCount
            str2 = getParentLogKey(childEntry)
        }, {
            "DISMISS Already Parent-Dismissed $str1 ($int1/$int2) with summary $str2"
        })
    }

    fun logLocallyDismissNonExistentNotif(entry: NotificationEntry, index: Int, count: Int) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            int1 = index
            int2 = count
        }, {
            "LOCALLY DISMISS Non Existent $str1 ($int1/$int2)"
        })
    }

    fun logLocallyDismissMismatchedEntry(
            entry: NotificationEntry,
            index: Int,
            count: Int,
            storedEntry: NotificationEntry
    ) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            int1 = index
            int2 = count
            str2 = Integer.toHexString(entry.hashCode())
            str3 = Integer.toHexString(storedEntry.hashCode())
        }, {
            "LOCALLY DISMISS Mismatch $str1 ($int1/$int2): dismissing @$str2 but stored @$str3"
        })
    }

    fun logLocallyDismissAlreadyDismissedNotif(
            entry: NotificationEntry,
            index: Int,
            count: Int
    ) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            int1 = index
            int2 = count
        }, {
            "LOCALLY DISMISS Already Dismissed $str1 ($int1/$int2)"
        })
    }

    fun logLocallyDismissAlreadyParentDismissedNotif(
            entry: NotificationEntry,
            index: Int,
            count: Int
    ) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
            int1 = index
            int2 = count
        }, {
            "LOCALLY DISMISS Already Dismissed $str1 ($int1/$int2)"
        })
    }

    fun logLocallyDismissAlreadyDismissedChild(
            childEntry: NotificationEntry,
            parentEntry: NotificationEntry,
            parentIndex: Int,
            parentCount: Int
    ) {
        buffer.log(TAG, INFO, {
            str1 = childEntry.logKey
            str2 = parentEntry.logKey
            int1 = parentIndex
            int2 = parentCount
        }, {
            "LOCALLY DISMISS Already Dismissed Child $str1 of parent $str2 ($int1/$int2)"
        })
    }

    fun logLocallyDismissAlreadyParentDismissedChild(
            childEntry: NotificationEntry,
            parentEntry: NotificationEntry,
            parentIndex: Int,
            parentCount: Int
    ) {
        buffer.log(TAG, INFO, {
            str1 = childEntry.logKey
            str2 = parentEntry.logKey
            int1 = parentIndex
            int2 = parentCount
        }, {
            "LOCALLY DISMISS Already Parent-Dismissed Child $str1 of parent $str2 ($int1/$int2)"
        })
    }

    fun logCancelLocalDismissalNotDismissedNotif(entry: NotificationEntry) {
        buffer.log(TAG, INFO, {
            str1 = entry.logKey
        }, {
            "CANCEL LOCAL DISMISS Not Dismissed $str1"
        })
    }
}

private const val TAG = "NotifCollection"
