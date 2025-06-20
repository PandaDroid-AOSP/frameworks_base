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

package com.android.systemui.statusbar.notification.logging;

import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_ALERTING;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_FOREGROUND_SERVICE;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_HEADS_UP;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_MEDIA_CONTROLS;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_NEWS;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_PEOPLE;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_PRIORITY_PEOPLE;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_PROMO;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_RECS;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_SILENT;
import static com.android.systemui.statusbar.notification.stack.NotificationPriorityBucketKt.BUCKET_SOCIAL;

import android.annotation.Nullable;
import android.service.notification.StatusBarNotification;

import com.android.internal.logging.UiEvent;
import com.android.internal.logging.UiEventLogger;
import com.android.systemui.statusbar.notification.collection.EntryAdapter;
import com.android.systemui.statusbar.notification.collection.NotificationEntry;
import com.android.systemui.statusbar.notification.logging.nano.Notifications;
import com.android.systemui.statusbar.notification.stack.PriorityBucket;

import java.util.List;

/**
 * Statsd logging for notification panel.
 */
public interface NotificationPanelLogger {

    /**
     * Log a NOTIFICATION_PANEL_REPORTED statsd event.
     */
    void logPanelShown(boolean isLockscreen, Notifications.NotificationList proto);

    /**
     * Log a NOTIFICATION_PANEL_REPORTED statsd event.
     * @param visibleNotifications as provided by NotificationEntryManager.getVisibleNotifications()
     */
    void logPanelShown(boolean isLockscreen,
            @Nullable List<NotificationEntry> visibleNotifications);

    /**
     * Log a NOTIFICATION_PANEL_REPORTED statsd event, with
     * {@link NotificationPanelEvent#NOTIFICATION_DRAG} as the eventID.
     *
     * @param draggedNotification the notification that is being dragged
     */
    void logNotificationDrag(NotificationEntry draggedNotification);

    void logNotificationDrag(EntryAdapter draggedNotification);

    enum NotificationPanelEvent implements UiEventLogger.UiEventEnum {
        @UiEvent(doc = "Notification panel shown from status bar.")
        NOTIFICATION_PANEL_OPEN_STATUS_BAR(200),
        @UiEvent(doc = "Notification panel shown from lockscreen.")
        NOTIFICATION_PANEL_OPEN_LOCKSCREEN(201),
        @UiEvent(doc = "Notification was dragged")
        NOTIFICATION_DRAG(1226);

        private final int mId;
        NotificationPanelEvent(int id) {
            mId = id;
        }
        @Override public int getId() {
            return mId;
        }

        public static NotificationPanelEvent fromLockscreen(boolean isLockscreen) {
            return isLockscreen ? NOTIFICATION_PANEL_OPEN_LOCKSCREEN :
                    NOTIFICATION_PANEL_OPEN_STATUS_BAR;
        }
    }

    /**
     * Composes a NotificationsList proto from the list of visible notifications.
     * @param visibleNotifications as provided by NotificationEntryManager.getVisibleNotifications()
     * @return NotificationList proto suitable for SysUiStatsLog.write(NOTIFICATION_PANEL_REPORTED)
     */
    static Notifications.NotificationList toNotificationProto(
            @Nullable List<NotificationEntry> visibleNotifications) {
        Notifications.NotificationList notificationList = new Notifications.NotificationList();
        if (visibleNotifications == null) {
            return notificationList;
        }
        final Notifications.Notification[] proto_array =
                new Notifications.Notification[visibleNotifications.size()];
        int i = 0;
        for (NotificationEntry ne : visibleNotifications) {
            final StatusBarNotification n = ne.getSbn();
            if (n != null) {
                final Notifications.Notification proto = new Notifications.Notification();
                proto.uid = n.getUid();
                proto.packageName = n.getPackageName();
                if (n.getInstanceId() != null) {
                    proto.instanceId = n.getInstanceId().getId();
                }
                // TODO set np.groupInstanceId
                if (n.getNotification() != null) {
                    proto.isGroupSummary = n.getNotification().isGroupSummary();
                }
                proto.section = toNotificationSection(ne.getBucket());
                proto_array[i] = proto;
            }
            ++i;
        }
        notificationList.notifications = proto_array;
        return notificationList;
    }

    /**
     * Composes a NotificationsList proto from the list of visible notifications.
     * @param visibleNotifications as provided by NotificationEntryManager.getVisibleNotifications()
     * @return NotificationList proto suitable for SysUiStatsLog.write(NOTIFICATION_PANEL_REPORTED)
     */
    static Notifications.NotificationList adapterToNotificationProto(
            @Nullable List<EntryAdapter> visibleNotifications) {
        Notifications.NotificationList notificationList = new Notifications.NotificationList();
        if (visibleNotifications == null) {
            return notificationList;
        }
        final Notifications.Notification[] proto_array =
                new Notifications.Notification[visibleNotifications.size()];
        int i = 0;
        for (EntryAdapter ne : visibleNotifications) {
            final StatusBarNotification n = ne.getSbn();
            if (n != null) {
                final Notifications.Notification proto = new Notifications.Notification();
                proto.uid = n.getUid();
                proto.packageName = n.getPackageName();
                if (n.getInstanceId() != null) {
                    proto.instanceId = n.getInstanceId().getId();
                }
                // TODO set np.groupInstanceId
                if (n.getNotification() != null) {
                    proto.isGroupSummary = n.getNotification().isGroupSummary();
                }
                proto.section = toNotificationSection(ne.getSectionBucket());
                proto_array[i] = proto;
            }
            ++i;
        }
        notificationList.notifications = proto_array;
        return notificationList;
    }

    /**
     * Maps PriorityBucket enum to Notification.SECTION constant. The two lists should generally
     * use matching names, but the values may differ, because PriorityBucket order changes from
     * time to time, while logs need to have stable meanings.
     * @param bucket PriorityBucket constant
     * @return Notification.SECTION constant
     */
    static int toNotificationSection(@PriorityBucket int bucket) {
        switch(bucket) {
            case BUCKET_MEDIA_CONTROLS : return Notifications.Notification.SECTION_MEDIA_CONTROLS;
            case BUCKET_HEADS_UP: return Notifications.Notification.SECTION_HEADS_UP;
            case BUCKET_FOREGROUND_SERVICE:
                return Notifications.Notification.SECTION_FOREGROUND_SERVICE;
            case BUCKET_PEOPLE, BUCKET_PRIORITY_PEOPLE:
                return Notifications.Notification.SECTION_PEOPLE;
            case BUCKET_ALERTING: return Notifications.Notification.SECTION_ALERTING;
            case BUCKET_SILENT: return Notifications.Notification.SECTION_SILENT;
            case BUCKET_NEWS: return Notifications.Notification.SECTION_NEWS;
            case BUCKET_SOCIAL: return Notifications.Notification.SECTION_SOCIAL;
            case BUCKET_RECS: return Notifications.Notification.SECTION_RECS;
            case BUCKET_PROMO: return Notifications.Notification.SECTION_PROMO;
        }
        return Notifications.Notification.SECTION_UNKNOWN;
    }

}
