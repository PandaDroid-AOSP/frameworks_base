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

package com.android.systemui.statusbar.notification.collection.provider;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.app.Notification;
import android.app.NotificationManager;

import com.android.systemui.dagger.SysUISingleton;
import com.android.systemui.statusbar.notification.collection.GroupEntry;
import com.android.systemui.statusbar.notification.collection.PipelineEntry;
import com.android.systemui.statusbar.notification.collection.NotificationEntry;
import com.android.systemui.statusbar.notification.collection.render.GroupMembershipManager;
import com.android.systemui.statusbar.notification.people.PeopleNotificationIdentifier;
import com.android.systemui.statusbar.notification.shared.NotificationBundleUi;

import java.util.List;

import javax.inject.Inject;

/**
 * Determines whether a notification is considered 'high priority'.
 *
 * Notifications that are high priority are visible on the lock screen/status bar and in the top
 * section in the shade.
 */
@SysUISingleton
public class HighPriorityProvider {
    private final PeopleNotificationIdentifier mPeopleNotificationIdentifier;
    private final GroupMembershipManager mGroupMembershipManager;

    @Inject
    public HighPriorityProvider(
            PeopleNotificationIdentifier peopleNotificationIdentifier,
            GroupMembershipManager groupManager) {
        mPeopleNotificationIdentifier = peopleNotificationIdentifier;
        mGroupMembershipManager = groupManager;
    }

    /**
     * @return true if the PipelineEntry is high priority, else false
     *
     * A NotificationEntry is considered high priority if it:
     *  - has importance greater than or equal to IMPORTANCE_DEFAULT
     *  OR
     *  - their importance has NOT been set to a low priority option by the user AND the
     *  notification fulfills one of the following:
     *      - has a person associated with it
     *      - has a media session associated with it
     *      - has messaging style
     *
     * A GroupEntry is considered high priority if its representativeEntry (summary) or any of its
     * children are high priority.
     */
    public boolean isHighPriority(@Nullable PipelineEntry entry) {
        return isHighPriority(entry, /* allowImplicit = */ true);
    }

    /**
     * @return true if the PipelineEntry is explicitly high priority, else false
     *
     * A NotificationEntry is considered explicitly high priority if has importance greater than or
     * equal to IMPORTANCE_DEFAULT.
     *
     * A GroupEntry is considered explicitly high priority if its representativeEntry (summary) or
     * any of its children are explicitly high priority.
     */
    public boolean isExplicitlyHighPriority(@Nullable PipelineEntry entry) {
        return isHighPriority(entry, /* allowImplicit= */ false);
    }

    private boolean isHighPriority(@Nullable PipelineEntry entry, boolean allowImplicit) {
        if (entry == null) {
            return false;
        }

        final NotificationEntry notifEntry = entry.getRepresentativeEntry();
        if (notifEntry == null) {
            return false;
        }

        return notifEntry.getRanking().getImportance() >= NotificationManager.IMPORTANCE_DEFAULT
                || (allowImplicit && hasHighPriorityCharacteristics(notifEntry))
                || hasHighPriorityChild(entry, allowImplicit);
    }

    /**
     * @return true if the PipelineEntry is high priority conversation, else false
     */
    public boolean isHighPriorityConversation(@NonNull PipelineEntry entry) {
        final NotificationEntry notifEntry = entry.getRepresentativeEntry();
        if (notifEntry == null) {
            return  false;
        }

        if (!isPeopleNotification(notifEntry)) {
            return false;
        }

        if (notifEntry.getRanking().getImportance() >= NotificationManager.IMPORTANCE_DEFAULT) {
            return true;
        }

        return isNotificationEntryWithAtLeastOneImportantChild(entry);
    }

    private boolean isNotificationEntryWithAtLeastOneImportantChild(@NonNull PipelineEntry entry) {
        if (!(entry instanceof GroupEntry)) {
            return false;
        }
        final GroupEntry groupEntry = (GroupEntry) entry;
        return groupEntry.getChildren().stream().anyMatch(
                childEntry ->
                        childEntry.getRanking().getImportance()
                                >= NotificationManager.IMPORTANCE_DEFAULT);
    }

    /**
     * Returns whether the given ListEntry has a high priority child or is in a group with a child
     * that's high priority
     */
    private boolean hasHighPriorityChild(PipelineEntry entry, boolean allowImplicit) {
        if (NotificationBundleUi.isEnabled()) {
            GroupEntry representativeGroupEntry = null;
            if (entry instanceof GroupEntry) {
                representativeGroupEntry = (GroupEntry) entry;
            } else if (entry instanceof NotificationEntry){
                final NotificationEntry notificationEntry = entry.getRepresentativeEntry();
                if (notificationEntry.getParent() != null
                        && notificationEntry.getParent() instanceof GroupEntry parent
                        && parent.getSummary() != null
                        && parent.getSummary() == notificationEntry) {
                    representativeGroupEntry = parent;
                }
            }
            return representativeGroupEntry != null &&
                    representativeGroupEntry.getChildren().stream().anyMatch(
                            childEntry -> isHighPriority(childEntry, allowImplicit));

        } else {
            if (entry instanceof NotificationEntry
                    && !mGroupMembershipManager.isGroupSummary((NotificationEntry) entry)) {
                return false;
            }
            List<NotificationEntry> children = mGroupMembershipManager.getChildren(entry);
            if (children != null) {
                for (NotificationEntry child : children) {
                    if (child != entry && isHighPriority(child, allowImplicit)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    private boolean hasHighPriorityCharacteristics(NotificationEntry entry) {
        return !hasUserSetImportance(entry)
                && (entry.getSbn().getNotification().isMediaNotification()
                || isPeopleNotification(entry)
                || isMessagingStyle(entry));
    }

    private boolean isMessagingStyle(NotificationEntry entry) {
        return entry.getSbn().getNotification().isStyle(Notification.MessagingStyle.class);
    }

    private boolean isPeopleNotification(NotificationEntry entry) {
        return mPeopleNotificationIdentifier.getPeopleNotificationType(entry)
                != PeopleNotificationIdentifier.TYPE_NON_PERSON;
    }

    private boolean hasUserSetImportance(NotificationEntry entry) {
        return entry.getRanking().getChannel() != null
                && entry.getRanking().getChannel().hasUserSetImportance();
    }
}
