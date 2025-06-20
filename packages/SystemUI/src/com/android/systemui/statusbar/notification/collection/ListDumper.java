/*
 * Copyright (C) 2019 The Android Open Source Project
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

package com.android.systemui.statusbar.notification.collection;

import static com.android.systemui.statusbar.notification.NotificationUtils.logKey;
import static com.android.systemui.statusbar.notification.collection.NotifCollection.REASON_NOT_CANCELED;
import static com.android.systemui.statusbar.notification.collection.NotificationEntry.DismissState.NOT_DISMISSED;

import static java.util.Objects.requireNonNull;

import com.android.systemui.statusbar.NotificationInteractionTracker;

import java.util.Arrays;
import java.util.List;

/**
 * Utility class for dumping the results of a {@link ShadeListBuilder} to a debug string.
 */
public class ListDumper {

    /**
     * Creates a debug string for a list of grouped notifications that will be printed
     * in the order given in a tiered/tree structure.
     * @param includeRecordKeeping whether to print out the Pluggables that caused the notification
     *                             entry to be in its current state (ie: filter, lifeExtender)
     */
    public static String dumpTree(
            List<PipelineEntry> entries,
            NotificationInteractionTracker interactionTracker,
            boolean includeRecordKeeping,
            String indent) {
        StringBuilder sb = new StringBuilder();
        final String childEntryIndent = indent + INDENT;
        for (int topEntryIndex = 0; topEntryIndex < entries.size(); topEntryIndex++) {
            PipelineEntry entry = entries.get(topEntryIndex);
            dumpEntry(entry,
                    Integer.toString(topEntryIndex),
                    indent,
                    sb,
                    true,
                    includeRecordKeeping,
                    interactionTracker.hasUserInteractedWith(logKey(entry)));
            if (entry instanceof GroupEntry) {
                GroupEntry ge = (GroupEntry) entry;
                NotificationEntry summary = ge.getSummary();
                if (summary != null) {
                    dumpEntry(summary,
                            topEntryIndex + ":*",
                            childEntryIndent,
                            sb,
                            true,
                            includeRecordKeeping,
                            interactionTracker.hasUserInteractedWith(logKey(summary)));
                }
                List<NotificationEntry> children = ge.getChildren();
                for (int childIndex = 0;  childIndex < children.size(); childIndex++) {
                    NotificationEntry child = children.get(childIndex);
                    dumpEntry(child,
                            topEntryIndex + "." + childIndex,
                            childEntryIndent,
                            sb,
                            true,
                            includeRecordKeeping,
                            interactionTracker.hasUserInteractedWith(logKey(child)));
                }
            }
        }
        return sb.toString();
    }

    /**
     * Creates a debug string for a flat list of notifications
     * @param includeRecordKeeping whether to print out the Pluggables that caused the notification
     *                             entry to be in its current state (ie: filter, lifeExtender)
     */
    public static String dumpList(
            List<NotificationEntry> entries,
            boolean includeRecordKeeping,
            String indent) {
        StringBuilder sb = new StringBuilder();
        for (int j = 0; j < entries.size(); j++) {
            dumpEntry(
                    entries.get(j),
                    Integer.toString(j),
                    indent,
                    sb,
                    false,
                    includeRecordKeeping,
                    false);
        }
        return sb.toString();
    }

    private static void dumpEntry(
            PipelineEntry entry,
            String index,
            String indent,
            StringBuilder sb,
            boolean includeParent,
            boolean includeRecordKeeping,
            boolean hasBeenInteractedWith
    ) {
        sb.append(indent)
                .append("[").append(index).append("] ")
                .append(index.length() == 1 ? " " : "")
                .append(logKey(entry));

        if (includeParent) {
            sb.append(" (parent=")
                    .append(logKey(entry.getParent()))
                    .append(")");

            NotificationEntry notifEntry = entry.getRepresentativeEntry();
            if (notifEntry != null) {
                sb.append(" rank=")
                        .append(notifEntry.getRanking().getRank());
            }
        }

        if (entry.getSection() != null) {
            sb.append(" section=")
                    .append(entry.getSection().getLabel());
        }

        if (includeRecordKeeping) {
            NotificationEntry notifEntry = requireNonNull(entry.getRepresentativeEntry());
            StringBuilder rksb = new StringBuilder();

            if (!notifEntry.mLifetimeExtenders.isEmpty()) {
                String[] lifetimeExtenderNames = new String[notifEntry.mLifetimeExtenders.size()];
                for (int i = 0; i < lifetimeExtenderNames.length; i++) {
                    lifetimeExtenderNames[i] = notifEntry.mLifetimeExtenders.get(i).getName();
                }
                rksb.append("lifetimeExtenders=")
                        .append(Arrays.toString(lifetimeExtenderNames))
                        .append(" ");
            }

            if (!notifEntry.mDismissInterceptors.isEmpty()) {
                String[] interceptorsNames = new String[notifEntry.mDismissInterceptors.size()];
                for (int i = 0; i < interceptorsNames.length; i++) {
                    interceptorsNames[i] = notifEntry.mDismissInterceptors.get(i).getName();
                }
                rksb.append("dismissInterceptors=")
                        .append(Arrays.toString(interceptorsNames))
                        .append(" ");
            }

            if (notifEntry.getExcludingFilter() != null) {
                rksb.append("filter=")
                        .append(notifEntry.getExcludingFilter().getName())
                        .append(" ");
            }

            if (notifEntry.getNotifPromoter() != null) {
                rksb.append("promoter=")
                        .append(notifEntry.getNotifPromoter().getName())
                        .append(" ");
            }

            if (notifEntry.mCancellationReason != REASON_NOT_CANCELED) {
                rksb.append("cancellationReason=")
                        .append(notifEntry.mCancellationReason)
                        .append(" ");
            }

            if (notifEntry.getDismissState() != NOT_DISMISSED) {
                rksb.append("dismissState=")
                        .append(notifEntry.getDismissState())
                        .append(" ");
            }

            if (notifEntry.getAttachState().getSuppressedChanges().getParent() != null) {
                rksb.append("suppressedParent=")
                        .append(logKey(notifEntry.getAttachState().getSuppressedChanges()
                                .getParent()))
                        .append(" ");
            }

            if (notifEntry.getAttachState().getSuppressedChanges().getSection() != null) {
                rksb.append("suppressedSection=")
                        .append(notifEntry.getAttachState().getSuppressedChanges()
                                .getSection().getLabel())
                        .append(" ");
            }

            if (hasBeenInteractedWith) {
                rksb.append("interacted=yes ");
            }

            String rkString = rksb.toString();
            if (!rkString.isEmpty()) {
                sb.append("\n\t")
                        .append(indent)
                        .append(rkString);
            }
        }

        sb.append("\n");
    }

    private static final String INDENT = "  ";
}
