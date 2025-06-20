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

package com.android.systemui.statusbar.notification.collection.render;

import android.util.Log;

import androidx.annotation.NonNull;

import com.android.systemui.Dumpable;
import com.android.systemui.dagger.SysUISingleton;
import com.android.systemui.dump.DumpManager;
import com.android.systemui.statusbar.notification.collection.EntryAdapter;
import com.android.systemui.statusbar.notification.collection.GroupEntry;
import com.android.systemui.statusbar.notification.collection.PipelineEntry;
import com.android.systemui.statusbar.notification.collection.NotifPipeline;
import com.android.systemui.statusbar.notification.collection.NotificationEntry;
import com.android.systemui.statusbar.notification.collection.listbuilder.OnBeforeRenderListListener;
import com.android.systemui.statusbar.notification.row.ExpandableNotificationRow;
import com.android.systemui.statusbar.notification.shared.NotificationBundleUi;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;

/**
 * Provides grouping information for notification entries including information about a group's
 * expanded state.
 */
@SysUISingleton
public class GroupExpansionManagerImpl implements GroupExpansionManager, Dumpable {
    private static final String TAG = "GroupExpansionaManagerImpl";

    private final DumpManager mDumpManager;
    private final GroupMembershipManager mGroupMembershipManager;
    private final Set<OnGroupExpansionChangeListener> mOnGroupChangeListeners = new HashSet<>();

    /**
     * Set of summary keys whose groups are expanded.
     * NOTE: This should not be modified without notifying listeners, so prefer using
     * {@code setGroupExpanded} when making changes.
     */
    private final Set<NotificationEntry> mExpandedGroups = new HashSet<>();

    private final Set<EntryAdapter> mExpandedCollections = new HashSet<>();

    @Inject
    public GroupExpansionManagerImpl(DumpManager dumpManager,
            GroupMembershipManager groupMembershipManager) {
        mDumpManager = dumpManager;
        mGroupMembershipManager = groupMembershipManager;
    }

    /**
     * Cleanup entries from internal tracking that no longer exist in the pipeline.
     */
    private final OnBeforeRenderListListener mNotifTracker = (entries) -> {
        if (NotificationBundleUi.isEnabled())  {
            if (mExpandedCollections.isEmpty()) {
                return; // nothing to do
            }
        } else {
            if (mExpandedGroups.isEmpty()) {
                return; // nothing to do
            }
        }

        final Set<NotificationEntry> renderingSummaries = new HashSet<>();
        for (PipelineEntry entry : entries) {
            if (entry instanceof GroupEntry) {
                renderingSummaries.add(entry.getRepresentativeEntry());
            }
        }

        if (NotificationBundleUi.isEnabled()) {
            for (EntryAdapter entryAdapter : mExpandedCollections) {
                boolean isInPipeline = false;
                for (NotificationEntry entry : renderingSummaries) {
                    if (entry.getKey().equals(entryAdapter.getKey())) {
                        isInPipeline = true;
                        break;
                    }
                }
                if (!isInPipeline) {
                    setGroupExpanded(entryAdapter, false);
                }
            }
        } else {
            // If a group is in mExpandedGroups but not in the pipeline entries, collapse it.
            final var groupsToRemove = setDifference(mExpandedGroups, renderingSummaries);
            for (NotificationEntry entry : groupsToRemove) {
                setGroupExpanded(entry, false);
            }
        }
    };

    public void attach(NotifPipeline pipeline) {
        mDumpManager.registerDumpable(this);
        pipeline.addOnBeforeRenderListListener(mNotifTracker);
    }

    @Override
    public void registerGroupExpansionChangeListener(OnGroupExpansionChangeListener listener) {
        mOnGroupChangeListeners.add(listener);
    }

    @Override
    public boolean isGroupExpanded(NotificationEntry entry) {
        NotificationBundleUi.assertInLegacyMode();
        return mExpandedGroups.contains(mGroupMembershipManager.getGroupSummary(entry));
    }

    @Override
    public void setGroupExpanded(NotificationEntry entry, boolean expanded) {
        NotificationBundleUi.assertInLegacyMode();
        NotificationEntry groupSummary = mGroupMembershipManager.getGroupSummary(entry);
        if (entry.getParent() == null) {
            if (expanded) {
                Log.wtf(TAG, "Cannot expand group that is not attached");
            } else {
                // The entry is no longer attached, but we still want to make sure we don't have
                // a stale expansion state.
                groupSummary = entry;
            }
        }

        boolean changed;
        if (expanded) {
            changed = mExpandedGroups.add(groupSummary);
        } else {
            changed = mExpandedGroups.remove(groupSummary);
        }

        // Only notify listeners if something changed.
        if (changed) {
            sendOnGroupExpandedChange(entry, expanded);
        }
    }

    @Override
    public boolean toggleGroupExpansion(NotificationEntry entry) {
        NotificationBundleUi.assertInLegacyMode();
        setGroupExpanded(entry, !isGroupExpanded(entry));
        return isGroupExpanded(entry);
    }

    @Override
    public boolean isGroupExpanded(EntryAdapter entry) {
        NotificationBundleUi.unsafeAssertInNewMode();
        ExpandableNotificationRow parent = entry.getRow().getNotificationParent();
        return mExpandedCollections.contains(entry)
                || (parent != null && mExpandedCollections.contains(parent.getEntryAdapter()));
    }

    @Override
    public void setGroupExpanded(EntryAdapter groupRoot, boolean expanded) {
        NotificationBundleUi.unsafeAssertInNewMode();
        if (!groupRoot.isAttached()) {
            if (expanded) {
                Log.wtf(TAG, "Cannot expand group that is not attached");
            }
        }

        boolean changed;
        if (expanded) {
            changed = mExpandedCollections.add(groupRoot);
        } else {
            changed = mExpandedCollections.remove(groupRoot);
        }

        // Only notify listeners if something changed.
        if (changed) {
            sendOnGroupExpandedChange(groupRoot, expanded);
        }
    }

    @Override
    public boolean toggleGroupExpansion(EntryAdapter groupRoot) {
        NotificationBundleUi.unsafeAssertInNewMode();
        setGroupExpanded(groupRoot, !isGroupExpanded(groupRoot));
        return isGroupExpanded(groupRoot);
    }

    @Override
    public void collapseGroups() {
        if (NotificationBundleUi.isEnabled()) {
            for (EntryAdapter entry : new ArrayList<>(mExpandedCollections)) {
                setGroupExpanded(entry, false);
            }
        } else {
            for (NotificationEntry entry : new ArrayList<>(mExpandedGroups)) {
                setGroupExpanded(entry, false);
            }
        }
    }

    @Override
    public void dump(@NonNull PrintWriter pw, @NonNull String[] args) {
        pw.println("NotificationEntryExpansion state:");
        pw.println("  mExpandedGroups: " + mExpandedGroups.size());
        for (NotificationEntry entry : mExpandedGroups) {
            pw.println("  * " + entry.getKey());
        }
        pw.println("  mExpandedCollection: " + mExpandedCollections.size());
        for (EntryAdapter entry : mExpandedCollections) {
            pw.println("  * " + entry.getKey());
        }
    }

    private void sendOnGroupExpandedChange(NotificationEntry entry, boolean expanded) {
        NotificationBundleUi.assertInLegacyMode();
        for (OnGroupExpansionChangeListener listener : mOnGroupChangeListeners) {
            listener.onGroupExpansionChange(entry.getRow(), expanded);
        }
    }

    private void sendOnGroupExpandedChange(EntryAdapter entry, boolean expanded) {
        NotificationBundleUi.unsafeAssertInNewMode();
        for (OnGroupExpansionChangeListener listener : mOnGroupChangeListeners) {
            listener.onGroupExpansionChange(entry.getRow(), expanded);
        }
    }

    /**
     * Utility method to compute the difference between two sets of NotificationEntry. Unfortunately
     * {@code Sets.difference} from Guava is not available in this codebase.
     */
    @NonNull
    private Set<NotificationEntry> setDifference(Set<NotificationEntry> set1,
            Set<NotificationEntry> set2) {
        if (set1 == null || set1.isEmpty()) {
            return new HashSet<>();
        }
        if (set2 == null || set2.isEmpty()) {
            return new HashSet<>(set1);
        }

        final Set<NotificationEntry> difference = new HashSet<>();
        for (NotificationEntry e : set1) {
            if (!set2.contains(e)) {
                difference.add(e);
            }
        }
        return difference;
    }
}
