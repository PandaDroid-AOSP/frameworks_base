/*
 * Copyright (C) 2015 The Android Open Source Project
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

package com.android.systemui.statusbar.notification.headsup;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.app.Notification;
import android.content.Context;
import android.content.res.Resources;
import android.database.ContentObserver;
import android.graphics.Region;
import android.os.Handler;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.Log;
import android.util.Pools;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.logging.MetricsLogger;
import com.android.internal.logging.UiEvent;
import com.android.internal.logging.UiEventLogger;
import com.android.internal.policy.SystemBarUtils;
import com.android.systemui.EventLogTags;
import com.android.systemui.dagger.SysUISingleton;
import com.android.systemui.dagger.qualifiers.Main;
import com.android.systemui.plugins.statusbar.StatusBarStateController;
import com.android.systemui.res.R;
import com.android.systemui.scene.shared.flag.SceneContainerFlag;
import com.android.systemui.shade.ShadeDisplayAware;
import com.android.systemui.shade.domain.interactor.ShadeInteractor;
import com.android.systemui.statusbar.StatusBarState;
import com.android.systemui.statusbar.chips.notification.shared.StatusBarNotifChips;
import com.android.systemui.statusbar.notification.collection.NotificationEntry;
import com.android.systemui.statusbar.notification.collection.coordinator.HeadsUpCoordinator;
import com.android.systemui.statusbar.notification.collection.provider.OnReorderingAllowedListener;
import com.android.systemui.statusbar.notification.collection.provider.OnReorderingBannedListener;
import com.android.systemui.statusbar.notification.collection.provider.VisualStabilityProvider;
import com.android.systemui.statusbar.notification.collection.render.GroupMembershipManager;
import com.android.systemui.statusbar.notification.data.repository.HeadsUpRepository;
import com.android.systemui.statusbar.notification.data.repository.HeadsUpRowRepository;
import com.android.systemui.statusbar.notification.row.ExpandableNotificationRow;
import com.android.systemui.statusbar.notification.shared.NotificationBundleUi;
import com.android.systemui.statusbar.notification.shared.NotificationThrottleHun;
import com.android.systemui.statusbar.phone.ExpandHeadsUpOnInlineReply;
import com.android.systemui.statusbar.phone.KeyguardBypassController;
import com.android.systemui.statusbar.policy.AccessibilityManagerWrapper;
import com.android.systemui.statusbar.policy.ConfigurationController;
import com.android.systemui.util.ListenerSet;
import com.android.systemui.util.concurrency.DelayableExecutor;
import com.android.systemui.util.kotlin.JavaAdapter;
import com.android.systemui.util.settings.GlobalSettings;
import com.android.systemui.util.time.SystemClock;

import kotlinx.coroutines.flow.Flow;
import kotlinx.coroutines.flow.MutableStateFlow;
import kotlinx.coroutines.flow.StateFlow;
import kotlinx.coroutines.flow.StateFlowKt;

import org.jetbrains.annotations.NotNull;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.Stack;
import java.util.stream.Stream;

import javax.inject.Inject;

/**
 * A manager which handles heads up notifications which is a special mode where
 * they simply peek from the top of the screen.
 */
@SysUISingleton
public class HeadsUpManagerImpl
        implements HeadsUpManager, HeadsUpRepository, OnHeadsUpChangedListener {
    private static final String TAG = "BaseHeadsUpManager";
    private static final String SETTING_HEADS_UP_SNOOZE_LENGTH_MS = "heads_up_snooze_length_ms";
    private static final String REASON_REORDER_ALLOWED = "mOnReorderingAllowedListener";
    private final ListenerSet<OnHeadsUpChangedListener> mListeners = new ListenerSet<>();

    private final Context mContext;

    private final int mTouchAcceptanceDelay;
    private int mSnoozeLengthMs;
    private boolean mHasPinnedNotification;
    private PinnedStatus mPinnedNotificationStatus = PinnedStatus.NotPinned;
    private int mUser;

    private final ArrayMap<String, Long> mSnoozedPackages;
    private final AccessibilityManagerWrapper mAccessibilityMgr;

    private final UiEventLogger mUiEventLogger;
    private AvalancheController mAvalancheController;
    private final KeyguardBypassController mBypassController;
    private final GroupMembershipManager mGroupMembershipManager;
    private final List<OnHeadsUpPhoneListenerChange> mHeadsUpPhoneListeners = new ArrayList<>();
    private final VisualStabilityProvider mVisualStabilityProvider;

    private final SystemClock mSystemClock;
    @VisibleForTesting
    final ArrayMap<String, HeadsUpEntry> mHeadsUpEntryMap = new ArrayMap<>();
    private final HeadsUpManagerLogger mLogger;
    private final int mMinimumDisplayTimeDefault;
    private final int mMinimumDisplayTimeForUserInitiated;
    private final int mStickyForSomeTimeAutoDismissTime;
    private final int mAutoDismissTime;
    private final DelayableExecutor mExecutor;

    private final int mExtensionTime;

    // TODO(b/328393698) move the topHeadsUpRow logic to an interactor
    private final MutableStateFlow<HeadsUpRowRepository> mTopHeadsUpRow =
            StateFlowKt.MutableStateFlow(null);
    private final MutableStateFlow<Set<HeadsUpRowRepository>> mHeadsUpNotificationRows =
            StateFlowKt.MutableStateFlow(new HashSet<>());
    private final MutableStateFlow<Boolean> mHeadsUpAnimatingAway =
            StateFlowKt.MutableStateFlow(false);
    private final MutableStateFlow<Boolean> mTrackingHeadsUp =
            StateFlowKt.MutableStateFlow(false);
    private final HashSet<String> mSwipedOutKeys = new HashSet<>();
    private final HashSet<NotificationEntry> mEntriesToRemoveAfterExpand = new HashSet<>();
    @VisibleForTesting
    final ArraySet<NotificationEntry> mEntriesToRemoveWhenReorderingAllowed
            = new ArraySet<>();

    private boolean mReleaseOnExpandFinish;
    private boolean mIsShadeOrQsExpanded;
    private boolean mIsQsExpanded;
    private int mStatusBarState;
    private AnimationStateHandler mAnimationStateHandler;
    private int mHeadsUpInset;

    // Used for determining the region for touch interaction
    private final Region mTouchableRegion = new Region();

    private final Pools.Pool<HeadsUpEntry> mEntryPool = new Pools.Pool<>() {
        private final Stack<HeadsUpEntry> mPoolObjects = new Stack<>();

        @Override
        public HeadsUpEntry acquire() {
            NotificationThrottleHun.assertInLegacyMode();
            if (!mPoolObjects.isEmpty()) {
                return mPoolObjects.pop();
            }
            return new HeadsUpEntry();
        }

        @Override
        public boolean release(@NonNull HeadsUpEntry instance) {
            NotificationThrottleHun.assertInLegacyMode();
            mPoolObjects.push(instance);
            return true;
        }
    };

    /**
     * Enum entry for notification peek logged from this class.
     */
    enum NotificationPeekEvent implements UiEventLogger.UiEventEnum {
        @UiEvent(doc = "Heads-up notification peeked on screen.")
        NOTIFICATION_PEEK(801);

        private final int mId;
        NotificationPeekEvent(int id) {
            mId = id;
        }
        @Override public int getId() {
            return mId;
        }
    }

    @Inject
    public HeadsUpManagerImpl(
            @NonNull @ShadeDisplayAware final Context context,
            HeadsUpManagerLogger logger,
            StatusBarStateController statusBarStateController,
            KeyguardBypassController bypassController,
            GroupMembershipManager groupMembershipManager,
            VisualStabilityProvider visualStabilityProvider,
            @ShadeDisplayAware ConfigurationController configurationController,
            @Main Handler handler,
            GlobalSettings globalSettings,
            SystemClock systemClock,
            @Main DelayableExecutor executor,
            AccessibilityManagerWrapper accessibilityManagerWrapper,
            UiEventLogger uiEventLogger,
            JavaAdapter javaAdapter,
            ShadeInteractor shadeInteractor,
            AvalancheController avalancheController) {
        mLogger = logger;
        mExecutor = executor;
        mSystemClock = systemClock;
        mContext = context;
        mAccessibilityMgr = accessibilityManagerWrapper;
        mUiEventLogger = uiEventLogger;
        mAvalancheController = avalancheController;
        mAvalancheController.setBaseEntryMapStr(this::getEntryMapStr);
        mBypassController = bypassController;
        mGroupMembershipManager = groupMembershipManager;
        mVisualStabilityProvider = visualStabilityProvider;
        Resources resources = context.getResources();
        mMinimumDisplayTimeDefault = NotificationThrottleHun.isEnabled()
                ? resources.getInteger(R.integer.heads_up_notification_minimum_time_with_throttling)
                : resources.getInteger(R.integer.heads_up_notification_minimum_time);
        mMinimumDisplayTimeForUserInitiated = resources.getInteger(
                R.integer.heads_up_notification_minimum_time_for_user_initiated);
        mStickyForSomeTimeAutoDismissTime = resources.getInteger(
                R.integer.sticky_heads_up_notification_time);
        mAutoDismissTime = resources.getInteger(R.integer.heads_up_notification_decay);
        mExtensionTime = resources.getInteger(R.integer.ambient_notification_extension_time);
        mTouchAcceptanceDelay = resources.getInteger(R.integer.touch_acceptance_delay);
        mSnoozedPackages = new ArrayMap<>();
        int defaultSnoozeLengthMs =
                resources.getInteger(R.integer.heads_up_default_snooze_length_ms);

        mSnoozeLengthMs = globalSettings.getInt(SETTING_HEADS_UP_SNOOZE_LENGTH_MS,
                defaultSnoozeLengthMs);
        ContentObserver settingsObserver = new ContentObserver(handler) {
            @Override
            public void onChange(boolean selfChange) {
                final int packageSnoozeLengthMs = globalSettings.getInt(
                        SETTING_HEADS_UP_SNOOZE_LENGTH_MS, -1);
                if (packageSnoozeLengthMs > -1 && packageSnoozeLengthMs != mSnoozeLengthMs) {
                    mSnoozeLengthMs = packageSnoozeLengthMs;
                    mLogger.logSnoozeLengthChange(packageSnoozeLengthMs);
                }
            }
        };
        globalSettings.registerContentObserverSync(
                globalSettings.getUriFor(SETTING_HEADS_UP_SNOOZE_LENGTH_MS),
                /* notifyForDescendants = */ false,
                settingsObserver);

        statusBarStateController.addCallback(mStatusBarStateListener);
        updateResources();
        configurationController.addCallback(new ConfigurationController.ConfigurationListener() {
            @Override
            public void onDensityOrFontScaleChanged() {
                updateResources();
            }

            @Override
            public void onThemeChanged() {
                updateResources();
            }
        });
        javaAdapter.alwaysCollectFlow(shadeInteractor.isAnyExpanded(),
                this::onShadeOrQsExpanded);
        if (SceneContainerFlag.isEnabled()) {
            javaAdapter.alwaysCollectFlow(shadeInteractor.isQsExpanded(),
                    this::onQsExpanded);
        }
        if (NotificationThrottleHun.isEnabled()) {
            mVisualStabilityProvider.addPersistentReorderingBannedListener(
                    mOnReorderingBannedListener);
            mVisualStabilityProvider.addPersistentReorderingAllowedListener(
                    mOnReorderingAllowedListener);
        }
    }

    /**
     * Adds an OnHeadUpChangedListener to observe events.
     */
    @Override
    public void addListener(@NonNull OnHeadsUpChangedListener listener) {
        mListeners.addIfAbsent(listener);
    }

    /**
     * Removes the OnHeadUpChangedListener from the observer list.
     */
    @Override
    public void removeListener(@NonNull OnHeadsUpChangedListener listener) {
        mListeners.remove(listener);
    }

    /**
     * Add a listener to receive callbacks {@link #setHeadsUpAnimatingAway(boolean)}
     */
    @Override
    public void addHeadsUpPhoneListener(@NonNull OnHeadsUpPhoneListenerChange listener) {
        mHeadsUpPhoneListeners.add(listener);
    }

    @Override
    public void setAnimationStateHandler(@NonNull AnimationStateHandler handler) {
        mAnimationStateHandler = handler;
    }

    private void updateResources() {
        Resources resources = mContext.getResources();
        mHeadsUpInset = SystemBarUtils.getStatusBarHeight(mContext)
                + resources.getDimensionPixelSize(R.dimen.heads_up_status_bar_padding);
    }

    @Override
    public void showNotification(
            @NonNull NotificationEntry entry, boolean isPinnedByUser) {
        HeadsUpEntry headsUpEntry = createHeadsUpEntry(entry);

        mLogger.logShowNotificationRequest(entry, isPinnedByUser);

        PinnedStatus requestedPinnedStatus =
                isPinnedByUser
                        ? PinnedStatus.PinnedByUser
                        : PinnedStatus.PinnedBySystem;
        headsUpEntry.setRequestedPinnedStatus(requestedPinnedStatus);

        Runnable runnable = () -> {
            mLogger.logShowNotification(entry, isPinnedByUser);

            // Add new entry and begin managing it
            mHeadsUpEntryMap.put(entry.getKey(), headsUpEntry);
            onEntryAdded(headsUpEntry, requestedPinnedStatus);
            // TODO(b/328390331) move accessibility events to the view layer
            entry.sendAccessibilityEvent(AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED);
            if (!NotificationBundleUi.isEnabled()) {
                entry.setIsHeadsUpEntry(true);
            }

            updateNotificationInternal(entry.getKey(), requestedPinnedStatus);
            entry.setInterruption();
        };
        mAvalancheController.update(headsUpEntry, runnable, "showNotification");
    }

    @Override
    public boolean removeNotification(
            @NonNull String key,
            boolean releaseImmediately,
            boolean animate,
            @NonNull String reason) {
        if (animate) {
            return removeNotification(key, releaseImmediately,
                    "removeNotification(animate: true), reason: " + reason);
        } else {
            mAnimationStateHandler.setHeadsUpGoingAwayAnimationsAllowed(false);
            final boolean removed = removeNotification(key, releaseImmediately,
                    "removeNotification(animate: false), reason: " + reason);
            mAnimationStateHandler.setHeadsUpGoingAwayAnimationsAllowed(true);
            return removed;
        }
    }

    @Override
    public boolean removeNotification(@NotNull String key, boolean releaseImmediately,
            @NonNull String reason) {
        final boolean isWaiting = mAvalancheController.isWaiting(key);
        mLogger.logRemoveNotification(key, releaseImmediately, isWaiting, reason);

        if (mAvalancheController.isWaiting(key)) {
            removeEntry(key, "removeNotification (isWaiting)");
            return true;
        }
        HeadsUpEntry headsUpEntry = mHeadsUpEntryMap.get(key);
        if (headsUpEntry == null) {
            mLogger.logNullEntry(key, reason);
            return true;
        }
        if (releaseImmediately) {
            removeEntry(key, "removeNotification (releaseImmediately)");
            return true;
        }
        if (canRemoveImmediately(key)) {
            removeEntry(key, "removeNotification (canRemoveImmediately)");
            return true;
        }
        headsUpEntry.removeAsSoonAsPossible();
        return false;
    }

    @Override
    public void updateNotification(
            @NonNull String key, @NonNull PinnedStatus requestedPinnedStatus) {
        HeadsUpEntry headsUpEntry = mHeadsUpEntryMap.get(key);
        mLogger.logUpdateNotificationRequest(key, requestedPinnedStatus, headsUpEntry != null);

        Runnable runnable = () -> updateNotificationInternal(key, requestedPinnedStatus);
        mAvalancheController.update(headsUpEntry, runnable, "updateNotification");
    }

    private void updateNotificationInternal(
            @NonNull String key, PinnedStatus requestedPinnedStatus) {
        HeadsUpEntry headsUpEntry = mHeadsUpEntryMap.get(key);
        mLogger.logUpdateNotification(key, requestedPinnedStatus, headsUpEntry != null);
        if (headsUpEntry == null) {
            // the entry was released before this update (i.e by a listener) This can happen
            // with the groupmanager
            return;
        }
        // TODO(b/328390331) move accessibility events to the view layer
        if (headsUpEntry.mEntry != null) {
            headsUpEntry.mEntry.sendAccessibilityEvent(
                    AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED);
        }
        if (requestedPinnedStatus.isPinned()) {
            headsUpEntry.updateEntry(true /* updatePostTime */, "updateNotification");
            PinnedStatus pinnedStatus =
                    getNewPinnedStatusForEntry(headsUpEntry, requestedPinnedStatus);
            setEntryPinned(headsUpEntry, pinnedStatus, "updateNotificationInternal");
        }
    }

    @Override
    public void setTrackingHeadsUp(boolean isTrackingHeadsUp) {
        mTrackingHeadsUp.setValue(isTrackingHeadsUp);
    }

    @Override
    public boolean shouldSwallowClick(@NonNull String key) {
        HeadsUpManagerImpl.HeadsUpEntry entry = getHeadsUpEntry(key);
        return entry != null && mSystemClock.elapsedRealtime() < entry.mPostTime;
    }

    @Override
    public void releaseAfterExpansion() {
        if (SceneContainerFlag.isUnexpectedlyInLegacyMode()) return;
        onExpandingFinished();
    }

    @Override
    public void onExpandingFinished() {
        if (mReleaseOnExpandFinish) {
            releaseAllImmediately();
            mReleaseOnExpandFinish = false;
        } else {
            for (NotificationEntry entry : getAllEntries().toList()) {
                entry.setSeenInShade(true);
            }
            for (NotificationEntry entry : mEntriesToRemoveAfterExpand) {
                if (isHeadsUpEntry(entry.getKey())) {
                    // Maybe the heads-up was removed already
                    removeEntry(entry.getKey(), "onExpandingFinished");
                }
            }
        }
        mEntriesToRemoveAfterExpand.clear();
    }

    /**
     * Clears all managed notifications.
     */
    public void releaseAllImmediately() {
        mLogger.logReleaseAllImmediately();
        // A copy is necessary here as we are changing the underlying map.  This would cause
        // undefined behavior if we iterated over the key set directly.
        ArraySet<String> keysToRemove = new ArraySet<>(mHeadsUpEntryMap.keySet());

        // Must get waiting keys before calling removeEntry, which clears waiting entries in
        // AvalancheController
        List<String> waitingKeysToRemove = mAvalancheController.getWaitingKeys();

        for (String key : keysToRemove) {
            removeEntry(key, "releaseAllImmediately (keysToRemove)");
        }
        for (String key : waitingKeysToRemove) {
            removeEntry(key, "releaseAllImmediately (waitingKeysToRemove)");
        }
    }

    /**
     * Returns the entry if it is managed by this manager.
     * @param key key of notification
     * @return the entry
     */
    @Nullable
    public NotificationEntry getEntry(@NonNull String key) {
        HeadsUpEntry headsUpEntry = mHeadsUpEntryMap.get(key);
        return headsUpEntry != null ? headsUpEntry.mEntry : null;
    }

    /**
     * Returns the stream of all current notifications managed by this manager.
     * @return all entries
     */
    @NonNull
    @Override
    public Stream<NotificationEntry> getAllEntries() {
        return getHeadsUpEntryList().stream().map(headsUpEntry -> headsUpEntry.mEntry);
    }

    public List<HeadsUpEntry> getHeadsUpEntryList() {
        List<HeadsUpEntry> entryList = new ArrayList<>(mHeadsUpEntryMap.values());
        entryList.addAll(mAvalancheController.getWaitingEntryList());
        return entryList;
    }

    /**
     * Whether or not there are any active notifications.
     * @return true if there is an entry, false otherwise
     */
    @Override
    public boolean hasNotifications() {
        return !mHeadsUpEntryMap.isEmpty()
                || !mAvalancheController.getWaitingEntryList().isEmpty();
    }

    @Override
    public boolean isHeadsUpEntry(@NonNull String key) {
        return mHeadsUpEntryMap.containsKey(key) || mAvalancheController.isWaiting(key);
    }

    /**
     * @return When a HUN entry with the given key should be removed in milliseconds from now
     */
    @Override
    public long getEarliestRemovalTime(String key) {
        HeadsUpEntry entry = mHeadsUpEntryMap.get(key);
        if (entry != null) {
            return Math.max(0, entry.mEarliestRemovalTime - mSystemClock.elapsedRealtime());
        }
        return 0;
    }

    @VisibleForTesting
    boolean shouldHeadsUpBecomePinned(@Nullable NotificationEntry entry) {
        if (entry == null) {
            return false;
        }
        boolean pin = mStatusBarState == StatusBarState.SHADE && !mIsShadeOrQsExpanded;
        if (SceneContainerFlag.isEnabled()) {
            pin |= mIsQsExpanded;
        }
        if (mBypassController.getBypassEnabled()) {
            pin |= mStatusBarState == StatusBarState.KEYGUARD;
        }
        if (pin) {
            return true;
        }

        final HeadsUpEntry headsUpEntry = getHeadsUpEntry(entry.getKey());
        if (headsUpEntry == null) {
            // This should not happen since shouldHeadsUpBecomePinned is always called after adding
            // the NotificationEntry into mHeadsUpEntryMap.
            return hasFullScreenIntent(entry);
        }
        return hasFullScreenIntent(entry) && !headsUpEntry.mWasUnpinned;
    }

    private boolean hasFullScreenIntent(@NonNull NotificationEntry entry) {
        if (entry.getSbn().getNotification() == null) {
            return false;
        }
        return entry.getSbn().getNotification().fullScreenIntent != null;
    }

    private void setEntryPinned(
            @NonNull HeadsUpManagerImpl.HeadsUpEntry headsUpEntry, PinnedStatus pinnedStatus,
            String reason) {
        NotificationEntry entry = headsUpEntry.requireEntry();
        mLogger.logSetEntryPinned(entry, pinnedStatus, reason);
        boolean isPinned = pinnedStatus.isPinned();
        if (!isPinned) {
            headsUpEntry.mWasUnpinned = true;
        }
        if (headsUpEntry.getPinnedStatus().getValue() != pinnedStatus) {
            headsUpEntry.setRowPinnedStatus(pinnedStatus);
            updatePinnedMode();
            if (isPinned) {
               mUiEventLogger.logWithInstanceId(
                        NotificationPeekEvent.NOTIFICATION_PEEK, entry.getSbn().getUid(),
                        entry.getSbn().getPackageName(), entry.getSbn().getInstanceId());
            }
        // TODO(b/325936094) use the isPinned Flow instead
            for (OnHeadsUpChangedListener listener : mListeners) {
                if (isPinned) {
                    listener.onHeadsUpPinned(entry);
                } else {
                    listener.onHeadsUpUnPinned(entry);
                }
            }
        }
    }

    /**
     * Manager-specific logic that should occur when an entry is added.
     * @param headsUpEntry entry added
     */
    @VisibleForTesting
     void onEntryAdded(HeadsUpEntry headsUpEntry, PinnedStatus requestedPinnedStatus) {
        NotificationEntry entry = headsUpEntry.requireEntry();
        entry.setHeadsUp(true);

        PinnedStatus pinnedStatus = getNewPinnedStatusForEntry(headsUpEntry, requestedPinnedStatus);
        setEntryPinned(headsUpEntry, pinnedStatus, "onEntryAdded");
        EventLogTags.writeSysuiHeadsUpStatus(entry.getKey(), 1 /* visible */);
        for (OnHeadsUpChangedListener listener : mListeners) {
            // TODO(b/382509804): It's odd that if pinnedStatus == PinnedStatus.NotPinned, then we
            //  still send isHeadsUp=true to listeners. Is this causing bugs?
            listener.onHeadsUpStateChanged(entry, true);
        }
        updateTopHeadsUpFlow();
        updateHeadsUpFlow();
    }

    private PinnedStatus getNewPinnedStatusForEntry(
            HeadsUpEntry headsUpEntry, PinnedStatus requestedPinnedStatus) {
        NotificationEntry entry = headsUpEntry.mEntry;
        if (entry == null) {
            return PinnedStatus.NotPinned;
        }
        boolean shouldBecomePinned = shouldHeadsUpBecomePinned(entry);
        if (!shouldBecomePinned) {
            return PinnedStatus.NotPinned;
        }

        if (!StatusBarNotifChips.isEnabled()
                && requestedPinnedStatus == PinnedStatus.PinnedByUser) {
            Log.wtf(TAG, "PinnedStatus.PinnedByUser not allowed if StatusBarNotifChips flag off");
            return PinnedStatus.NotPinned;
        }

        return requestedPinnedStatus;
    }

    /**
     * Remove a notification from the alerting entries.
     * @param key key of notification to remove
     */
    private void removeEntry(@NonNull String key, String reason) {
        HeadsUpEntry headsUpEntry = mHeadsUpEntryMap.get(key);
        boolean isWaiting;
        if (headsUpEntry == null) {
            headsUpEntry = mAvalancheController.getWaitingEntry(key);
            isWaiting = true;
        } else {
            isWaiting = false;
        }
        mLogger.logRemoveEntryRequest(key, reason, isWaiting);
        HeadsUpEntry finalHeadsUpEntry = headsUpEntry;
        Runnable runnable = () -> {
            mLogger.logRemoveEntry(key, reason, isWaiting);

            if (finalHeadsUpEntry == null) {
                return;
            }
            NotificationEntry entry = finalHeadsUpEntry.requireEntry();

            // If the notification is animating, we will remove it at the end of the animation.
            if (entry.isExpandAnimationRunning()) {
                return;
            }
            entry.demoteStickyHun();
            mHeadsUpEntryMap.remove(key);
            onEntryRemoved(finalHeadsUpEntry, reason);
            // TODO(b/328390331) move accessibility events to the view layer
            entry.sendAccessibilityEvent(AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED);
            if (NotificationThrottleHun.isEnabled()) {
                finalHeadsUpEntry.cancelAutoRemovalCallbacks("removeEntry");
            } else {
                finalHeadsUpEntry.reset();
            }
        };
        mAvalancheController.delete(headsUpEntry, runnable, "removeEntry");
    }

    /**
     * Manager-specific logic that should occur when an entry is removed.
     * @param headsUpEntry entry removed
     * @param reason why onEntryRemoved was called
     */
    @VisibleForTesting
    void onEntryRemoved(@NonNull HeadsUpEntry headsUpEntry, String reason) {
        NotificationEntry entry = headsUpEntry.requireEntry();
        entry.setHeadsUp(false);
        setEntryPinned(headsUpEntry, PinnedStatus.NotPinned, "onEntryRemoved");
        EventLogTags.writeSysuiHeadsUpStatus(entry.getKey(), 0 /* visible */);
        mLogger.logNotificationActuallyRemoved(entry);
        for (OnHeadsUpChangedListener listener : mListeners) {
            listener.onHeadsUpStateChanged(entry, false);
        }
        if (!NotificationThrottleHun.isEnabled()) {
            mEntryPool.release(headsUpEntry);
        }
        updateTopHeadsUpFlow();
        updateHeadsUpFlow();
        if (NotificationThrottleHun.isEnabled()) {
            NotificationEntry notifEntry = headsUpEntry.mEntry;
            if (notifEntry == null) {
                return;
            }
            // If reorder was just allowed and we called onEntryRemoved while iterating over
            // mEntriesToRemoveWhenReorderingAllowed, we should not remove from this list (and cause
            // ArrayIndexOutOfBoundsException). We don't need to in this case anyway, because we
            // clear mEntriesToRemoveWhenReorderingAllowed after removing these entries.
            if (!reason.equals(REASON_REORDER_ALLOWED)) {
                mEntriesToRemoveWhenReorderingAllowed.remove(notifEntry);
            }
        }
    }

    private void updateTopHeadsUpFlow() {
        mTopHeadsUpRow.setValue(getTopHeadsUpEntry());
    }

    private void updateHeadsUpFlow() {
        mHeadsUpNotificationRows.setValue(new HashSet<>(mHeadsUpEntryMap.values()));
    }

    @Override
    @NonNull
    public Flow<HeadsUpRowRepository> getTopHeadsUpRow() {
        return mTopHeadsUpRow;
    }

    @Override
    @NonNull
    public Flow<Set<HeadsUpRowRepository>> getActiveHeadsUpRows() {
        return mHeadsUpNotificationRows;
    }

    @Override
    @NonNull
    public StateFlow<Boolean> isHeadsUpAnimatingAway() {
        return mHeadsUpAnimatingAway;
    }

    @Override
    public boolean isHeadsUpAnimatingAwayValue() {
        return mHeadsUpAnimatingAway.getValue();
    }

    /**
     * Called to notify the listeners that the HUN animating away animation has ended.
     */
    @Override
    public void onEntryAnimatingAwayEnded(@NonNull NotificationEntry entry) {
        for (OnHeadsUpChangedListener listener : mListeners) {
            listener.onHeadsUpAnimatingAwayEnded(entry);
        }
    }

    private void updatePinnedMode() {
        boolean hasPinnedNotification = hasPinnedNotificationInternal();
        mPinnedNotificationStatus = pinnedNotificationStatusInternal();
        if (hasPinnedNotification == mHasPinnedNotification) {
            return;
        }
        mLogger.logUpdatePinnedMode(hasPinnedNotification, mPinnedNotificationStatus);
        mHasPinnedNotification = hasPinnedNotification;
        if (mHasPinnedNotification) {
            MetricsLogger.count(mContext, "note_peek", 1);
        }
        for (OnHeadsUpChangedListener listener : mListeners) {
            listener.onHeadsUpPinnedModeChanged(hasPinnedNotification);
        }
    }

    /**
     * Returns if the given notification is snoozed or not.
     */
    public boolean isSnoozed(@NonNull String packageName) {
        final String key = snoozeKey(packageName, mUser);
        Long snoozedUntil = mSnoozedPackages.get(key);
        if (snoozedUntil != null) {
            if (snoozedUntil > mSystemClock.elapsedRealtime()) {
                mLogger.logIsSnoozedReturned(key);
                return true;
            }
            mLogger.logPackageUnsnoozed(key);
            mSnoozedPackages.remove(key);
        }
        return false;
    }

    /**
     * Snoozes all current Heads Up Notifications.
     */
    @Override
    public void snooze() {
        List<String> keySet = new ArrayList<>(mHeadsUpEntryMap.keySet());
        keySet.addAll(mAvalancheController.getWaitingKeys());
        for (String key : keySet) {
            HeadsUpEntry entry = getHeadsUpEntry(key);
            if (entry == null || entry.mEntry == null) {
                continue;
            }
            String packageName = entry.mEntry.getSbn().getPackageName();
            String snoozeKey = snoozeKey(packageName, mUser);
            mLogger.logPackageSnoozed(snoozeKey);
            mSnoozedPackages.put(snoozeKey, mSystemClock.elapsedRealtime() + mSnoozeLengthMs);
        }
        mReleaseOnExpandFinish = true;
    }

    @NonNull
    private static String snoozeKey(@NonNull String packageName, int user) {
        return user + "," + packageName;
    }

    @Override
    public void addSwipedOutNotification(@NonNull String key) {
        mSwipedOutKeys.add(key);
    }

    @Nullable
    @VisibleForTesting
    HeadsUpEntry getHeadsUpEntry(@NonNull String key) {
        if (mHeadsUpEntryMap.containsKey(key)) {
            return mHeadsUpEntryMap.get(key);
        }
        return mAvalancheController.getWaitingEntry(key);
    }

    /**
     * Returns the top Heads Up Notification, which appears to show at first.
     */
    @Nullable
    public NotificationEntry getTopEntry() {
        HeadsUpEntry topEntry = getTopHeadsUpEntry();
        return (topEntry != null) ? topEntry.mEntry : null;
    }

    @Nullable
    private HeadsUpEntry getTopHeadsUpEntry() {
        if (mHeadsUpEntryMap.isEmpty()) {
            return null;
        }
        HeadsUpEntry topEntry = null;
        for (HeadsUpEntry entry: mHeadsUpEntryMap.values()) {
            if (topEntry == null || entry.compareTo(topEntry) < 0) {
                topEntry = entry;
            }
        }
        return topEntry;
    }

    /**
     * Sets the current user.
     */
    public void setUser(int user) {
        mUser = user;
    }

    /** Returns the ID of the current user. */
    public int getUser() {
        return  mUser;
    }

    private String getEntryMapStr() {
        if (mHeadsUpEntryMap.isEmpty()) {
            return "";
        }
        StringBuilder entryMapStr = new StringBuilder();
        for (HeadsUpEntry entry: mHeadsUpEntryMap.values()) {
            entryMapStr.append("\n ").append(
                    entry.mEntry == null ? "null" : entry.mEntry.getKey());
        }
        return entryMapStr.toString();
    }

    @Override
    public @Nullable Region getTouchableRegion() {
        NotificationEntry topEntry = getTopEntry();

        // This call could be made in an inconsistent state while the pinnedMode hasn't been
        // updated yet, but callbacks leading out of the headsUp manager, querying it. Let's
        // therefore also check if the topEntry is null.
        if (!hasPinnedHeadsUp() || topEntry == null) {
            return null;
        } else {
            ExpandableNotificationRow topRow = topEntry.getRow();
            if (topEntry.rowIsChildInGroup()) {
                if (NotificationBundleUi.isEnabled()) {
                    if (topRow.getNotificationParent() != null) {
                        topRow = topRow.getNotificationParent();
                    }
                } else {
                    final NotificationEntry groupSummary =
                            mGroupMembershipManager.getGroupSummary(topEntry);
                    if (groupSummary != null) {
                        topEntry = groupSummary;
                        topRow = topEntry.getRow();
                    }
                }
            }

            int[] tmpArray = new int[2];
            topRow.getLocationOnScreen(tmpArray);
            int minX = tmpArray[0];
            int maxX = tmpArray[0] + topRow.getWidth();
            int height = topRow.getIntrinsicHeight();
            final boolean stretchToTop = tmpArray[1] <= mHeadsUpInset;
            mTouchableRegion.set(minX, stretchToTop ? 0 : tmpArray[1], maxX, tmpArray[1] + height);
            return mTouchableRegion;
        }
    }

    @Override
    public void setHeadsUpAnimatingAway(boolean headsUpAnimatingAway) {
        if (headsUpAnimatingAway != mHeadsUpAnimatingAway.getValue()) {
            for (OnHeadsUpPhoneListenerChange listener : mHeadsUpPhoneListeners) {
                listener.onHeadsUpAnimatingAwayStateChanged(headsUpAnimatingAway);
            }
            mHeadsUpAnimatingAway.setValue(headsUpAnimatingAway);
        }
    }

    private void onShadeOrQsExpanded(Boolean isExpanded) {
        if (isExpanded != mIsShadeOrQsExpanded) {
            mIsShadeOrQsExpanded = isExpanded;
            if (!SceneContainerFlag.isEnabled() && isExpanded) {
                mHeadsUpAnimatingAway.setValue(false);
            }
        }
    }

    private void onQsExpanded(Boolean isQsExpanded) {
        if (SceneContainerFlag.isUnexpectedlyInLegacyMode()) return;
        if (isQsExpanded != mIsQsExpanded) mIsQsExpanded = isQsExpanded;
    }

    @Override
    public void dump(@NonNull PrintWriter pw, @NonNull String[] args) {
        pw.println("HeadsUpManager state:");
        dumpInternal(pw, args);
    }

    private void dumpInternal(@NonNull PrintWriter pw, @NonNull String[] args) {
        pw.print("  mTouchAcceptanceDelay="); pw.println(mTouchAcceptanceDelay);
        pw.print("  mSnoozeLengthMs="); pw.println(mSnoozeLengthMs);
        pw.print("  now="); pw.println(mSystemClock.elapsedRealtime());
        pw.print("  mUser="); pw.println(mUser);
        for (HeadsUpEntry entry: mHeadsUpEntryMap.values()) {
            pw.println(entry.mEntry == null ? "null" : entry.mEntry);
        }
        int n = mSnoozedPackages.size();
        pw.println("  snoozed packages: " + n);
        for (int i = 0; i < n; i++) {
            pw.print("    "); pw.print(mSnoozedPackages.valueAt(i));
            pw.print(", "); pw.println(mSnoozedPackages.keyAt(i));
        }
        pw.print("  mBarState=");
        pw.println(mStatusBarState);
        pw.print("  mTouchableRegion=");
        pw.println(mTouchableRegion);
    }

    @Override
    public boolean hasPinnedHeadsUp() {
        return mHasPinnedNotification;
    }

    @Override
    @NonNull
    public PinnedStatus pinnedHeadsUpStatus() {
        if (!StatusBarNotifChips.isEnabled()) {
            return mHasPinnedNotification ? PinnedStatus.PinnedBySystem : PinnedStatus.NotPinned;
        }
        return mPinnedNotificationStatus;
    }

    private boolean hasPinnedNotificationInternal() {
        for (String key : mHeadsUpEntryMap.keySet()) {
            HeadsUpEntry entry = getHeadsUpEntry(key);
            if (entry != null && entry.mEntry != null && entry.mEntry.isRowPinned()) {
                return true;
            }
        }
        return false;
    }

    private PinnedStatus pinnedNotificationStatusInternal() {
        for (String key : mHeadsUpEntryMap.keySet()) {
            HeadsUpEntry entry = getHeadsUpEntry(key);
            if (entry.mEntry != null && entry.mEntry.isRowPinned()) {
                return entry.mEntry.getPinnedStatus();
            }
        }
        return PinnedStatus.NotPinned;
    }

    /**
     * Unpins all pinned Heads Up Notifications.
     * @param userUnPinned The unpinned action is trigger by user real operation.
     */
    @Override
    public void unpinAll(boolean userUnPinned) {
        for (String key : mHeadsUpEntryMap.keySet()) {
            HeadsUpEntry headsUpEntry = getHeadsUpEntry(key);
            if (headsUpEntry == null) {
                Log.wtf(TAG, "Couldn't find entry " + key + " in unpinAll");
                continue;
            }
            mLogger.logUnpinEntryRequest(key);
            Runnable runnable = () -> {
                mLogger.logUnpinEntry(key);

                setEntryPinned(headsUpEntry, PinnedStatus.NotPinned, "unpinAll");
                // maybe it got un sticky
                headsUpEntry.updateEntry(false /* updatePostTime */, "unpinAll");

                // when the user unpinned all of HUNs by moving one HUN, all of HUNs should not stay
                // on the screen.
                if (userUnPinned
                        && headsUpEntry.mEntry != null
                        && headsUpEntry.mEntry.mustStayOnScreen()) {
                    headsUpEntry.mEntry.setHeadsUpIsVisible();
                }
            };
            mAvalancheController.delete(headsUpEntry, runnable, "unpinAll");
        }
    }

    @Override
    public void setRemoteInputActive(
            @NonNull NotificationEntry entry, boolean remoteInputActive) {
        HeadsUpEntry headsUpEntry = mHeadsUpEntryMap.get(entry.getKey());
        if (headsUpEntry != null && headsUpEntry.mRemoteInputActive != remoteInputActive) {
            headsUpEntry.mRemoteInputActive = remoteInputActive;
            if (ExpandHeadsUpOnInlineReply.isEnabled() && remoteInputActive) {
                headsUpEntry.mRemoteInputActivatedAtLeastOnce = true;
            }
            if (remoteInputActive) {
                headsUpEntry.cancelAutoRemovalCallbacks("setRemoteInputActive(true)");
            } else {
                headsUpEntry.updateEntry(false /* updatePostTime */, "setRemoteInputActive(false)");
            }
            updateTopHeadsUpFlow();
        }
    }

    @Override
    public void setGutsShown(@NonNull NotificationEntry entry, boolean gutsShown) {
        HeadsUpEntry headsUpEntry = getHeadsUpEntry(entry.getKey());
        if (headsUpEntry == null) return;
        if (entry.isRowPinned() || !gutsShown) {
            headsUpEntry.setGutsShownPinned(gutsShown);
        }
    }

    @Override
    public void extendHeadsUp() {
        HeadsUpEntry topEntry = getTopHeadsUpEntryPhone();
        if (topEntry == null) {
            return;
        }
        topEntry.extendPulse();
    }

    @Nullable
    private HeadsUpEntry getTopHeadsUpEntryPhone() {
        if (SceneContainerFlag.isEnabled()) {
            return (HeadsUpEntry) mTopHeadsUpRow.getValue();
        } else {
            return getTopHeadsUpEntry();
        }
    }

    @NonNull
    @Override
    public StateFlow<Boolean> isTrackingHeadsUp() {
        return mTrackingHeadsUp;
    }

    /**
     * Compare two entries and decide how they should be ranked.
     *
     * @return -1 if the first argument should be ranked higher than the second, 1 if the second
     * one should be ranked higher and 0 if they are equal.
     */
    public int compare(@Nullable NotificationEntry a, @Nullable NotificationEntry b) {
        if (a == null || b == null) {
            return Boolean.compare(a == null, b == null);
        }
        HeadsUpEntry aEntry = getHeadsUpEntry(a.getKey());
        HeadsUpEntry bEntry = getHeadsUpEntry(b.getKey());
        if (aEntry == null || bEntry == null) {
            return Boolean.compare(aEntry == null, bEntry == null);
        }
        return aEntry.compareTo(bEntry);
    }

    /**
     * Set an entry to be expanded and therefore stick in the heads up area if it's pinned
     * until it's collapsed again.
     */
    @Override
    public void setExpanded(@NonNull String entryKey, @NonNull ExpandableNotificationRow row,
            boolean expanded) {
        NotificationBundleUi.unsafeAssertInNewMode();
        HeadsUpEntry headsUpEntry = getHeadsUpEntry(entryKey);
        if (headsUpEntry != null && row.getPinnedStatus().isPinned()) {
            headsUpEntry.setExpanded(expanded);
        }
    }

    /**
     * Set an entry to be expanded and therefore stick in the heads up area if it's pinned
     * until it's collapsed again.
     */
    @Override
    public void setExpanded(@NonNull NotificationEntry entry, boolean expanded) {
        NotificationBundleUi.assertInLegacyMode();
        HeadsUpEntry headsUpEntry = getHeadsUpEntry(entry.getKey());
        if (headsUpEntry != null && entry.isRowPinned()) {
            headsUpEntry.setExpanded(expanded);
        }
    }

    /**
     * Notes that the user took an action on an entry that might indirectly cause the system or the
     * app to remove the notification.
     *
     * @param entry the entry that might be indirectly removed by the user's action
     *
     * @see HeadsUpCoordinator.mActionPressListener
     * @see #canRemoveImmediately(String)
     */
    public void setUserActionMayIndirectlyRemove(@NonNull String entryKey) {
        HeadsUpEntry headsUpEntry = getHeadsUpEntry(entryKey);
        if (headsUpEntry != null) {
            headsUpEntry.mUserActionMayIndirectlyRemove = true;
        }
    }

    /**
     * Whether or not the entry can be removed currently.  If it hasn't been on screen long enough
     * it should not be removed unless forced
     * @param key the key to check if removable
     * @return true if the entry can be removed
     */
    @Override
    public boolean canRemoveImmediately(@NonNull String key) {
        if (mSwipedOutKeys.contains(key)) {
            // We always instantly dismiss views being manually swiped out.
            mSwipedOutKeys.remove(key);
            return true;
        }

        HeadsUpEntry headsUpEntry = mHeadsUpEntryMap.get(key);
        HeadsUpEntry topEntry = getTopHeadsUpEntryPhone();

        if (headsUpEntry == null || headsUpEntry != topEntry) {
            return true;
        }

        if (headsUpEntry.mUserActionMayIndirectlyRemove) {
            return true;
        }
        return headsUpEntry.wasShownLongEnough()
                || (headsUpEntry.mEntry != null && headsUpEntry.mEntry.isRowDismissed());
    }

    /**
     * @return true if the entry with the given key is (pinned and expanded) or (has an active
     * remote input)
     */
    @Override
    public boolean isSticky(String key) {
        HeadsUpEntry headsUpEntry = getHeadsUpEntry(key);
        if (headsUpEntry != null) {
            return headsUpEntry.isSticky();
        }
        return false;
    }

    @NonNull
    @VisibleForTesting
    HeadsUpEntry createHeadsUpEntry(NotificationEntry entry) {
        if (NotificationThrottleHun.isEnabled()) {
            return new HeadsUpEntry(entry);
        } else {
            HeadsUpEntry headsUpEntry = mEntryPool.acquire();
            headsUpEntry.setEntry(entry);
            return headsUpEntry;
        }
    }

    /**
     * Determines if the notification is for a critical call that must display on top of an active
     * input notification.
     * The call isOngoing check is for a special case of incoming calls (see b/164291424).
     */
    private static boolean isCriticalCallNotif(NotificationEntry entry) {
        Notification n = entry.getSbn().getNotification();
        boolean isIncomingCall = n.isStyle(Notification.CallStyle.class) && n.extras.getInt(
                Notification.EXTRA_CALL_TYPE) == Notification.CallStyle.CALL_TYPE_INCOMING;
        return isIncomingCall || (entry.getSbn().isOngoing()
                && Notification.CATEGORY_CALL.equals(n.category));
    }

    @VisibleForTesting
    final OnReorderingAllowedListener mOnReorderingAllowedListener = () -> {
        if (NotificationThrottleHun.isEnabled()) {
            mAvalancheController.setEnableAtRuntime(true);
            if (mEntriesToRemoveWhenReorderingAllowed.isEmpty()) {
                return;
            }
        }
        mAnimationStateHandler.setHeadsUpGoingAwayAnimationsAllowed(false);
        for (NotificationEntry entry : mEntriesToRemoveWhenReorderingAllowed) {
            if (entry != null && isHeadsUpEntry(entry.getKey())) {
                // Maybe the heads-up was removed already
                removeEntry(entry.getKey(), REASON_REORDER_ALLOWED);
            }
        }
        mEntriesToRemoveWhenReorderingAllowed.clear();
        mAnimationStateHandler.setHeadsUpGoingAwayAnimationsAllowed(true);
    };

    private final OnReorderingBannedListener mOnReorderingBannedListener = () -> {
        if (mAvalancheController != null) {
            // In open shade the first HUN is pinned, and visual stability logic prevents us from
            // unpinning this first HUN as long as the shade remains open. AvalancheController only
            // shows the next HUN when the currently showing HUN is unpinned, so we must disable
            // throttling here so that the incoming HUN stream is not forever paused. This is reset
            // when reorder becomes allowed.
            mAvalancheController.setEnableAtRuntime(false);

            // Note that we cannot do the above when
            // 1) The remove runnable runs because its delay means it may not run before shade close
            // 2) Reordering is allowed again (when shade closes) because the HUN appear animation
            // will have started by then
        }
    };

    private final StatusBarStateController.StateListener
            mStatusBarStateListener = new StatusBarStateController.StateListener() {
        @Override
        public void onStateChanged(int newState) {
            boolean wasKeyguard = mStatusBarState == StatusBarState.KEYGUARD;
            boolean isKeyguard = newState == StatusBarState.KEYGUARD;
            mStatusBarState = newState;

            if (wasKeyguard && !isKeyguard && mBypassController.getBypassEnabled()) {
                ArrayList<String> keysToRemove = new ArrayList<>();
                for (HeadsUpEntry entry : getHeadsUpEntryList()) {
                    if (entry.mEntry != null && entry.mEntry.isBubble() && !entry.isSticky()) {
                        keysToRemove.add(entry.mEntry.getKey());
                    }
                }
                for (String key : keysToRemove) {
                    removeEntry(key, "mStatusBarStateListener");
                }
            }
        }

        @Override
        public void onDozingChanged(boolean isDozing) {
            if (!isDozing) {
                // Let's make sure all huns we got while dozing time out within the normal timeout
                // duration. Otherwise they could get stuck for a very long time
                for (HeadsUpEntry entry : getHeadsUpEntryList()) {
                    entry.updateEntry(true /* updatePostTime */, "onDozingChanged(false)");
                }
            }
        }
    };

    /**
     * This represents a notification and how long it is in a heads up mode. It also manages its
     * lifecycle automatically when created. This class is public because it is exposed by methods
     * of AvalancheController that take it as param.
     */
    public class HeadsUpEntry implements Comparable<HeadsUpEntry>, HeadsUpRowRepository {
        public boolean mRemoteInputActivatedAtLeastOnce;
        public boolean mRemoteInputActive;
        public boolean mUserActionMayIndirectlyRemove;

        private boolean mExpanded;
        @VisibleForTesting
        boolean mWasUnpinned;

        @Nullable public NotificationEntry mEntry;
        public long mPostTime;
        public long mEarliestRemovalTime;

        @Nullable private Runnable mRemoveRunnable;

        @Nullable private Runnable mCancelRemoveRunnable;

        private boolean mGutsShownPinned;
        /** The *current* pinned status of this HUN. */
        private final MutableStateFlow<PinnedStatus> mPinnedStatus =
                StateFlowKt.MutableStateFlow(PinnedStatus.NotPinned);

        /**
         * The *requested* pinned status of this HUN. {@link AvalancheController} uses this value to
         * know if the current HUN needs to be removed so that a pinned-by-user HUN can show.
         */
        private PinnedStatus mRequestedPinnedStatus = PinnedStatus.NotPinned;

        /**
         * If the time this entry has been on was extended
         */
        private boolean extended;

        public HeadsUpEntry() {
            NotificationThrottleHun.assertInLegacyMode();
        }

        public HeadsUpEntry(NotificationEntry entry) {
            // Attach NotificationEntry for AvalancheController to log key and
            // record mPostTime for AvalancheController sorting
            setEntry(entry, createRemoveRunnable(entry));
        }

        @Override
        @NonNull
        public String getKey() {
            return requireEntry().getKey();
        }

        @Override
        @NonNull
        public Object getElementKey() {
            return requireEntry().getRow();
        }

        private NotificationEntry requireEntry() {
            return Objects.requireNonNull(mEntry);
        }

        @Override
        @NonNull
        public StateFlow<PinnedStatus> getPinnedStatus() {
            return mPinnedStatus;
        }

        /** Attach a NotificationEntry. */
        public void setEntry(@NonNull final NotificationEntry entry) {
            NotificationThrottleHun.assertInLegacyMode();
            setEntry(entry, createRemoveRunnable(entry));
        }

        private void setEntry(
                @NonNull final NotificationEntry entry,
                @Nullable Runnable removeRunnable) {
            mEntry = entry;
            mRemoveRunnable = removeRunnable;

            mPostTime = calculatePostTime();
            updateEntry(true /* updatePostTime */, "setEntry");

            if (NotificationThrottleHun.isEnabled()) {
                mEntriesToRemoveWhenReorderingAllowed.add(entry);
                if (!mVisualStabilityProvider.isReorderingAllowed()) {
                    entry.setSeenInShade(true);
                }
            }
        }

        /** Sets what pinned status this HUN is requesting. */
        void setRequestedPinnedStatus(PinnedStatus pinnedStatus) {
            if (!StatusBarNotifChips.isEnabled() && pinnedStatus == PinnedStatus.PinnedByUser) {
                Log.w(TAG, "PinnedByUser status not allowed if StatusBarNotifChips is disabled");
                mRequestedPinnedStatus = PinnedStatus.NotPinned;
            } else {
                mRequestedPinnedStatus = pinnedStatus;
            }
        }

        PinnedStatus getRequestedPinnedStatus() {
            return mRequestedPinnedStatus;
        }

        @VisibleForTesting
        void setRowPinnedStatus(PinnedStatus pinnedStatus) {
            if (mEntry != null) mEntry.setRowPinnedStatus(pinnedStatus);
            mPinnedStatus.setValue(pinnedStatus);
        }

        /**
         * An interface that returns the amount of time left this HUN should show.
         */
        private interface FinishTimeUpdater {
            long updateAndGetTimeRemaining();
        }

        /**
         * Updates an entry's removal time.
         * @param updatePostTime whether or not to refresh the post time
         */
        public void updateEntry(boolean updatePostTime, @Nullable String reason) {
            updateEntry(updatePostTime, /* updateEarliestRemovalTime= */ true, reason);
        }

        /**
         * Updates an entry's removal time.
         * @param updatePostTime whether or not to refresh the post time
         * @param updateEarliestRemovalTime whether this update should further delay removal
         */
        public void updateEntry(boolean updatePostTime, boolean updateEarliestRemovalTime,
                @Nullable String reason) {
            Runnable runnable = () -> {
                if (mEntry == null) {
                    Log.wtf(TAG, "#updateEntry called with null mEntry; returning early");
                    return;
                }
                mLogger.logUpdateEntry(mEntry, updatePostTime, reason);

                final long now = mSystemClock.elapsedRealtime();
                if (updateEarliestRemovalTime) {
                    if (StatusBarNotifChips.isEnabled()
                            && mPinnedStatus.getValue() == PinnedStatus.PinnedByUser) {
                        mEarliestRemovalTime = now + mMinimumDisplayTimeForUserInitiated;
                    } else {
                        mEarliestRemovalTime = now + mMinimumDisplayTimeDefault;
                    }
                }

                if (updatePostTime) {
                    mPostTime = Math.max(mPostTime, now);
                }
            };
            mAvalancheController.update(this, runnable, "updateEntry reason:"
                    + reason + " updatePostTime:" + updatePostTime);

            if (isSticky()) {
                cancelAutoRemovalCallbacks("updateEntry (sticky)");
                return;
            }

            FinishTimeUpdater finishTimeCalculator = () -> {
                RemainingDuration remainingDuration =
                        mAvalancheController.getDuration(this, mAutoDismissTime);

                if (remainingDuration instanceof RemainingDuration.HideImmediately) {
                    /* Check if */ StatusBarNotifChips.isUnexpectedlyInLegacyMode();
                    return 0;
                }

                int remainingTimeoutMs;
                if (isStickyForSomeTime()) {
                    remainingTimeoutMs = mStickyForSomeTimeAutoDismissTime;
                } else {
                    remainingTimeoutMs =
                            ((RemainingDuration.UpdatedDuration) remainingDuration).getDuration();
                }
                final long duration = getRecommendedHeadsUpTimeoutMs(remainingTimeoutMs);
                final long timeoutTimestamp =
                        mPostTime + duration + (extended ? mExtensionTime : 0);

                final long now = mSystemClock.elapsedRealtime();
                return NotificationThrottleHun.isEnabled()
                        ? Math.max(timeoutTimestamp, mEarliestRemovalTime) - now
                        : Math.max(timeoutTimestamp - now, mMinimumDisplayTimeDefault);
            };
            scheduleAutoRemovalCallback(finishTimeCalculator, "updateEntry (not sticky)");

            // Notify the manager, that the posted time has changed.
            updateTopHeadsUpFlow();

            mEntriesToRemoveAfterExpand.remove(mEntry);
            if (!NotificationThrottleHun.isEnabled()) {
                mEntriesToRemoveWhenReorderingAllowed.remove(mEntry);
            }
        }

        private void extendPulse() {
            if (!extended) {
                extended = true;
                updateEntry(false, "extendPulse()");
            }
        }

        /**
         * Whether or not the notification is "sticky" i.e. should stay on screen regardless
         * of the timer (forever) and should be removed externally.
         * @return true if the notification is sticky
         */
        public boolean isSticky() {
            if (mGutsShownPinned) return true;

            if (mEntry == null) return false;

            if (ExpandHeadsUpOnInlineReply.isEnabled()) {
                // we don't consider pinned and expanded huns as sticky after the remote input
                // has been activated for them
                if (!mRemoteInputActive && mRemoteInputActivatedAtLeastOnce) {
                    return false;
                }
            }

            // Promoted notifications are always shown as expanded, and we don't want them to ever
            // be sticky.
            boolean isStickyDueToExpansion =
                    mEntry.isRowPinned() && mExpanded && !mEntry.isPromotedOngoing();

            return isStickyDueToExpansion
                    || mRemoteInputActive
                    || hasFullScreenIntent(mEntry);
        }

        public boolean isStickyForSomeTime() {
            if (mEntry == null) return false;

            return mEntry.isStickyAndNotDemoted();
        }

        /**
         * Whether the notification has been on screen long enough and can be removed.
         * @return true if the notification has been on screen long enough
         */
        public boolean wasShownLongEnough() {
            return mEarliestRemovalTime < mSystemClock.elapsedRealtime();
        }

        public int compareNonTimeFields(HeadsUpEntry headsUpEntry) {
            if (mEntry == null && headsUpEntry.mEntry == null) {
                return 0;
            } else if (headsUpEntry.mEntry == null) {
                return -1;
            } else if (mEntry == null) {
                return 1;
            }

            boolean selfFullscreen = hasFullScreenIntent(mEntry);
            boolean otherFullscreen = hasFullScreenIntent(headsUpEntry.mEntry);
            if (selfFullscreen && !otherFullscreen) {
                return -1;
            } else if (!selfFullscreen && otherFullscreen) {
                return 1;
            }

            boolean selfCall = isCriticalCallNotif(mEntry);
            boolean otherCall = isCriticalCallNotif(headsUpEntry.mEntry);

            if (selfCall && !otherCall) {
                return -1;
            } else if (!selfCall && otherCall) {
                return 1;
            }

            if (mRemoteInputActive && !headsUpEntry.mRemoteInputActive) {
                return -1;
            } else if (!mRemoteInputActive && headsUpEntry.mRemoteInputActive) {
                return 1;
            }
            return 0;
        }

        public int compareTo(@NonNull HeadsUpEntry headsUpEntry) {
            if (mEntry == null && headsUpEntry.mEntry == null) {
                return 0;
            } else if (headsUpEntry.mEntry == null) {
                return -1;
            } else if (mEntry == null) {
                return 1;
            }
            boolean isPinned = mEntry.isRowPinned();
            boolean otherPinned = headsUpEntry.mEntry.isRowPinned();
            if (isPinned && !otherPinned) {
                return -1;
            } else if (!isPinned && otherPinned) {
                return 1;
            }
            int nonTimeCompareResult = compareNonTimeFields(headsUpEntry);
            if (nonTimeCompareResult != 0) {
                return nonTimeCompareResult;
            }
            if (mPostTime > headsUpEntry.mPostTime) {
                return -1;
            } else if (mPostTime == headsUpEntry.mPostTime) {
                return mEntry.getKey().compareTo(headsUpEntry.mEntry.getKey());
            } else {
                return 1;
            }
        }

        @Override
        public int hashCode() {
            if (mEntry == null) return super.hashCode();
            int result = mEntry.getKey().hashCode();
            result = 31 * result;
            return result;
        }

        @Override
        public boolean equals(@Nullable Object o) {
            if (this == o) return true;
            if (!(o instanceof HeadsUpEntry otherHeadsUpEntry)) return false;
            if (mEntry != null && otherHeadsUpEntry.mEntry != null) {
                return mEntry.getKey().equals(otherHeadsUpEntry.mEntry.getKey());
            }
            return false;
        }

        public void setExpanded(boolean expanded) {
            if (this.mExpanded == expanded) {
                return;
            }

            this.mExpanded = expanded;
            if (expanded) {
                cancelAutoRemovalCallbacks("setExpanded(true)");
            } else {
                updateEntry(false /* updatePostTime */, "setExpanded(false)");
            }
        }

        public void setGutsShownPinned(boolean gutsShownPinned) {
            if (mGutsShownPinned == gutsShownPinned) {
                return;
            }

            mGutsShownPinned = gutsShownPinned;
            if (gutsShownPinned) {
                cancelAutoRemovalCallbacks("setGutsShownPinned(true)");
            } else {
                updateEntry(false /* updatePostTime */, "setGutsShownPinned(false)");
            }
        }

        public void reset() {
            NotificationThrottleHun.assertInLegacyMode();
            cancelAutoRemovalCallbacks("reset()");
            mEntry = null;
            mRemoveRunnable = null;
            mExpanded = false;
            mRemoteInputActive = false;
            mGutsShownPinned = false;
            extended = false;
        }

        /**
         * Clear any pending removal runnables.
         */
        public void cancelAutoRemovalCallbacks(@Nullable String reason) {
            Runnable runnable = () -> {
                final boolean removed = cancelAutoRemovalCallbackInternal();

                if (removed) {
                    mLogger.logAutoRemoveCanceled(mEntry, reason);
                }
            };
            if (mEntry != null && isHeadsUpEntry(mEntry.getKey())) {
                mLogger.logAutoRemoveCancelRequest(this.mEntry, reason);
                mAvalancheController.update(this, runnable, reason + " cancelAutoRemovalCallbacks");
            } else {
                // Just removed
                runnable.run();
            }
        }

        private void scheduleAutoRemovalCallback(FinishTimeUpdater finishTimeCalculator,
                @NonNull String reason) {
            if (mEntry == null) {
                Log.wtf(TAG, "#scheduleAutoRemovalCallback with null mEntry; returning early");
                return;
            }
            mLogger.logAutoRemoveRequest(mEntry, reason);
            Runnable runnable = () -> {
                long delayMs = finishTimeCalculator.updateAndGetTimeRemaining();

                if (mRemoveRunnable == null) {
                    Log.wtf(TAG, "scheduleAutoRemovalCallback with no callback set");
                    return;
                }

                final boolean deletedExistingRemovalRunnable = cancelAutoRemovalCallbackInternal();
                mCancelRemoveRunnable = mExecutor.executeDelayed(mRemoveRunnable,
                        delayMs);

                if (deletedExistingRemovalRunnable) {
                    mLogger.logAutoRemoveRescheduled(mEntry, delayMs, reason);
                } else {
                    mLogger.logAutoRemoveScheduled(mEntry, delayMs, reason);
                }
            };
            mAvalancheController.update(this, runnable,
                    reason + " scheduleAutoRemovalCallback");
        }

        public boolean cancelAutoRemovalCallbackInternal() {
            final boolean scheduled = (mCancelRemoveRunnable != null);

            if (scheduled) {
                mCancelRemoveRunnable.run();  // Delete removal runnable from Executor queue
                mCancelRemoveRunnable = null;
            }

            return scheduled;
        }

        /**
         * Remove the entry at the earliest allowed removal time.
         */
        public void removeAsSoonAsPossible() {
            if (mRemoveRunnable != null) {

                FinishTimeUpdater finishTimeCalculator = () ->
                        mEarliestRemovalTime - mSystemClock.elapsedRealtime();
                scheduleAutoRemovalCallback(finishTimeCalculator, "removeAsSoonAsPossible");
            }
        }

        /** Creates a runnable to remove this notification from the alerting entries. */
        private Runnable createRemoveRunnable(NotificationEntry entry) {
            return () -> {
                if (!NotificationThrottleHun.isEnabled()
                        && !mVisualStabilityProvider.isReorderingAllowed()
                        // We don't want to allow reordering while pulsing, but headsup need to
                        // time out anyway
                        && !entry.showingPulsing()) {
                    mEntriesToRemoveWhenReorderingAllowed.add(entry);
                    mVisualStabilityProvider.addTemporaryReorderingAllowedListener(
                            mOnReorderingAllowedListener);
                } else if (mTrackingHeadsUp.getValue()) {
                    mEntriesToRemoveAfterExpand.add(entry);
                    mLogger.logRemoveEntryAfterExpand(entry);
                } else if (mVisualStabilityProvider.isReorderingAllowed()
                        || entry.showingPulsing()) {
                    removeEntry(entry.getKey(), "createRemoveRunnable");
                }
            };
        }

        /**
         * Calculate what the post time of a notification is at some current time.
         * @return the post time
         */
        private long calculatePostTime() {
            // The actual post time will be just after the heads-up really slided in
            return mSystemClock.elapsedRealtime() + mTouchAcceptanceDelay;
        }

        /**
         * Get user-preferred or default timeout duration. The larger one will be returned.
         * @return milliseconds before auto-dismiss
         */
        private int getRecommendedHeadsUpTimeoutMs(int requestedTimeout) {
            return mAccessibilityMgr.getRecommendedTimeoutMillis(
                    requestedTimeout,
                    AccessibilityManager.FLAG_CONTENT_CONTROLS
                            | AccessibilityManager.FLAG_CONTENT_ICONS
                            | AccessibilityManager.FLAG_CONTENT_TEXT);
        }
    }
}
