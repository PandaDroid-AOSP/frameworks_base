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

package com.android.systemui.statusbar.notification.stack;

import static com.android.server.notification.Flags.FLAG_SCREENSHARE_NOTIFICATION_HIDING;
import static com.android.systemui.log.LogBufferHelperKt.logcatLogBuffer;
import static com.android.systemui.statusbar.StatusBarState.KEYGUARD;
import static com.android.systemui.statusbar.StatusBarState.SHADE;
import static com.android.systemui.statusbar.notification.row.NotificationRowContentBinder.FLAG_CONTENT_VIEW_ALL;
import static com.android.systemui.statusbar.notification.stack.NotificationStackScrollLayout.ROWS_ALL;

import static kotlinx.coroutines.flow.FlowKt.emptyFlow;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import android.metrics.LogMaker;
import android.platform.test.annotations.DisableFlags;
import android.platform.test.annotations.EnableFlags;
import android.testing.TestableLooper;
import android.view.MotionEvent;
import android.view.ViewTreeObserver;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.SmallTest;

import com.android.internal.logging.MetricsLogger;
import com.android.internal.logging.UiEventLogger;
import com.android.internal.logging.nano.MetricsProto;
import com.android.internal.statusbar.IStatusBarService;
import com.android.systemui.ExpandHelper;
import com.android.systemui.SysuiTestCase;
import com.android.systemui.classifier.FalsingCollectorFake;
import com.android.systemui.classifier.FalsingManagerFake;
import com.android.systemui.dump.DumpManager;
import com.android.systemui.flags.DisableSceneContainer;
import com.android.systemui.flags.EnableSceneContainer;
import com.android.systemui.keyguard.data.repository.KeyguardTransitionRepository;
import com.android.systemui.kosmos.KosmosJavaAdapter;
import com.android.systemui.media.controls.ui.controller.KeyguardMediaController;
import com.android.systemui.plugins.ActivityStarter;
import com.android.systemui.plugins.statusbar.NotificationMenuRowPlugin;
import com.android.systemui.plugins.statusbar.NotificationMenuRowPlugin.OnMenuEventListener;
import com.android.systemui.plugins.statusbar.StatusBarStateController;
import com.android.systemui.power.domain.interactor.PowerInteractor;
import com.android.systemui.scene.ui.view.WindowRootView;
import com.android.systemui.shade.ShadeController;
import com.android.systemui.statusbar.LockscreenShadeTransitionController;
import com.android.systemui.statusbar.NotificationLockscreenUserManager;
import com.android.systemui.statusbar.NotificationLockscreenUserManager.UserChangedListener;
import com.android.systemui.statusbar.SysuiStatusBarStateController;
import com.android.systemui.statusbar.notification.ColorUpdateLogger;
import com.android.systemui.statusbar.notification.DynamicPrivacyController;
import com.android.systemui.statusbar.notification.NotificationWakeUpCoordinator;
import com.android.systemui.statusbar.notification.collection.NotifCollection;
import com.android.systemui.statusbar.notification.collection.NotifPipeline;
import com.android.systemui.statusbar.notification.collection.provider.NotificationDismissibilityProvider;
import com.android.systemui.statusbar.notification.collection.provider.VisibilityLocationProviderDelegator;
import com.android.systemui.statusbar.notification.collection.render.GroupExpansionManager;
import com.android.systemui.statusbar.notification.collection.render.NotificationVisibilityProvider;
import com.android.systemui.statusbar.notification.headsup.HeadsUpManager;
import com.android.systemui.statusbar.notification.headsup.HeadsUpTouchHelper;
import com.android.systemui.statusbar.notification.init.NotificationsController;
import com.android.systemui.statusbar.notification.row.ExpandableNotificationRow;
import com.android.systemui.statusbar.notification.row.NotificationGutsManager;
import com.android.systemui.statusbar.notification.row.NotificationTestHelper;
import com.android.systemui.statusbar.notification.shared.GroupHunAnimationFix;
import com.android.systemui.statusbar.notification.stack.NotificationStackScrollLayoutController.NotificationPanelEvent;
import com.android.systemui.statusbar.notification.stack.NotificationSwipeHelper.NotificationCallback;
import com.android.systemui.statusbar.notification.stack.ui.viewbinder.NotificationListViewBinder;
import com.android.systemui.statusbar.phone.HeadsUpAppearanceController;
import com.android.systemui.statusbar.phone.KeyguardBypassController;
import com.android.systemui.statusbar.policy.ConfigurationController;
import com.android.systemui.statusbar.policy.ResourcesSplitShadeStateController;
import com.android.systemui.statusbar.policy.SensitiveNotificationProtectionController;
import com.android.systemui.tuner.TunerService;
import com.android.systemui.util.settings.SecureSettings;
import com.android.systemui.wallpapers.domain.interactor.WallpaperInteractor;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.inject.Provider;

/**
 * Tests for {@link NotificationStackScrollLayoutController}.
 */
@SmallTest
@TestableLooper.RunWithLooper(setAsMainLooper = true)
@RunWith(AndroidJUnit4.class)
public class NotificationStackScrollLayoutControllerTest extends SysuiTestCase {

    protected KosmosJavaAdapter mKosmos = new KosmosJavaAdapter(this);
    @Mock private NotificationGutsManager mNotificationGutsManager;
    @Mock private NotificationsController mNotificationsController;
    @Mock private NotificationVisibilityProvider mVisibilityProvider;
    @Mock private NotificationWakeUpCoordinator mNotificationWakeUpCoordinator;
    @Mock private HeadsUpManager mHeadsUpManager;
    @Mock private HeadsUpTouchHelper.Callback mHeadsUpCallback;
    @Mock private Provider<IStatusBarService> mStatusBarService;
    @Mock private NotificationRoundnessManager mNotificationRoundnessManager;
    @Mock private TunerService mTunerService;
    @Mock private DynamicPrivacyController mDynamicPrivacyController;
    @Mock private ConfigurationController mConfigurationController;
    @Mock private NotificationStackScrollLayout mNotificationStackScrollLayout;
    @Mock private KeyguardMediaController mKeyguardMediaController;
    @Mock private SysuiStatusBarStateController mSysuiStatusBarStateController;
    @Mock private KeyguardBypassController mKeyguardBypassController;
    @Mock private PowerInteractor mPowerInteractor;
    @Mock private WallpaperInteractor mWallpaperInteractor;
    @Mock private NotificationLockscreenUserManager mNotificationLockscreenUserManager;
    @Mock private MetricsLogger mMetricsLogger;
    @Mock private ColorUpdateLogger mColorUpdateLogger;
    @Mock private DumpManager mDumpManager;
    @Mock(answer = Answers.RETURNS_SELF)
    private NotificationSwipeHelper.Builder mNotificationSwipeHelperBuilder;
    @Mock private NotificationSwipeHelper mNotificationSwipeHelper;
    @Mock private GroupExpansionManager mGroupExpansionManager;
    @Mock private NotifPipeline mNotifPipeline;
    @Mock private NotifCollection mNotifCollection;
    @Mock private UiEventLogger mUiEventLogger;
    @Mock private LockscreenShadeTransitionController mLockscreenShadeTransitionController;
    @Mock private VisibilityLocationProviderDelegator mVisibilityLocationProviderDelegator;
    @Mock private ShadeController mShadeController;
    @Mock private Provider<WindowRootView> mWindowRootView;
    private final StackStateLogger mStackLogger = new StackStateLogger(logcatLogBuffer(),
            logcatLogBuffer());
    private final NotificationStackScrollLogger mLogger = new NotificationStackScrollLogger(
            logcatLogBuffer(), logcatLogBuffer(), logcatLogBuffer());
    @Mock private NotificationStackSizeCalculator mNotificationStackSizeCalculator;
    @Mock private NotificationTargetsHelper mNotificationTargetsHelper;
    @Mock private SecureSettings mSecureSettings;
    @Mock private ActivityStarter mActivityStarter;
    @Mock private KeyguardTransitionRepository mKeyguardTransitionRepo;
    @Mock private NotificationListViewBinder mViewBinder;
    @Mock
    private SensitiveNotificationProtectionController mSensitiveNotificationProtectionController;
    @Mock private ExpandHelper mExpandHelper;
    @Mock private MagneticNotificationRowManager mMagneticNotificationRowManager;
    @Mock private NotificationSectionsManager mSectionsManager;

    @Captor
    private ArgumentCaptor<Runnable> mSensitiveStateListenerArgumentCaptor;

    @Captor
    private ArgumentCaptor<StatusBarStateController.StateListener> mStateListenerArgumentCaptor;

    private NotificationStackScrollLayoutController mController;

    private NotificationTestHelper mNotificationTestHelper;

    @Before
    public void setUp() {
        allowTestableLooperAsMainThread();
        MockitoAnnotations.initMocks(this);

        when(mNotificationSwipeHelperBuilder.build()).thenReturn(mNotificationSwipeHelper);
        when(mKeyguardTransitionRepo.getTransitions()).thenReturn(emptyFlow());
        mNotificationTestHelper = new NotificationTestHelper(
                mContext,
                mDependency,
                TestableLooper.get(this));
        mNotificationTestHelper.setDefaultInflationFlags(FLAG_CONTENT_VIEW_ALL);
    }

    @Test
    public void testAttach_viewAlreadyAttached() {
        initController(/* viewIsAttached= */ true);

        verify(mConfigurationController).addCallback(
                any(ConfigurationController.ConfigurationListener.class));
    }
    @Test
    public void testAttach_viewAttachedAfterInit() {
        initController(/* viewIsAttached= */ false);
        verify(mConfigurationController, never()).addCallback(
                any(ConfigurationController.ConfigurationListener.class));

        mController.mOnAttachStateChangeListener.onViewAttachedToWindow(
                mNotificationStackScrollLayout);

        verify(mConfigurationController).addCallback(
                any(ConfigurationController.ConfigurationListener.class));
    }

    @Test
    @EnableFlags(GroupHunAnimationFix.FLAG_NAME)
    public void changeHeadsUpAnimatingAwayToTrue_onEntryAnimatingAwayEndedNotCalled()
            throws Exception {
        // Before: bind an ExpandableNotificationRow,
        initController(/* viewIsAttached= */ true);
        mController.setHeadsUpAppearanceController(mock(HeadsUpAppearanceController.class));
        NotificationListContainer listContainer = mController.getNotificationListContainer();
        ExpandableNotificationRow row = mNotificationTestHelper.createRow();
        listContainer.bindRow(row);

        // When: call setHeadsUpAnimatingAway to change set mHeadsupDisappearRunning to true
        row.setHeadsUpAnimatingAway(true);

        // Then: mHeadsUpManager.onEntryAnimatingAwayEnded is not called
        verify(mHeadsUpManager, never()).onEntryAnimatingAwayEnded(row.getEntry());
    }

    @Test
    @EnableFlags(GroupHunAnimationFix.FLAG_NAME)
    public void changeHeadsUpAnimatingAwayToFalse_onEntryAnimatingAwayEndedCalled()
            throws Exception {
        // Before: bind an ExpandableNotificationRow, set its mHeadsupDisappearRunning to true
        initController(/* viewIsAttached= */ true);
        mController.setHeadsUpAppearanceController(mock(HeadsUpAppearanceController.class));
        NotificationListContainer listContainer = mController.getNotificationListContainer();
        ExpandableNotificationRow row = mNotificationTestHelper.createRow();
        listContainer.bindRow(row);
        row.setHeadsUpAnimatingAway(true);

        // When: call setHeadsUpAnimatingAway to change set mHeadsupDisappearRunning to false
        row.setHeadsUpAnimatingAway(false);

        // Then: mHeadsUpManager.onEntryAnimatingAwayEnded is called
        verify(mHeadsUpManager).onEntryAnimatingAwayEnded(row.getEntry());
    }
    @Test
    public void testOnDensityOrFontScaleChanged_reInflatesFooterViews() {
        initController(/* viewIsAttached= */ true);

        mController.mConfigurationListener.onDensityOrFontScaleChanged();
        verify(mNotificationStackScrollLayout).reinflateViews();
    }

    @Test
    public void testOnUserChange_verifyNotSensitive() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        initController(/* viewIsAttached= */ true);

        ArgumentCaptor<UserChangedListener> userChangedCaptor = ArgumentCaptor
                .forClass(UserChangedListener.class);

        verify(mNotificationLockscreenUserManager)
                .addUserChangedListener(userChangedCaptor.capture());
        reset(mNotificationStackScrollLayout);

        UserChangedListener changedListener = userChangedCaptor.getValue();
        changedListener.onUserChanged(0);
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, false);
    }

    @Test
    public void testOnUserChange_verifySensitiveProfile() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(true);
        initController(/* viewIsAttached= */ true);

        ArgumentCaptor<UserChangedListener> userChangedCaptor = ArgumentCaptor
                .forClass(UserChangedListener.class);

        verify(mNotificationLockscreenUserManager)
                .addUserChangedListener(userChangedCaptor.capture());
        reset(mNotificationStackScrollLayout);

        UserChangedListener changedListener = userChangedCaptor.getValue();
        changedListener.onUserChanged(0);
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnUserChange_verifyNotSensitive_screenshareNotificationHidingEnabled() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(false);

        initController(/* viewIsAttached= */ true);

        ArgumentCaptor<UserChangedListener> userChangedCaptor = ArgumentCaptor
                .forClass(UserChangedListener.class);

        verify(mNotificationLockscreenUserManager)
                .addUserChangedListener(userChangedCaptor.capture());
        reset(mNotificationStackScrollLayout);

        UserChangedListener changedListener = userChangedCaptor.getValue();
        changedListener.onUserChanged(0);
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, false);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnUserChange_verifySensitiveProfile_screenshareNotificationHidingEnabled() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(true);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(false);

        initController(/* viewIsAttached= */ true);

        ArgumentCaptor<UserChangedListener> userChangedCaptor = ArgumentCaptor
                .forClass(UserChangedListener.class);

        verify(mNotificationLockscreenUserManager)
                .addUserChangedListener(userChangedCaptor.capture());
        reset(mNotificationStackScrollLayout);

        UserChangedListener changedListener = userChangedCaptor.getValue();
        changedListener.onUserChanged(0);
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnUserChange_verifySensitiveActive_screenshareNotificationHidingEnabled() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(true);
        initController(/* viewIsAttached= */ true);

        ArgumentCaptor<UserChangedListener> userChangedCaptor = ArgumentCaptor
                .forClass(UserChangedListener.class);

        verify(mNotificationLockscreenUserManager)
                .addUserChangedListener(userChangedCaptor.capture());
        reset(mNotificationStackScrollLayout);

        UserChangedListener changedListener = userChangedCaptor.getValue();
        changedListener.onUserChanged(0);
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    public void testOnStatePostChange_verifyNotSensitive() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, false);
    }

    @Test
    public void testOnStatePostChange_verifyIfProfileIsPublic() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(true);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnStatePostChange_verifyNotSensitive_screenshareNotificationHidingEnabled() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(false);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, false);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnStatePostChange_verifyIfProfileIsPublic_screenshareNotificationHidingEnabled(
    ) {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(true);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(false);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnStatePostChange_verifyIfSensitiveActive_screenshareNotificationHidingEnabled(
    ) {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(true);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    public void testOnStatePostChange_goingFullShade_verifyNotSensitive() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSysuiStatusBarStateController.goingToFullShade()).thenReturn(true);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(true, false);
    }

    @Test
    public void testOnStatePostChange_goingFullShade_verifyIfProfileIsPublic() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(true);
        when(mSysuiStatusBarStateController.goingToFullShade()).thenReturn(true);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(true, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnStatePostChange_goingFullShade_verifyNotSensitive_screenshareHideEnabled(
    ) {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSysuiStatusBarStateController.goingToFullShade()).thenReturn(true);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(false);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(true, false);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnStatePostChange_goingFullShade_verifyProfileIsPublic_screenshareHideEnabled(
    ) {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(true);
        when(mSysuiStatusBarStateController.goingToFullShade()).thenReturn(true);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(false);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(true, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnStatePostChange_goingFullShade_verifySensitiveActive_screenshareHideEnabled(
    ) {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSysuiStatusBarStateController.goingToFullShade()).thenReturn(true);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(true);

        initController(/* viewIsAttached= */ true);
        verify(mSysuiStatusBarStateController).addCallback(
                mStateListenerArgumentCaptor.capture(), anyInt());

        StatusBarStateController.StateListener stateListener =
                mStateListenerArgumentCaptor.getValue();

        stateListener.onStatePostChange();
        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnProjectionStateChanged_verifyNotSensitive() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive())
                .thenReturn(false);

        initController(/* viewIsAttached= */ true);
        verify(mSensitiveNotificationProtectionController)
                .registerSensitiveStateListener(mSensitiveStateListenerArgumentCaptor.capture());

        mSensitiveStateListenerArgumentCaptor.getValue().run();

        verify(mNotificationStackScrollLayout).updateSensitiveness(false, false);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnProjectionStateChanged_verifyIfProfileIsPublic() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(true);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(false);

        initController(/* viewIsAttached= */ true);
        verify(mSensitiveNotificationProtectionController)
                .registerSensitiveStateListener(mSensitiveStateListenerArgumentCaptor.capture());

        mSensitiveStateListenerArgumentCaptor.getValue().run();

        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void testOnProjectionStateChanged_verifyIfSensitiveActive() {
        when(mNotificationLockscreenUserManager.isAnyProfilePublicMode()).thenReturn(false);
        when(mSensitiveNotificationProtectionController.isSensitiveStateActive()).thenReturn(true);

        initController(/* viewIsAttached= */ true);
        verify(mSensitiveNotificationProtectionController)
                .registerSensitiveStateListener(mSensitiveStateListenerArgumentCaptor.capture());

        mSensitiveStateListenerArgumentCaptor.getValue().run();

        verify(mNotificationStackScrollLayout).updateSensitiveness(false, true);
    }

    @Test
    public void testOnMenuShownLogging() {
        ExpandableNotificationRow row = mock(ExpandableNotificationRow.class, RETURNS_DEEP_STUBS);
        when(row.getEntry().getSbn().getLogMaker()).thenReturn(new LogMaker(
                MetricsProto.MetricsEvent.VIEW_UNKNOWN));

        ArgumentCaptor<OnMenuEventListener> onMenuEventListenerArgumentCaptor =
                ArgumentCaptor.forClass(OnMenuEventListener.class);

        initController(/* viewIsAttached= */ true);
        verify(mNotificationSwipeHelperBuilder).setOnMenuEventListener(
                onMenuEventListenerArgumentCaptor.capture());

        OnMenuEventListener onMenuEventListener = onMenuEventListenerArgumentCaptor.getValue();

        onMenuEventListener.onMenuShown(row);
        verify(row.getEntry().getSbn()).getLogMaker();  // This writes most of the log data
        verify(mMetricsLogger).write(logMatcher(MetricsProto.MetricsEvent.ACTION_REVEAL_GEAR,
                MetricsProto.MetricsEvent.TYPE_ACTION));
    }

    @Test
    public void callSwipeCallbacksDuringClearAll() {
        initController(/* viewIsAttached= */ true);
        ExpandableNotificationRow row = mock(ExpandableNotificationRow.class);
        NotificationCallback notificationCallback = mController.mNotificationCallback;

        when(mNotificationStackScrollLayout.getClearAllInProgress()).thenReturn(true);

        notificationCallback.onBeginDrag(row);
        verify(mNotificationStackScrollLayout).onSwipeBegin(row);

        notificationCallback.handleChildViewDismissed(row);
        verify(mNotificationStackScrollLayout).onSwipeEnd();
    }

    @Test
    public void callSwipeCallbacksDuringClearNotification() {
        initController(/* viewIsAttached= */ true);
        ExpandableNotificationRow row = mock(ExpandableNotificationRow.class);
        NotificationCallback notificationCallback = mController.mNotificationCallback;

        when(mNotificationStackScrollLayout.getClearAllInProgress()).thenReturn(false);

        notificationCallback.onBeginDrag(row);
        verify(mNotificationStackScrollLayout).onSwipeBegin(row);

        notificationCallback.handleChildViewDismissed(row);
        verify(mNotificationStackScrollLayout).onSwipeEnd();
    }

    @Test
    public void testOnMenuClickedLogging() {
        ExpandableNotificationRow row = mock(ExpandableNotificationRow.class, RETURNS_DEEP_STUBS);
        when(row.getEntry().getSbn().getLogMaker()).thenReturn(new LogMaker(
                MetricsProto.MetricsEvent.VIEW_UNKNOWN));

        ArgumentCaptor<OnMenuEventListener> onMenuEventListenerArgumentCaptor =
                ArgumentCaptor.forClass(OnMenuEventListener.class);

        initController(/* viewIsAttached= */ true);
        verify(mNotificationSwipeHelperBuilder).setOnMenuEventListener(
                onMenuEventListenerArgumentCaptor.capture());

        OnMenuEventListener onMenuEventListener = onMenuEventListenerArgumentCaptor.getValue();

        onMenuEventListener.onMenuClicked(row, 0, 0, mock(
                NotificationMenuRowPlugin.MenuItem.class));
        verify(row.getEntry().getSbn()).getLogMaker();  // This writes most of the log data
        verify(mMetricsLogger).write(logMatcher(MetricsProto.MetricsEvent.ACTION_TOUCH_GEAR,
                MetricsProto.MetricsEvent.TYPE_ACTION));
    }

    @Test
    public void testDismissListener() {
        ArgumentCaptor<NotificationStackScrollLayout.ClearAllListener>
                dismissListenerArgumentCaptor = ArgumentCaptor.forClass(
                NotificationStackScrollLayout.ClearAllListener.class);

        initController(/* viewIsAttached= */ true);

        verify(mNotificationStackScrollLayout).setClearAllListener(
                dismissListenerArgumentCaptor.capture());
        NotificationStackScrollLayout.ClearAllListener dismissListener =
                dismissListenerArgumentCaptor.getValue();

        dismissListener.onClearAll(ROWS_ALL);
        verify(mUiEventLogger).log(NotificationPanelEvent.fromSelection(ROWS_ALL));
    }

    @Test
    public void testAttach_updatesViewStatusBarState() {
        // GIVEN: Controller is attached
        initController(/* viewIsAttached= */ true);
        ArgumentCaptor<StatusBarStateController.StateListener> captor =
                ArgumentCaptor.forClass(StatusBarStateController.StateListener.class);
        verify(mSysuiStatusBarStateController).addCallback(captor.capture(), anyInt());
        StatusBarStateController.StateListener stateListener = captor.getValue();

        // WHEN: StatusBarState changes to SHADE
        when(mSysuiStatusBarStateController.getState()).thenReturn(SHADE);
        stateListener.onStateChanged(SHADE);

        // THEN: NSSL is updated with the current state
        verify(mNotificationStackScrollLayout).setStatusBarState(SHADE);

        // WHEN: Controller is detached
        mController.mOnAttachStateChangeListener
                .onViewDetachedFromWindow(mNotificationStackScrollLayout);

        // WHEN: StatusBarState changes to KEYGUARD
        when(mSysuiStatusBarStateController.getState()).thenReturn(KEYGUARD);

        // WHEN: Controller is re-attached
        mController.mOnAttachStateChangeListener
                .onViewAttachedToWindow(mNotificationStackScrollLayout);

        // THEN: NSSL is updated with the current state
        verify(mNotificationStackScrollLayout).setStatusBarState(KEYGUARD);
    }

    @Test
    @DisableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void sensitiveNotificationProtectionControllerListenerNotRegistered() {
        initController(/* viewIsAttached= */ true);
        verifyNoMoreInteractions(mSensitiveNotificationProtectionController);
    }

    @Test
    @EnableFlags(FLAG_SCREENSHARE_NOTIFICATION_HIDING)
    public void sensitiveNotificationProtectionControllerListenerRegistered() {
        initController(/* viewIsAttached= */ true);
        verify(mSensitiveNotificationProtectionController).registerSensitiveStateListener(any());
    }

    @Test
    @EnableSceneContainer
    public void onTouchEvent_stopExpandingNotification_sceneContainerEnabled() {
        stopExpandingNotification();

        verify(mExpandHelper).finishExpanding();
        verify(mNotificationStackScrollLayout, never()).dispatchDownEventToScroller(any());
    }

    @Test
    @DisableSceneContainer
    public void onTouchEvent_stopExpandingNotification_sceneContainerDisabled() {
        stopExpandingNotification();

        verify(mExpandHelper, never()).finishExpanding();
        verify(mNotificationStackScrollLayout).dispatchDownEventToScroller(any());
    }

    private void stopExpandingNotification() {
        when(mNotificationStackScrollLayout.getExpandHelper()).thenReturn(mExpandHelper);
        when(mNotificationStackScrollLayout.getIsExpanded()).thenReturn(true);
        when(mNotificationStackScrollLayout.getExpandedInThisMotion()).thenReturn(true);
        when(mNotificationStackScrollLayout.isExpandingNotification()).thenReturn(true);

        when(mExpandHelper.onTouchEvent(any())).thenAnswer(i -> {
            when(mNotificationStackScrollLayout.isExpandingNotification()).thenReturn(false);
            return false;
        });

        initController(/* viewIsAttached= */ true);
        NotificationStackScrollLayoutController.TouchHandler touchHandler =
                mController.getTouchHandler();

        touchHandler.onTouchEvent(MotionEvent.obtain(
            /* downTime= */ 0,
            /* eventTime= */ 0,
            MotionEvent.ACTION_DOWN,
            0,
            0,
            /* metaState= */ 0
        ));
    }

    private LogMaker logMatcher(int category, int type) {
        return argThat(new LogMatcher(category, type));
    }

    private void initController(boolean viewIsAttached) {
        when(mNotificationStackScrollLayout.isAttachedToWindow()).thenReturn(viewIsAttached);
        ViewTreeObserver viewTreeObserver = mock(ViewTreeObserver.class);
        when(mNotificationStackScrollLayout.getViewTreeObserver())
                .thenReturn(viewTreeObserver);
        when(mNotificationStackScrollLayout.getContext()).thenReturn(getContext());
        when(mNotificationStackScrollLayout.getHeadsUpCallback()).thenReturn(mHeadsUpCallback);
        when(mHeadsUpCallback.getContext()).thenReturn(getContext());
        mController = new NotificationStackScrollLayoutController(
                mNotificationStackScrollLayout,
                true,
                mNotificationGutsManager,
                mNotificationsController,
                mVisibilityProvider,
                mNotificationWakeUpCoordinator,
                mHeadsUpManager,
                mStatusBarService,
                mNotificationRoundnessManager,
                mTunerService,
                mDynamicPrivacyController,
                mConfigurationController,
                mSysuiStatusBarStateController,
                mKeyguardMediaController,
                mKeyguardBypassController,
                mPowerInteractor,
                mNotificationLockscreenUserManager,
                mMetricsLogger,
                mColorUpdateLogger,
                mDumpManager,
                new FalsingCollectorFake(),
                new FalsingManagerFake(),
                mNotificationSwipeHelperBuilder,
                mGroupExpansionManager,
                mNotifPipeline,
                mNotifCollection,
                mLockscreenShadeTransitionController,
                mUiEventLogger,
                mVisibilityLocationProviderDelegator,
                mViewBinder,
                mShadeController,
                mWindowRootView,
                mKosmos.getInteractionJankMonitor(),
                mStackLogger,
                mLogger,
                mNotificationStackSizeCalculator,
                mNotificationTargetsHelper,
                mSecureSettings,
                mock(NotificationDismissibilityProvider.class),
                mActivityStarter,
                new ResourcesSplitShadeStateController(),
                mSensitiveNotificationProtectionController,
                mWallpaperInteractor,
                mMagneticNotificationRowManager,
                mSectionsManager);
    }

    static class LogMatcher implements ArgumentMatcher<LogMaker> {
        private final int mCategory, mType;

        LogMatcher(int category, int type) {
            mCategory = category;
            mType = type;
        }
        public boolean matches(LogMaker l) {
            return (l.getCategory() == mCategory)
                    && (l.getType() == mType);
        }

        public String toString() {
            return String.format("LogMaker(%d, %d)", mCategory, mType);
        }
    }
}
