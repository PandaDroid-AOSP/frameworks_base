/*
 * Copyright (C) 2024 The Android Open Source Project
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

import android.content.Context
import android.platform.test.annotations.EnableFlags
import android.platform.test.annotations.RequiresFlagsDisabled
import android.platform.test.flag.junit.FlagsParameterization
import android.testing.TestableLooper
import android.testing.TestableLooper.RunWithLooper
import android.view.Choreographer
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import androidx.test.filters.SmallTest
import com.android.keyguard.KeyguardSecurityContainerController
import com.android.keyguard.dagger.KeyguardBouncerComponent
import com.android.systemui.Flags
import com.android.systemui.SysuiTestCase
import com.android.systemui.bouncer.domain.interactor.AlternateBouncerInteractor
import com.android.systemui.bouncer.domain.interactor.PrimaryBouncerInteractor
import com.android.systemui.bouncer.ui.binder.BouncerViewBinder
import com.android.systemui.classifier.FalsingCollectorFake
import com.android.systemui.dock.DockManager
import com.android.systemui.dump.DumpManager
import com.android.systemui.flags.DisableSceneContainer
import com.android.systemui.flags.FakeFeatureFlagsClassic
import com.android.systemui.flags.Flags.SPLIT_SHADE_SUBPIXEL_OPTIMIZATION
import com.android.systemui.flags.andSceneContainer
import com.android.systemui.keyevent.domain.interactor.SysUIKeyEventHandler
import com.android.systemui.keyguard.KeyguardUnlockAnimationController
import com.android.systemui.keyguard.domain.interactor.KeyguardTransitionInteractor
import com.android.systemui.keyguard.shared.model.Edge
import com.android.systemui.keyguard.shared.model.KeyguardState.DREAMING
import com.android.systemui.keyguard.shared.model.KeyguardState.LOCKSCREEN
import com.android.systemui.keyguard.shared.model.TransitionStep
import com.android.systemui.kosmos.testDispatcher
import com.android.systemui.kosmos.testScope
import com.android.systemui.log.assertLogsWtf
import com.android.systemui.qs.flags.QSComposeFragment
import com.android.systemui.res.R
import com.android.systemui.scene.ui.view.WindowRootViewKeyEventHandler
import com.android.systemui.settings.brightness.data.repository.BrightnessMirrorShowingRepository
import com.android.systemui.settings.brightness.domain.interactor.BrightnessMirrorShowingInteractorPassThrough
import com.android.systemui.shade.NotificationShadeWindowView.InteractionEventHandler
import com.android.systemui.shade.data.repository.ShadeAnimationRepository
import com.android.systemui.shade.data.repository.ShadeRepositoryImpl
import com.android.systemui.shade.domain.interactor.PanelExpansionInteractor
import com.android.systemui.shade.domain.interactor.ShadeAnimationInteractorLegacyImpl
import com.android.systemui.statusbar.BlurUtils
import com.android.systemui.statusbar.DragDownHelper
import com.android.systemui.statusbar.LockscreenShadeTransitionController
import com.android.systemui.statusbar.NotificationInsetsController
import com.android.systemui.statusbar.NotificationShadeDepthController
import com.android.systemui.statusbar.NotificationShadeWindowController
import com.android.systemui.statusbar.SysuiStatusBarStateController
import com.android.systemui.statusbar.notification.data.repository.NotificationLaunchAnimationRepository
import com.android.systemui.statusbar.notification.domain.interactor.NotificationLaunchAnimationInteractor
import com.android.systemui.statusbar.notification.stack.AmbientState
import com.android.systemui.statusbar.notification.stack.NotificationStackScrollLayoutController
import com.android.systemui.statusbar.phone.CentralSurfaces
import com.android.systemui.statusbar.phone.ConfigurationForwarder
import com.android.systemui.statusbar.phone.DozeScrimController
import com.android.systemui.statusbar.phone.DozeServiceHost
import com.android.systemui.statusbar.phone.PhoneStatusBarViewController
import com.android.systemui.statusbar.window.StatusBarWindowStateController
import com.android.systemui.testKosmos
import com.android.systemui.unfold.SysUIUnfoldComponent
import com.android.systemui.unfold.UnfoldTransitionProgressProvider
import com.android.systemui.user.domain.interactor.SelectedUserInteractor
import com.android.systemui.util.mockito.any
import com.android.systemui.util.mockito.eq
import com.android.systemui.util.time.FakeSystemClock
import com.android.systemui.window.ui.viewmodel.WindowRootViewModel
import com.google.common.truth.Truth.assertThat
import java.util.Optional
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Answers
import org.mockito.ArgumentCaptor
import org.mockito.Mock
import org.mockito.Mockito.anyFloat
import org.mockito.Mockito.atLeast
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when` as whenever
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.clearInvocations
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

@SmallTest
@RunWith(ParameterizedAndroidJunit4::class)
@RunWithLooper(setAsMainLooper = true)
class NotificationShadeWindowViewControllerTest(flags: FlagsParameterization) : SysuiTestCase() {

    val kosmos = testKosmos()

    @Mock private lateinit var view: NotificationShadeWindowView
    @Mock private lateinit var sysuiStatusBarStateController: SysuiStatusBarStateController
    @Mock private lateinit var centralSurfaces: CentralSurfaces
    @Mock private lateinit var dozeServiceHost: DozeServiceHost
    @Mock private lateinit var dozeScrimController: DozeScrimController
    @Mock private lateinit var dockManager: DockManager
    @Mock private lateinit var shadeViewController: ShadeViewController
    @Mock private lateinit var panelExpansionInteractor: PanelExpansionInteractor
    @Mock private lateinit var notificationShadeDepthController: NotificationShadeDepthController
    @Mock private lateinit var notificationShadeWindowController: NotificationShadeWindowController
    @Mock private lateinit var keyguardUnlockAnimationController: KeyguardUnlockAnimationController
    @Mock private lateinit var shadeLogger: ShadeLogger
    @Mock private lateinit var dumpManager: DumpManager
    @Mock private lateinit var ambientState: AmbientState
    @Mock private lateinit var stackScrollLayoutController: NotificationStackScrollLayoutController
    @Mock private lateinit var statusBarWindowStateController: StatusBarWindowStateController
    @Mock private lateinit var quickSettingsController: QuickSettingsControllerImpl
    @Mock
    private lateinit var lockscreenShadeTransitionController: LockscreenShadeTransitionController
    @Mock private lateinit var phoneStatusBarViewController: PhoneStatusBarViewController
    @Mock private lateinit var pulsingGestureListener: PulsingGestureListener
    @Mock private lateinit var notificationInsetsController: NotificationInsetsController
    @Mock private lateinit var mGlanceableHubContainerController: GlanceableHubContainerController
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private lateinit var sysUiUnfoldComponent: SysUIUnfoldComponent
    @Mock lateinit var keyguardBouncerComponentFactory: KeyguardBouncerComponent.Factory
    @Mock lateinit var keyguardBouncerComponent: KeyguardBouncerComponent
    @Mock lateinit var keyguardSecurityContainerController: KeyguardSecurityContainerController
    @Mock
    private lateinit var unfoldTransitionProgressProvider:
        Optional<UnfoldTransitionProgressProvider>
    @Mock lateinit var keyguardTransitionInteractor: KeyguardTransitionInteractor
    @Mock lateinit var dragDownHelper: DragDownHelper
    @Mock lateinit var mSelectedUserInteractor: SelectedUserInteractor
    @Mock lateinit var sysUIKeyEventHandler: SysUIKeyEventHandler
    @Mock lateinit var primaryBouncerInteractor: PrimaryBouncerInteractor
    @Mock lateinit var alternateBouncerInteractor: AlternateBouncerInteractor
    @Mock private lateinit var blurUtils: BlurUtils
    @Mock private lateinit var choreographer: Choreographer
    @Mock private lateinit var windowViewModelFactory: WindowRootViewModel.Factory
    private val notificationLaunchAnimationRepository = NotificationLaunchAnimationRepository()
    private val notificationLaunchAnimationInteractor =
        NotificationLaunchAnimationInteractor(notificationLaunchAnimationRepository)

    private val brightnessMirrorShowingRepository = BrightnessMirrorShowingRepository()
    private val brightnessMirrorShowingInteractor =
        BrightnessMirrorShowingInteractorPassThrough(brightnessMirrorShowingRepository)

    private lateinit var falsingCollector: FalsingCollectorFake
    private lateinit var fakeClock: FakeSystemClock
    private lateinit var interactionEventHandlerCaptor: ArgumentCaptor<InteractionEventHandler>
    private lateinit var interactionEventHandler: InteractionEventHandler

    private lateinit var underTest: NotificationShadeWindowViewController

    private lateinit var testScope: TestScope
    private lateinit var testableLooper: TestableLooper

    private lateinit var featureFlagsClassic: FakeFeatureFlagsClassic

    init {
        mSetFlagsRule.setFlagsParameterization(flags)
    }

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        whenever(view.bottom).thenReturn(VIEW_BOTTOM)
        whenever(view.findViewById<ViewGroup>(R.id.keyguard_bouncer_container))
            .thenReturn(mock(ViewGroup::class.java))
        whenever(keyguardBouncerComponentFactory.create(any(ViewGroup::class.java)))
            .thenReturn(keyguardBouncerComponent)
        whenever(keyguardBouncerComponent.securityContainerController)
            .thenReturn(keyguardSecurityContainerController)
        whenever(keyguardTransitionInteractor.transition(Edge.create(LOCKSCREEN, DREAMING)))
            .thenReturn(emptyFlow<TransitionStep>())

        featureFlagsClassic = FakeFeatureFlagsClassic()
        featureFlagsClassic.set(SPLIT_SHADE_SUBPIXEL_OPTIMIZATION, true)
        mSetFlagsRule.enableFlags(Flags.FLAG_REVAMPED_BOUNCER_MESSAGES)

        testScope = kosmos.testScope
        testableLooper = TestableLooper.get(this)

        falsingCollector = FalsingCollectorFake()
        fakeClock = FakeSystemClock()
        underTest =
            NotificationShadeWindowViewController(
                blurUtils,
                windowViewModelFactory,
                choreographer,
                lockscreenShadeTransitionController,
                falsingCollector,
                sysuiStatusBarStateController,
                dockManager,
                notificationShadeDepthController,
                view,
                shadeViewController,
                ShadeAnimationInteractorLegacyImpl(
                    ShadeAnimationRepository(),
                    ShadeRepositoryImpl(testScope),
                ),
                panelExpansionInteractor,
                ShadeExpansionStateManager(),
                stackScrollLayoutController,
                statusBarWindowStateController,
                centralSurfaces,
                dozeServiceHost,
                dozeScrimController,
                notificationShadeWindowController,
                unfoldTransitionProgressProvider,
                Optional.of(sysUiUnfoldComponent),
                keyguardUnlockAnimationController,
                notificationInsetsController,
                ambientState,
                shadeLogger,
                dumpManager,
                pulsingGestureListener,
                keyguardTransitionInteractor,
                mGlanceableHubContainerController,
                notificationLaunchAnimationInteractor,
                featureFlagsClassic,
                fakeClock,
                WindowRootViewKeyEventHandler({ sysUIKeyEventHandler }, falsingCollector),
                quickSettingsController,
                primaryBouncerInteractor,
                alternateBouncerInteractor,
                mock(BouncerViewBinder::class.java),
                { mock(ConfigurationForwarder::class.java) },
                brightnessMirrorShowingInteractor,
                kosmos.testDispatcher,
            )
        underTest.setupExpandedStatusBar()
        underTest.setDragDownHelper(dragDownHelper)

        interactionEventHandlerCaptor = ArgumentCaptor.forClass(InteractionEventHandler::class.java)
        verify(view).setInteractionEventHandler(interactionEventHandlerCaptor.capture())
        interactionEventHandler = interactionEventHandlerCaptor.value
    }

    // Note: So far, these tests only cover interactions with the status bar view controller. More
    // tests need to be added to test the rest of handleDispatchTouchEvent.

    @Test
    fun handleDispatchTouchEvent_nullStatusBarViewController_returnsFalse() =
        testScope.runTest {
            underTest.setStatusBarViewController(null)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

            assertThat(returnVal).isFalse()
        }

    @Test
    fun handleDispatchTouchEvent_downTouchBelowView_sendsTouchToSb() =
        testScope.runTest {
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            val ev = MotionEvent.obtain(0L, 0L, MotionEvent.ACTION_DOWN, 0f, VIEW_BOTTOM + 4f, 0)
            whenever(phoneStatusBarViewController.sendTouchToView(ev)).thenReturn(true)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(ev)

            verify(phoneStatusBarViewController).sendTouchToView(ev)
            assertThat(returnVal).isTrue()
        }

    @Test
    fun handleDispatchTouchEvent_downTouchBelowViewThenAnotherTouch_sendsTouchToSb() =
        testScope.runTest {
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            val downEvBelow =
                MotionEvent.obtain(0L, 0L, MotionEvent.ACTION_DOWN, 0f, VIEW_BOTTOM + 4f, 0)
            interactionEventHandler.handleDispatchTouchEvent(downEvBelow)

            val nextEvent =
                MotionEvent.obtain(0L, 0L, MotionEvent.ACTION_MOVE, 0f, VIEW_BOTTOM + 5f, 0)
            whenever(phoneStatusBarViewController.sendTouchToView(nextEvent)).thenReturn(true)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(nextEvent)

            verify(phoneStatusBarViewController).sendTouchToView(nextEvent)
            assertThat(returnVal).isTrue()
        }

    @Test
    fun handleDispatchTouchEvent_downAndPanelCollapsedAndInSbBoundAndSbWindowShow_sendsTouchToSb() =
        testScope.runTest {
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            whenever(statusBarWindowStateController.windowIsShowing()).thenReturn(true)
            whenever(panelExpansionInteractor.isFullyCollapsed).thenReturn(true)
            whenever(phoneStatusBarViewController.touchIsWithinView(anyFloat(), anyFloat()))
                .thenReturn(true)
            whenever(phoneStatusBarViewController.sendTouchToView(DOWN_EVENT)).thenReturn(true)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

            verify(phoneStatusBarViewController).sendTouchToView(DOWN_EVENT)
            assertThat(returnVal).isTrue()
        }

    @Test
    fun handleDispatchTouchEvent_panelNotCollapsed_returnsNull() =
        testScope.runTest {
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            whenever(statusBarWindowStateController.windowIsShowing()).thenReturn(true)
            whenever(phoneStatusBarViewController.touchIsWithinView(anyFloat(), anyFloat()))
                .thenReturn(true)
            // Item we're testing
            whenever(panelExpansionInteractor.isFullyCollapsed).thenReturn(false)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

            verify(phoneStatusBarViewController, never()).sendTouchToView(DOWN_EVENT)
            assertThat(returnVal).isNull()
        }

    @Test
    fun handleDispatchTouchEvent_touchNotInSbBounds_returnsNull() =
        testScope.runTest {
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            whenever(statusBarWindowStateController.windowIsShowing()).thenReturn(true)
            whenever(panelExpansionInteractor.isFullyCollapsed).thenReturn(true)
            // Item we're testing
            whenever(phoneStatusBarViewController.touchIsWithinView(anyFloat(), anyFloat()))
                .thenReturn(false)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

            verify(phoneStatusBarViewController, never()).sendTouchToView(DOWN_EVENT)
            assertThat(returnVal).isNull()
        }

    @Test
    fun handleDispatchTouchEvent_sbWindowNotShowing_noSendTouchToSbAndReturnsTrue() =
        testScope.runTest {
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            whenever(panelExpansionInteractor.isFullyCollapsed).thenReturn(true)
            whenever(phoneStatusBarViewController.touchIsWithinView(anyFloat(), anyFloat()))
                .thenReturn(true)
            // Item we're testing
            whenever(statusBarWindowStateController.windowIsShowing()).thenReturn(false)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

            verify(phoneStatusBarViewController, never()).sendTouchToView(DOWN_EVENT)
            assertThat(returnVal).isTrue()
        }

    @Test
    fun handleDispatchTouchEvent_downEventSentToSbThenAnotherEvent_sendsTouchToSb() =
        testScope.runTest {
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            whenever(statusBarWindowStateController.windowIsShowing()).thenReturn(true)
            whenever(panelExpansionInteractor.isFullyCollapsed).thenReturn(true)
            whenever(phoneStatusBarViewController.touchIsWithinView(anyFloat(), anyFloat()))
                .thenReturn(true)

            // Down event first
            interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

            // Then another event
            val nextEvent = MotionEvent.obtain(0L, 0L, MotionEvent.ACTION_MOVE, 0f, 0f, 0)
            whenever(phoneStatusBarViewController.sendTouchToView(nextEvent)).thenReturn(true)

            val returnVal = interactionEventHandler.handleDispatchTouchEvent(nextEvent)

            verify(phoneStatusBarViewController).sendTouchToView(nextEvent)
            assertThat(returnVal).isTrue()
        }

    @Test
    fun handleDispatchTouchEvent_launchAnimationRunningTimesOut() =
        testScope.runTest {
            // GIVEN touch dispatcher in a state that returns true
            underTest.setStatusBarViewController(phoneStatusBarViewController)
            whenever(keyguardUnlockAnimationController.isPlayingCannedUnlockAnimation())
                .thenReturn(true)
            assertThat(interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)).isTrue()

            // WHEN launch animation is running for 2 seconds
            fakeClock.setUptimeMillis(10000)
            underTest.setExpandAnimationRunning(true)
            fakeClock.advanceTime(2000)

            // THEN touch is ignored
            assertThat(interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)).isFalse()

            // WHEN Launch animation is running for 6 seconds
            fakeClock.advanceTime(4000)

            // THEN move is ignored, down is handled, and window is notified
            assertThat(interactionEventHandler.handleDispatchTouchEvent(MOVE_EVENT)).isFalse()
            assertLogsWtf {
                assertThat(interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)).isTrue()
            }
            verify(notificationShadeWindowController).setLaunchingActivity(false)
        }

    @Test
    fun handleDispatchTouchEvent_nsslMigrationOn_userActivity() {
        underTest.setStatusBarViewController(phoneStatusBarViewController)

        interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

        verify(centralSurfaces).userActivity()
    }

    @Test
    @DisableSceneContainer
    fun handleDispatchTouchEvent_glanceableHubIntercepts_returnsTrue() {
        whenever(mGlanceableHubContainerController.onTouchEvent(DOWN_EVENT)).thenReturn(true)
        underTest.setStatusBarViewController(phoneStatusBarViewController)

        val returnVal = interactionEventHandler.handleDispatchTouchEvent(DOWN_EVENT)

        assertThat(returnVal).isTrue()
    }

    @Test
    fun shouldInterceptTouchEvent_dozing_touchNotInLockIconArea_touchIntercepted() {
        // GIVEN dozing
        whenever(sysuiStatusBarStateController.isDozing).thenReturn(true)
        // AND quick settings controller doesn't want it
        whenever(quickSettingsController.shouldQuickSettingsIntercept(any(), any(), any()))
            .thenReturn(false)

        // THEN touch should be intercepted by NotificationShade
        assertThat(interactionEventHandler.shouldInterceptTouchEvent(DOWN_EVENT)).isTrue()
    }

    @Test
    fun shouldInterceptTouchEvent_dozing_touchInStatusBar_touchIntercepted() {
        // GIVEN dozing
        whenever(sysuiStatusBarStateController.isDozing).thenReturn(true)
        // AND quick settings controller DOES want it
        whenever(quickSettingsController.shouldQuickSettingsIntercept(any(), any(), any()))
            .thenReturn(true)

        // THEN touch should be intercepted by NotificationShade
        assertThat(interactionEventHandler.shouldInterceptTouchEvent(DOWN_EVENT)).isTrue()
    }

    @Test
    fun shouldInterceptTouchEvent_dozingAndPulsing_touchIntercepted() {
        // GIVEN dozing
        whenever(sysuiStatusBarStateController.isDozing).thenReturn(true)
        // AND pulsing
        whenever(dozeServiceHost.isPulsing()).thenReturn(true)
        // AND quick settings controller DOES want it
        whenever(quickSettingsController.shouldQuickSettingsIntercept(any(), any(), any()))
            .thenReturn(true)
        // AND bouncer is not showing
        whenever(centralSurfaces.isBouncerShowing()).thenReturn(false)
        // AND panel view controller wants it
        whenever(shadeViewController.handleExternalInterceptTouch(DOWN_EVENT)).thenReturn(true)

        // THEN touch should be intercepted by NotificationShade
        assertThat(interactionEventHandler.shouldInterceptTouchEvent(DOWN_EVENT)).isTrue()
    }

    @Test
    fun handleExternalTouch_intercepted_sendsOnTouch() {
        // Accept dispatch and also intercept.
        whenever(view.dispatchTouchEvent(any())).thenReturn(true)
        whenever(view.onInterceptTouchEvent(any())).thenReturn(true)

        underTest.handleExternalTouch(DOWN_EVENT)
        underTest.handleExternalTouch(MOVE_EVENT)

        // Once intercepted, both events are sent to the view.
        verify(view).onTouchEvent(DOWN_EVENT)
        verify(view).onTouchEvent(MOVE_EVENT)
    }

    @Test
    fun handleExternalTouch_notDispatched_interceptNotCalled() {
        // Don't accept dispatch
        whenever(view.dispatchTouchEvent(any())).thenReturn(false)

        underTest.handleExternalTouch(DOWN_EVENT)

        // Interception is not offered.
        verify(view, never()).onInterceptTouchEvent(any())
    }

    @Test
    fun handleExternalTouch_notIntercepted_onTouchNotSent() {
        // Accept dispatch, but don't dispatch
        whenever(view.dispatchTouchEvent(any())).thenReturn(true)
        whenever(view.onInterceptTouchEvent(any())).thenReturn(false)

        underTest.handleExternalTouch(DOWN_EVENT)
        underTest.handleExternalTouch(MOVE_EVENT)

        // Interception offered for both events, but onTouchEvent is never called.
        verify(view).onInterceptTouchEvent(DOWN_EVENT)
        verify(view).onInterceptTouchEvent(MOVE_EVENT)
        verify(view, never()).onTouchEvent(any())
    }

    @Test
    fun testGetKeyguardMessageArea() =
        testScope.runTest {
            underTest.keyguardMessageArea
            verify(view).findViewById<ViewGroup>(R.id.keyguard_message_area)
        }

    @EnableFlags(Flags.FLAG_SHADE_LAUNCH_ACCESSIBILITY)
    @Test
    fun notifiesTheViewWhenLaunchAnimationIsRunning() {
        testScope.runTest {
            underTest.setExpandAnimationRunning(true)
            verify(view).setAnimatingContentLaunch(true)

            underTest.setExpandAnimationRunning(false)
            verify(view).setAnimatingContentLaunch(false)
        }
    }

    @Test
    @DisableSceneContainer
    fun setsUpCommunalHubLayout_whenFlagEnabled() {
        whenever(mGlanceableHubContainerController.communalAvailable())
            .thenReturn(MutableStateFlow(true))

        val communalView = View(context)
        whenever(mGlanceableHubContainerController.initView(any<Context>()))
            .thenReturn(communalView)

        val mockCommunalPlaceholder = mock(View::class.java)
        val fakeViewIndex = 20
        whenever(view.findViewById<View>(R.id.communal_ui_stub)).thenReturn(mockCommunalPlaceholder)
        whenever(view.indexOfChild(mockCommunalPlaceholder)).thenReturn(fakeViewIndex)
        whenever(view.context).thenReturn(context)
        whenever(view.viewTreeObserver).thenReturn(mock(ViewTreeObserver::class.java))

        underTest.setupCommunalHubLayout()

        // Simluate attaching the view so flow collection starts.
        val onAttachStateChangeListenerArgumentCaptor =
            ArgumentCaptor.forClass(View.OnAttachStateChangeListener::class.java)
        verify(view, atLeast(1))
            .addOnAttachStateChangeListener(onAttachStateChangeListenerArgumentCaptor.capture())
        for (listener in onAttachStateChangeListenerArgumentCaptor.allValues) {
            listener.onViewAttachedToWindow(view)
        }
        testableLooper.processAllMessages()

        // Communal view added as a child of the container at the proper index.
        verify(view).addView(eq(communalView), eq(fakeViewIndex))
    }

    @Test
    @RequiresFlagsDisabled(Flags.FLAG_COMMUNAL_HUB)
    fun doesNotSetupCommunalHubLayout_whenFlagDisabled() {
        whenever(mGlanceableHubContainerController.communalAvailable())
            .thenReturn(MutableStateFlow(false))

        val mockCommunalPlaceholder = mock(View::class.java)
        val fakeViewIndex = 20
        whenever(view.findViewById<View>(R.id.communal_ui_stub)).thenReturn(mockCommunalPlaceholder)
        whenever(view.indexOfChild(mockCommunalPlaceholder)).thenReturn(fakeViewIndex)
        whenever(view.context).thenReturn(context)

        underTest.setupCommunalHubLayout()

        // No adding of views occurs.
        verify(view, times(0)).addView(any(), eq(fakeViewIndex))
    }

    @Test
    fun cancelCurrentTouch_callsDragDownHelper() {
        underTest.cancelCurrentTouch()

        verify(dragDownHelper).stopDragging()
    }

    @Test
    @EnableFlags(QSComposeFragment.FLAG_NAME)
    fun mirrorShowing_depthControllerSet() =
        testScope.runTest {
            try {
                Dispatchers.setMain(kosmos.testDispatcher)

                // Simulate attaching the view so flow collection starts.
                whenever(view.viewTreeObserver).thenReturn(mock(ViewTreeObserver::class.java))
                val onAttachStateChangeListenerArgumentCaptor =
                    ArgumentCaptor.forClass(View.OnAttachStateChangeListener::class.java)
                verify(view, atLeast(1))
                    .addOnAttachStateChangeListener(
                        onAttachStateChangeListenerArgumentCaptor.capture()
                    )
                for (listener in onAttachStateChangeListenerArgumentCaptor.allValues) {
                    listener.onViewAttachedToWindow(view)
                }
                testableLooper.processAllMessages()
                clearInvocations(notificationShadeDepthController)

                brightnessMirrorShowingInteractor.setMirrorShowing(true)
                runCurrent()
                verify(notificationShadeDepthController).brightnessMirrorVisible = true

                brightnessMirrorShowingInteractor.setMirrorShowing(false)
                runCurrent()
                verify(notificationShadeDepthController).brightnessMirrorVisible = false
            } finally {
                Dispatchers.resetMain()
            }
        }

    companion object {
        private val DOWN_EVENT = MotionEvent.obtain(0L, 0L, MotionEvent.ACTION_DOWN, 0f, 0f, 0)
        private val MOVE_EVENT = MotionEvent.obtain(0L, 0L, MotionEvent.ACTION_MOVE, 0f, 0f, 0)
        private const val VIEW_BOTTOM = 100

        @JvmStatic
        @Parameters(name = "{0}")
        fun getParams(): List<FlagsParameterization> {
            return FlagsParameterization.allCombinationsOf().andSceneContainer()
        }
    }
}
