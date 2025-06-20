/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.systemui.keyguard.domain.interactor

import android.app.ActivityManager
import android.app.WindowConfiguration
import android.platform.test.annotations.DisableFlags
import android.platform.test.annotations.EnableFlags
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.Flags
import com.android.systemui.SysuiTestCase
import com.android.systemui.coroutines.collectValues
import com.android.systemui.keyguard.data.repository.FakeKeyguardTransitionRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepository
import com.android.systemui.keyguard.data.repository.keyguardOcclusionRepository
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.StatusBarState
import com.android.systemui.keyguard.shared.model.StatusBarState.KEYGUARD
import com.android.systemui.keyguard.shared.model.TransitionState
import com.android.systemui.keyguard.shared.model.TransitionStep
import com.android.systemui.keyguard.util.KeyguardTransitionRepositorySpySubject.Companion.assertThat as assertThatRepository
import com.android.systemui.kosmos.testScope
import com.android.systemui.shade.data.repository.FlingInfo
import com.android.systemui.shade.data.repository.fakeShadeRepository
import com.android.systemui.testKosmos
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.reset
import org.mockito.Mockito.spy

@SmallTest
@RunWith(AndroidJUnit4::class)
class FromLockscreenTransitionInteractorTest : SysuiTestCase() {
    private val kosmos =
        testKosmos().apply {
            this.fakeKeyguardTransitionRepository =
                spy(FakeKeyguardTransitionRepository(testScope = testScope))
        }

    private val testScope = kosmos.testScope
    private val underTest = kosmos.fromLockscreenTransitionInteractor
    private lateinit var transitionRepository: FakeKeyguardTransitionRepository
    private val shadeRepository = kosmos.fakeShadeRepository
    private val keyguardRepository = kosmos.fakeKeyguardRepository

    @Before
    fun setup() {
        transitionRepository = kosmos.fakeKeyguardTransitionRepository
    }

    @Test
    fun testSurfaceBehindVisibility() =
        testScope.runTest {
            val values by collectValues(underTest.surfaceBehindVisibility)
            runCurrent()

            // Transition-specific surface visibility should be null ("don't care") initially.
            assertThat(values).containsExactly(null)

            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.STARTED,
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.AOD,
                )
            )
            runCurrent()

            assertThat(values)
                .containsExactly(
                    null // LOCKSCREEN -> AOD does not have any specific surface visibility.
                )

            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.STARTED,
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.GONE,
                )
            )
            runCurrent()

            assertThat(values)
                .containsExactly(
                    null,
                    true, // Surface is made visible immediately during LOCKSCREEN -> GONE
                )
                .inOrder()

            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.FINISHED,
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.GONE,
                )
            )
            runCurrent()

            assertThat(values)
                .containsExactly(
                    null,
                    true, // Surface remains visible.
                )
                .inOrder()
        }

    @Test
    fun draggingToPrimaryBouncerUpdateIsSent() =
        testScope.runTest {
            underTest.start()
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.OFF,
                to = KeyguardState.LOCKSCREEN,
                testScope,
            )

            val steps by collectValues(transitionRepository.transitions)

            shadeRepository.setLegacyShadeExpansion(0f)
            shadeRepository.setLegacyShadeTracking(true)
            keyguardRepository.setKeyguardDismissible(false)
            keyguardRepository.setStatusBarState(KEYGUARD)
            runCurrent()

            // User starts dragging up
            shadeRepository.setLegacyShadeExpansion(0.1f)
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.PRIMARY_BOUNCER,
                )

            // FakeKeyguardRepository doesn't send the step, so do that
            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.STARTED,
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.PRIMARY_BOUNCER,
                    value = 0f,
                )
            )
            runCurrent()

            // Update is sent
            shadeRepository.setLegacyShadeExpansion(0.2f)
            runCurrent()

            assertThatRepository(transitionRepository)
                .updatedTransition(value = 1f, state = TransitionState.RUNNING)
        }

    @Test
    @EnableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionsToGone_whenDismissFlingWhileDismissable_flagEnabled() =
        testScope.runTest {
            underTest.start()
            assertThatRepository(transitionRepository).noTransitionsStarted()

            transitionRepository.sendTransitionSteps(
                from = KeyguardState.DOZING,
                to = KeyguardState.LOCKSCREEN,
                testScope = testScope,
            )

            keyguardRepository.setKeyguardDismissible(true)
            runCurrent()
            shadeRepository.setCurrentFling(
                FlingInfo(expand = false) // Is a dismiss fling upward (expand = false).
            )
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(from = KeyguardState.LOCKSCREEN, to = KeyguardState.GONE)
        }

    @Test
    @DisableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testDoesNotTransitionToGone_whenDismissFlingWhileDismissable_flagDisabled() =
        testScope.runTest {
            underTest.start()
            assertThatRepository(transitionRepository).noTransitionsStarted()

            keyguardRepository.setKeyguardDismissible(true)
            runCurrent()
            shadeRepository.setCurrentFling(
                FlingInfo(expand = true) // Not a dismiss fling (expand = true).
            )
            runCurrent()

            assertThatRepository(transitionRepository).noTransitionsStarted()
        }

    @Test
    @DisableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testDoesNotTransitionToGone_whenDismissFling_emitsNull() =
        testScope.runTest {
            underTest.start()
            assertThatRepository(transitionRepository).noTransitionsStarted()

            keyguardRepository.setKeyguardDismissible(true)
            runCurrent()

            // The fling is null when it a) initializes b) ends and in either case we should not
            // swipe to unlock.
            shadeRepository.setCurrentFling(null)
            runCurrent()

            assertThatRepository(transitionRepository).noTransitionsStarted()
        }

    @EnableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionsToOccluded_whenShowWhenLockedActivityOnTop() =
        testScope.runTest {
            underTest.start()
            runCurrent()

            reset(transitionRepository)
            kosmos.keyguardOcclusionRepository.setShowWhenLockedActivityInfo(
                true,
                ActivityManager.RunningTaskInfo().apply {
                    topActivityType = WindowConfiguration.ACTIVITY_TYPE_STANDARD
                },
            )
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(from = KeyguardState.LOCKSCREEN, to = KeyguardState.OCCLUDED)
        }

    @Test
    @EnableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionsToDream_whenDreamActivityOnTop() =
        testScope.runTest {
            underTest.start()
            runCurrent()

            reset(transitionRepository)
            kosmos.keyguardOcclusionRepository.setShowWhenLockedActivityInfo(
                true,
                ActivityManager.RunningTaskInfo().apply {
                    topActivityType = WindowConfiguration.ACTIVITY_TYPE_DREAM
                },
            )
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(from = KeyguardState.LOCKSCREEN, to = KeyguardState.DREAMING)
        }

    @Test
    fun testTransitionsBackToOccluded_ifOccluded_andCanceledSwipe() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setStatusBarState(StatusBarState.KEYGUARD)
            keyguardRepository.setKeyguardDismissible(false)
            keyguardRepository.setKeyguardOccluded(false)
            runCurrent()

            reset(transitionRepository)

            shadeRepository.setLegacyShadeTracking(true)
            runCurrent()
            shadeRepository.setLegacyShadeExpansion(0.5f)
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.PRIMARY_BOUNCER,
                )
            reset(transitionRepository)

            runCurrent()

            shadeRepository.setLegacyShadeExpansion(0.6f)
            shadeRepository.setLegacyShadeExpansion(0.7f)
            runCurrent()

            shadeRepository.setLegacyShadeExpansion(1f)
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.LOCKSCREEN,
                )
        }

    /**
     * External signals can cause us to transition from PRIMARY_BOUNCER -> * while a manual
     * transition is in progress. This test was added after a bug that caused the manual transition
     * ID to get stuck in this scenario, preventing subsequent transitions to PRIMARY_BOUNCER.
     */
    @Test
    fun testExternalTransitionAwayFromBouncer_transitionIdNotStuck() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setStatusBarState(StatusBarState.KEYGUARD)
            keyguardRepository.setKeyguardDismissible(false)
            shadeRepository.setLegacyShadeTracking(true)
            keyguardRepository.setKeyguardOccluded(false)
            runCurrent()

            reset(transitionRepository)

            // Disable automatic sending of transition steps so we can send steps through RUNNING
            // to simulate a cancellation.
            transitionRepository.sendTransitionStepsOnStartTransition = false
            shadeRepository.setLegacyShadeExpansion(0.5f)
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.PRIMARY_BOUNCER,
                )

            // Partially transition to PRIMARY_BOUNCER.
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.PRIMARY_BOUNCER,
                throughTransitionState = TransitionState.RUNNING,
                testScope = testScope,
            )

            // Start a transition to GONE, which will cancel LS -> BOUNCER.
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.PRIMARY_BOUNCER,
                to = KeyguardState.GONE,
                testScope = testScope,
            )

            // Go to AOD, then LOCKSCREEN.
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.GONE,
                to = KeyguardState.AOD,
                testScope = testScope,
            )
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.AOD,
                to = KeyguardState.LOCKSCREEN,
                testScope = testScope,
            )

            reset(transitionRepository)

            // Start a swipe up to the bouncer, and verify that we started a transition to
            // PRIMARY_BOUNCER, verifying the transition ID did not get stuck.
            shadeRepository.setLegacyShadeExpansion(0.25f)
            runCurrent()

            assertThatRepository(transitionRepository)
                .startedTransition(
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.PRIMARY_BOUNCER,
                )
        }
}
