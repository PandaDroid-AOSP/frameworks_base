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

import android.platform.test.annotations.EnableFlags
import android.platform.test.flag.junit.FlagsParameterization
import androidx.test.filters.SmallTest
import com.android.compose.animation.scene.ObservableTransitionState
import com.android.systemui.Flags.FLAG_GLANCEABLE_HUB_V2
import com.android.systemui.Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR
import com.android.systemui.SysuiTestCase
import com.android.systemui.bouncer.data.repository.fakeKeyguardBouncerRepository
import com.android.systemui.communal.data.repository.fakeCommunalSceneRepository
import com.android.systemui.communal.domain.interactor.communalSceneInteractor
import com.android.systemui.communal.domain.interactor.setCommunalV2Available
import com.android.systemui.communal.domain.interactor.setCommunalV2ConfigEnabled
import com.android.systemui.communal.shared.model.CommunalScenes
import com.android.systemui.coroutines.collectValues
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepositorySpy
import com.android.systemui.keyguard.data.repository.keyguardOcclusionRepository
import com.android.systemui.keyguard.data.repository.keyguardTransitionRepository
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.TransitionState
import com.android.systemui.keyguard.shared.model.TransitionStep
import com.android.systemui.keyguard.util.KeyguardTransitionRepositorySpySubject.Companion.assertThat
import com.android.systemui.kosmos.collectLastValue
import com.android.systemui.kosmos.runCurrent
import com.android.systemui.kosmos.runTest
import com.android.systemui.kosmos.testScope
import com.android.systemui.power.domain.interactor.PowerInteractor.Companion.setAsleepForTest
import com.android.systemui.power.domain.interactor.powerInteractor
import com.android.systemui.testKosmos
import com.google.common.truth.Truth
import junit.framework.Assert.assertEquals
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.reset
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

@SmallTest
@RunWith(ParameterizedAndroidJunit4::class)
class FromPrimaryBouncerTransitionInteractorTest(flags: FlagsParameterization) : SysuiTestCase() {

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getParams(): List<FlagsParameterization> {
            return FlagsParameterization.allCombinationsOf(FLAG_GLANCEABLE_HUB_V2)
        }
    }

    init {
        mSetFlagsRule.setFlagsParameterization(flags)
    }

    private val kosmos =
        testKosmos().apply {
            this.keyguardTransitionRepository = fakeKeyguardTransitionRepositorySpy
        }
    val underTest = kosmos.fromPrimaryBouncerTransitionInteractor
    val testScope = kosmos.testScope
    val transitionRepository = kosmos.fakeKeyguardTransitionRepositorySpy
    val bouncerRepository = kosmos.fakeKeyguardBouncerRepository

    @Before
    fun setUp() {
        kosmos.setCommunalV2ConfigEnabled(true)
    }

    @Test
    fun testSurfaceBehindVisibility() =
        testScope.runTest {
            val values by collectValues(underTest.surfaceBehindVisibility)
            runCurrent()

            // Transition-specific surface visibility should be null ("don't care") initially.
            assertEquals(listOf(null), values)

            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.STARTED,
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.LOCKSCREEN,
                )
            )

            runCurrent()

            assertEquals(
                listOf(
                    null // PRIMARY_BOUNCER -> LOCKSCREEN does not have any specific visibility.
                ),
                values,
            )

            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.STARTED,
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.GONE,
                )
            )

            runCurrent()

            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.RUNNING,
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.GONE,
                    value = 0.01f,
                )
            )

            runCurrent()

            assertEquals(
                listOf(
                    null,
                    false, // Surface is only made visible once the bouncer UI animates out.
                ),
                values,
            )

            transitionRepository.sendTransitionStep(
                TransitionStep(
                    transitionState = TransitionState.STARTED,
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.GONE,
                    value = 0.99f,
                )
            )

            runCurrent()

            assertEquals(
                listOf(
                    null,
                    false,
                    true, // Surface should eventually be visible.
                ),
                values,
            )
        }

    @Test
    @EnableFlags(FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testReturnToLockscreen_whenBouncerHides() =
        testScope.runTest {
            underTest.start()
            bouncerRepository.setPrimaryShow(true)
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.PRIMARY_BOUNCER,
                testScope,
            )

            reset(transitionRepository)

            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.LOCKSCREEN,
                )
        }

    @Test
    @EnableFlags(FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testReturnToGlanceableHub_whenBouncerHides_ifIdleOnCommunal() =
        testScope.runTest {
            underTest.start()
            kosmos.fakeCommunalSceneRepository.setTransitionState(
                flowOf(ObservableTransitionState.Idle(CommunalScenes.Communal))
            )
            bouncerRepository.setPrimaryShow(true)
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.PRIMARY_BOUNCER,
                testScope,
            )

            reset(transitionRepository)

            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.GLANCEABLE_HUB,
                )
        }

    @Test
    @EnableFlags(FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionToOccluded_bouncerHide_occludingActivityOnTop() =
        testScope.runTest {
            underTest.start()
            bouncerRepository.setPrimaryShow(true)
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.PRIMARY_BOUNCER,
                testScope,
            )

            reset(transitionRepository)

            kosmos.keyguardOcclusionRepository.setShowWhenLockedActivityInfo(true)
            runCurrent()

            // Shouldn't transition to OCCLUDED until the bouncer hides.
            assertThat(transitionRepository).noTransitionsStarted()

            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.OCCLUDED,
                )
        }

    @Test
    @EnableFlags(FLAG_GLANCEABLE_HUB_V2)
    fun testTransitionToDozing_bouncerShowingOnTopOfGlanceableHub() =
        kosmos.runTest {
            underTest.start()
            setCommunalV2Available(true)

            val currentScene by collectLastValue(communalSceneInteractor.currentScene)
            // Communal is showing.
            fakeCommunalSceneRepository.changeScene(CommunalScenes.Communal)

            Truth.assertThat(currentScene).isEqualTo(CommunalScenes.Communal)

            // Bouncer is shown on top of the Glanceable Hub.
            bouncerRepository.setPrimaryShow(true)
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.GLANCEABLE_HUB,
                to = KeyguardState.PRIMARY_BOUNCER,
                testScope,
            )

            reset(transitionRepository)

            powerInteractor.setAsleepForTest()
            runCurrent()

            Truth.assertThat(currentScene).isEqualTo(CommunalScenes.Blank)
        }
}
