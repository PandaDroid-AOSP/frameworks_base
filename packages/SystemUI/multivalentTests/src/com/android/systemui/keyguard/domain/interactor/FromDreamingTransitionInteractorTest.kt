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

package com.android.systemui.keyguard.domain.interactor

import android.platform.test.annotations.DisableFlags
import android.platform.test.annotations.EnableFlags
import android.platform.test.flag.junit.FlagsParameterization
import android.provider.Settings
import android.service.dream.dreamManager
import androidx.test.filters.SmallTest
import com.android.systemui.Flags
import com.android.systemui.Flags.FLAG_GLANCEABLE_HUB_V2
import com.android.systemui.Flags.glanceableHubV2
import com.android.systemui.SysuiTestCase
import com.android.systemui.bouncer.data.repository.fakeKeyguardBouncerRepository
import com.android.systemui.common.data.repository.batteryRepository
import com.android.systemui.common.data.repository.fake
import com.android.systemui.communal.data.repository.communalSceneRepository
import com.android.systemui.communal.domain.interactor.setCommunalAvailable
import com.android.systemui.communal.domain.interactor.setCommunalV2ConfigEnabled
import com.android.systemui.communal.shared.model.CommunalScenes
import com.android.systemui.flags.andSceneContainer
import com.android.systemui.keyguard.data.repository.FakeKeyguardTransitionRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepositorySpy
import com.android.systemui.keyguard.data.repository.keyguardOcclusionRepository
import com.android.systemui.keyguard.data.repository.keyguardTransitionRepository
import com.android.systemui.keyguard.shared.model.BiometricUnlockMode
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.util.KeyguardTransitionRepositorySpySubject.Companion.assertThat
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.runTest
import com.android.systemui.kosmos.testScope
import com.android.systemui.kosmos.useUnconfinedTestDispatcher
import com.android.systemui.power.domain.interactor.PowerInteractor.Companion.setAwakeForTest
import com.android.systemui.power.domain.interactor.powerInteractor
import com.android.systemui.statusbar.domain.interactor.keyguardOcclusionInteractor
import com.android.systemui.testKosmos
import com.android.systemui.user.data.repository.fakeUserRepository
import com.android.systemui.util.settings.fakeSettings
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.advanceTimeBy
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.anyBoolean
import org.mockito.Mockito.reset
import org.mockito.kotlin.whenever
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

@SmallTest
@RunWith(ParameterizedAndroidJunit4::class)
class FromDreamingTransitionInteractorTest(flags: FlagsParameterization?) : SysuiTestCase() {
    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getParams(): List<FlagsParameterization> {
            return FlagsParameterization.allCombinationsOf(FLAG_GLANCEABLE_HUB_V2)
                .andSceneContainer()
        }
    }

    init {
        mSetFlagsRule.setFlagsParameterization(flags!!)
    }

    private val kosmos =
        testKosmos().useUnconfinedTestDispatcher().apply {
            this.fakeKeyguardTransitionRepository =
                FakeKeyguardTransitionRepository(
                    // This test sends transition steps manually in the test cases.
                    initiallySendTransitionStepsOnStartTransition = false,
                    testScope = testScope,
                )

            this.keyguardTransitionRepository = fakeKeyguardTransitionRepositorySpy
        }

    private val Kosmos.underTest by Kosmos.Fixture { fromDreamingTransitionInteractor }
    private val Kosmos.transitionRepository by
        Kosmos.Fixture { fakeKeyguardTransitionRepositorySpy }

    @Before
    fun setup() {
        runBlocking {
            kosmos.transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.DREAMING,
                kosmos.testScope,
            )
            reset(kosmos.transitionRepository)
            kosmos.setCommunalAvailable(true)
            kosmos.setCommunalV2ConfigEnabled(true)
        }
        kosmos.underTest.start()
    }

    @Test
    @EnableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    @Ignore("Until b/349837588 is fixed")
    fun testTransitionToOccluded_ifDreamEnds_occludingActivityOnTop() =
        kosmos.runTest {
            fakeKeyguardRepository.setDreaming(true)
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.DREAMING,
                kosmos.testScope,
            )

            reset(transitionRepository)

            keyguardOcclusionRepository.setShowWhenLockedActivityInfo(onTop = true)
            fakeKeyguardRepository.setDreaming(false)

            assertThat(transitionRepository)
                .startedTransition(from = KeyguardState.DREAMING, to = KeyguardState.OCCLUDED)
        }

    @Test
    @EnableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testDoesNotTransitionToOccluded_occludingActivityOnTop_whileStillDreaming() =
        kosmos.runTest {
            fakeKeyguardRepository.setDreaming(true)
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.DREAMING,
                testScope,
            )
            reset(transitionRepository)
            keyguardOcclusionRepository.setShowWhenLockedActivityInfo(onTop = true)

            assertThat(transitionRepository).noTransitionsStarted()
        }

    @Test
    @EnableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionsToLockscreen_whenOccludingActivityEnds() =
        kosmos.runTest {
            fakeKeyguardRepository.setDreaming(true)
            keyguardOcclusionInteractor.setWmNotifiedShowWhenLockedActivityOnTop(true)
            // Transition to DREAMING and set the power interactor awake
            powerInteractor.setAwakeForTest()

            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.DREAMING,
                testScope,
            )
            fakeKeyguardRepository.setBiometricUnlockState(BiometricUnlockMode.NONE)

            // Get past initial setup
            testScope.advanceTimeBy(600L)
            reset(transitionRepository)

            keyguardOcclusionRepository.setShowWhenLockedActivityInfo(onTop = false)
            fakeKeyguardRepository.setDreaming(false)
            testScope.advanceTimeBy(60L)

            assertThat(transitionRepository)
                .startedTransition(from = KeyguardState.DREAMING, to = KeyguardState.LOCKSCREEN)
        }

    @Test
    fun testTransitionToAlternateBouncer() =
        kosmos.runTest {
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.DREAMING,
                testScope,
            )
            reset(transitionRepository)

            fakeKeyguardBouncerRepository.setAlternateVisible(true)

            assertThat(transitionRepository)
                .startedTransition(
                    from = KeyguardState.DREAMING,
                    to = KeyguardState.ALTERNATE_BOUNCER,
                )
        }

    @Test
    @DisableFlags(Flags.FLAG_SCENE_CONTAINER)
    fun testTransitionToGlanceableHubOnWake() =
        kosmos.runTest {
            transitionRepository.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.DREAMING,
                testScope,
            )
            reset(transitionRepository)

            setCommunalAvailable(true)
            if (glanceableHubV2()) {
                val user = fakeUserRepository.asMainUser()
                fakeSettings.putIntForUser(
                    Settings.Secure.SCREENSAVER_ACTIVATE_ON_SLEEP,
                    1,
                    user.id,
                )
                batteryRepository.fake.setDevicePluggedIn(true)
            } else {
                whenever(dreamManager.canStartDreaming(anyBoolean())).thenReturn(true)
            }

            // Device wakes up.
            powerInteractor.setAwakeForTest()
            testScope.advanceTimeBy(150L)

            // We transition to the hub when waking up.
            assertThat(communalSceneRepository.currentScene.value)
                .isEqualTo(CommunalScenes.Communal)
            // No transitions are directly started by this interactor.
            assertThat(transitionRepository).noTransitionsStarted()
        }
}
