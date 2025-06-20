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

package com.android.systemui.communal

import android.platform.test.annotations.DisableFlags
import android.platform.test.annotations.EnableFlags
import android.platform.test.flag.junit.FlagsParameterization
import android.service.dream.dreamManager
import androidx.test.filters.SmallTest
import com.android.systemui.Flags
import com.android.systemui.Flags.FLAG_GLANCEABLE_HUB_V2
import com.android.systemui.SysuiTestCase
import com.android.systemui.communal.domain.interactor.communalSceneInteractor
import com.android.systemui.communal.domain.interactor.communalSettingsInteractor
import com.android.systemui.communal.domain.interactor.setCommunalV2Enabled
import com.android.systemui.flags.Flags.COMMUNAL_SERVICE_ENABLED
import com.android.systemui.flags.fakeFeatureFlagsClassic
import com.android.systemui.keyguard.data.repository.fakeKeyguardRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepository
import com.android.systemui.keyguard.data.repository.keyguardRepository
import com.android.systemui.keyguard.domain.interactor.keyguardInteractor
import com.android.systemui.keyguard.domain.interactor.keyguardTransitionInteractor
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.kosmos.applicationCoroutineScope
import com.android.systemui.kosmos.testScope
import com.android.systemui.power.data.repository.fakePowerRepository
import com.android.systemui.power.domain.interactor.powerInteractor
import com.android.systemui.power.shared.model.ScreenPowerState
import com.android.systemui.testKosmos
import com.android.systemui.util.mockito.whenever
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

@SmallTest
@EnableFlags(Flags.FLAG_COMMUNAL_HUB)
@RunWith(ParameterizedAndroidJunit4::class)
class CommunalDreamStartableTest(flags: FlagsParameterization) : SysuiTestCase() {
    private val kosmos = testKosmos()
    private val testScope = kosmos.testScope

    private lateinit var underTest: CommunalDreamStartable

    private val dreamManager by lazy { kosmos.dreamManager }
    private val keyguardRepository by lazy { kosmos.fakeKeyguardRepository }
    private val powerRepository by lazy { kosmos.fakePowerRepository }

    init {
        mSetFlagsRule.setFlagsParameterization(flags)
    }

    @Before
    fun setUp() {
        kosmos.fakeFeatureFlagsClassic.set(COMMUNAL_SERVICE_ENABLED, true)

        underTest =
            CommunalDreamStartable(
                powerInteractor = kosmos.powerInteractor,
                communalSettingsInteractor = kosmos.communalSettingsInteractor,
                keyguardInteractor = kosmos.keyguardInteractor,
                keyguardTransitionInteractor = kosmos.keyguardTransitionInteractor,
                dreamManager = dreamManager,
                communalSceneInteractor = kosmos.communalSceneInteractor,
                bgScope = kosmos.applicationCoroutineScope,
            )
    }

    @EnableFlags(FLAG_GLANCEABLE_HUB_V2)
    @Test
    fun dreamNotStartedWhenTransitioningToHub() =
        testScope.runTest {
            // Enable v2 flag and recreate + rerun start method.
            kosmos.setCommunalV2Enabled(true)
            underTest.start()

            keyguardRepository.setKeyguardShowing(true)
            keyguardRepository.setDreaming(false)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(true)
            runCurrent()

            transition(from = KeyguardState.DREAMING, to = KeyguardState.GLANCEABLE_HUB)

            verify(dreamManager, never()).startDream()
        }

    @DisableFlags(FLAG_GLANCEABLE_HUB_V2)
    @Test
    fun startDreamWhenTransitioningToHub() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setKeyguardShowing(true)
            keyguardRepository.setDreaming(false)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(true)
            runCurrent()

            verify(dreamManager, never()).startDream()

            transition(from = KeyguardState.DREAMING, to = KeyguardState.GLANCEABLE_HUB)

            verify(dreamManager).startDream()
        }

    @Test
    @EnableFlags(Flags.FLAG_RESTART_DREAM_ON_UNOCCLUDE)
    fun restartDreamingWhenTransitioningFromDreamingToOccludedToDreaming() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setDreaming(false)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(true)
            runCurrent()

            verify(dreamManager, never()).startDream()

            kosmos.fakeKeyguardRepository.setKeyguardOccluded(true)
            kosmos.fakeKeyguardRepository.setDreaming(true)
            runCurrent()

            transition(from = KeyguardState.DREAMING, to = KeyguardState.OCCLUDED)
            kosmos.fakeKeyguardRepository.setKeyguardOccluded(false)
            kosmos.fakeKeyguardRepository.setDreaming(false)
            runCurrent()

            transition(from = KeyguardState.OCCLUDED, to = KeyguardState.DREAMING)
            runCurrent()

            verify(dreamManager).startDream()
        }

    @DisableFlags(FLAG_GLANCEABLE_HUB_V2)
    @Test
    fun shouldNotStartDreamWhenIneligibleToDream() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setDreaming(false)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            // Not eligible to dream
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(false)
            transition(from = KeyguardState.DREAMING, to = KeyguardState.GLANCEABLE_HUB)

            verify(dreamManager, never()).startDream()
        }

    @DisableFlags(FLAG_GLANCEABLE_HUB_V2)
    @Test
    fun shouldNotStartDreamIfAlreadyDreaming() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setDreaming(true)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(true)
            transition(from = KeyguardState.DREAMING, to = KeyguardState.GLANCEABLE_HUB)

            verify(dreamManager, never()).startDream()
        }

    @DisableFlags(FLAG_GLANCEABLE_HUB_V2)
    @Test
    fun shouldNotStartDreamForInvalidTransition() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setDreaming(true)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(true)

            // Verify we do not trigger dreaming for any other state besides glanceable hub
            for (state in KeyguardState.entries) {
                if (state == KeyguardState.GLANCEABLE_HUB) continue
                transition(from = KeyguardState.GLANCEABLE_HUB, to = state)
                verify(dreamManager, never()).startDream()
            }
        }

    @DisableFlags(FLAG_GLANCEABLE_HUB_V2)
    @Test
    fun shouldNotStartDreamWhenLaunchingWidget() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setKeyguardShowing(true)
            keyguardRepository.setDreaming(false)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            kosmos.communalSceneInteractor.setIsLaunchingWidget(true)
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(true)
            runCurrent()

            transition(from = KeyguardState.DREAMING, to = KeyguardState.GLANCEABLE_HUB)

            verify(dreamManager, never()).startDream()
        }

    @DisableFlags(FLAG_GLANCEABLE_HUB_V2)
    @Test
    fun shouldNotStartDreamWhenOccluded() =
        testScope.runTest {
            underTest.start()
            keyguardRepository.setKeyguardShowing(true)
            keyguardRepository.setDreaming(false)
            powerRepository.setScreenPowerState(ScreenPowerState.SCREEN_ON)
            keyguardRepository.setKeyguardOccluded(true)
            whenever(dreamManager.canStartDreaming(/* isScreenOn= */ true)).thenReturn(true)
            runCurrent()

            transition(from = KeyguardState.DREAMING, to = KeyguardState.GLANCEABLE_HUB)

            verify(dreamManager, never()).startDream()
        }

    private suspend fun TestScope.transition(from: KeyguardState, to: KeyguardState) {
        kosmos.fakeKeyguardTransitionRepository.sendTransitionSteps(
            from = from,
            to = to,
            testScope = this,
        )
        runCurrent()
    }

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getParams(): List<FlagsParameterization> {
            return FlagsParameterization.allCombinationsOf(FLAG_GLANCEABLE_HUB_V2)
        }
    }
}
