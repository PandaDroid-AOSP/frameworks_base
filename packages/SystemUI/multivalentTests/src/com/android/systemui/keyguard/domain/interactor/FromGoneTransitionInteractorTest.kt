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
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.internal.widget.LockPatternUtils
import com.android.systemui.Flags.FLAG_GLANCEABLE_HUB_V2
import com.android.systemui.Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR
import com.android.systemui.SysuiTestCase
import com.android.systemui.communal.data.repository.communalSceneRepository
import com.android.systemui.communal.domain.interactor.setCommunalV2Enabled
import com.android.systemui.communal.shared.model.CommunalScenes
import com.android.systemui.keyguard.data.repository.fakeBiometricSettingsRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepositorySpy
import com.android.systemui.keyguard.data.repository.keyguardTransitionRepository
import com.android.systemui.keyguard.shared.model.AuthenticationFlags
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.TransitionState
import com.android.systemui.keyguard.shared.model.TransitionStep
import com.android.systemui.keyguard.util.KeyguardTransitionRepositorySpySubject.Companion.assertThat
import com.android.systemui.kosmos.collectLastValue
import com.android.systemui.kosmos.runTest
import com.android.systemui.kosmos.testScope
import com.android.systemui.kosmos.useUnconfinedTestDispatcher
import com.android.systemui.testKosmos
import com.google.common.truth.Truth
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.reset

@SmallTest
@RunWith(AndroidJUnit4::class)
class FromGoneTransitionInteractorTest : SysuiTestCase() {
    private val kosmos =
        testKosmos().useUnconfinedTestDispatcher().apply {
            this.keyguardTransitionRepository = fakeKeyguardTransitionRepositorySpy
        }
    private val underTest = kosmos.fromGoneTransitionInteractor

    @Before
    fun setUp() {
        underTest.start()
    }

    @Test
    @Ignore("Fails due to fix for b/324432820 - will re-enable once permanent fix is submitted.")
    fun testDoesNotTransitionToLockscreen_ifStartedButNotFinishedInGone() =
        kosmos.runTest {
            fakeKeyguardTransitionRepositorySpy.sendTransitionSteps(
                listOf(
                    TransitionStep(
                        from = KeyguardState.LOCKSCREEN,
                        to = KeyguardState.GONE,
                        transitionState = TransitionState.STARTED,
                    ),
                    TransitionStep(
                        from = KeyguardState.LOCKSCREEN,
                        to = KeyguardState.GONE,
                        transitionState = TransitionState.RUNNING,
                    ),
                ),
                testScope,
            )
            reset(fakeKeyguardTransitionRepositorySpy)
            fakeKeyguardRepository.setKeyguardShowing(true)

            // We're in the middle of a LOCKSCREEN -> GONE transition.
            assertThat(fakeKeyguardTransitionRepositorySpy).noTransitionsStarted()
        }

    @Test
    @DisableFlags(FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionsToLockscreen_ifFinishedInGone() =
        kosmos.runTest {
            fakeKeyguardTransitionRepositorySpy.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.GONE,
                testScope,
            )
            reset(fakeKeyguardTransitionRepositorySpy)
            fakeKeyguardRepository.setKeyguardShowing(true)

            // We're in the middle of a GONE -> LOCKSCREEN transition.
            assertThat(fakeKeyguardTransitionRepositorySpy)
                .startedTransition(to = KeyguardState.LOCKSCREEN)
        }

    @Test
    @EnableFlags(FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionsToLockscreen_ifFinishedInGone_wmRefactor() =
        kosmos.runTest {
            fakeKeyguardTransitionRepositorySpy.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.GONE,
                testScope,
            )
            reset(fakeKeyguardTransitionRepositorySpy)

            // Trigger lockdown.
            fakeBiometricSettingsRepository.setAuthenticationFlags(
                AuthenticationFlags(
                    0,
                    LockPatternUtils.StrongAuthTracker.STRONG_AUTH_REQUIRED_AFTER_USER_LOCKDOWN,
                )
            )

            // We're in the middle of a GONE -> LOCKSCREEN transition.
            assertThat(fakeKeyguardTransitionRepositorySpy)
                .startedTransition(to = KeyguardState.LOCKSCREEN)
        }

    @Test
    @EnableFlags(FLAG_GLANCEABLE_HUB_V2)
    @DisableFlags(FLAG_KEYGUARD_WM_STATE_REFACTOR)
    fun testTransitionToGlanceableHub() =
        kosmos.runTest {
            val currentScene by collectLastValue(communalSceneRepository.currentScene)

            fakeKeyguardTransitionRepositorySpy.sendTransitionSteps(
                from = KeyguardState.LOCKSCREEN,
                to = KeyguardState.GONE,
                testScope,
            )
            reset(fakeKeyguardTransitionRepositorySpy)
            // Communal is enabled
            setCommunalV2Enabled(true)
            Truth.assertThat(currentScene).isEqualTo(CommunalScenes.Blank)

            fakeKeyguardRepository.setKeyguardShowing(true)

            Truth.assertThat(currentScene).isEqualTo(CommunalScenes.Communal)
            assertThat(fakeKeyguardTransitionRepositorySpy).noTransitionsStarted()
        }
}
