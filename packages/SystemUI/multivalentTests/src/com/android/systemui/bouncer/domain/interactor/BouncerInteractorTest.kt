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

package com.android.systemui.bouncer.domain.interactor

import android.content.testableContext
import android.provider.Settings.Global.ONE_HANDED_KEYGUARD_SIDE
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.compose.animation.scene.ObservableTransitionState
import com.android.internal.logging.uiEventLoggerFake
import com.android.systemui.SysuiTestCase
import com.android.systemui.authentication.data.repository.FakeAuthenticationRepository
import com.android.systemui.authentication.data.repository.fakeAuthenticationRepository
import com.android.systemui.authentication.domain.interactor.AuthenticationResult
import com.android.systemui.authentication.domain.interactor.authenticationInteractor
import com.android.systemui.authentication.shared.model.AuthenticationMethodModel
import com.android.systemui.authentication.shared.model.AuthenticationPatternCoordinate
import com.android.systemui.authentication.shared.model.BouncerInputSide
import com.android.systemui.bouncer.data.repository.bouncerRepository
import com.android.systemui.bouncer.shared.logging.BouncerUiEvent
import com.android.systemui.common.ui.data.repository.fakeConfigurationRepository
import com.android.systemui.coroutines.collectLastValue
import com.android.systemui.coroutines.collectValues
import com.android.systemui.deviceentry.domain.interactor.deviceEntryFaceAuthInteractor
import com.android.systemui.flags.EnableSceneContainer
import com.android.systemui.flags.Flags.FULL_SCREEN_USER_SWITCHER
import com.android.systemui.flags.fakeFeatureFlagsClassic
import com.android.systemui.keyguard.data.repository.fakeDeviceEntryFaceAuthRepository
import com.android.systemui.kosmos.collectLastValue
import com.android.systemui.kosmos.runCurrent
import com.android.systemui.kosmos.runTest
import com.android.systemui.kosmos.testScope
import com.android.systemui.power.data.repository.fakePowerRepository
import com.android.systemui.res.R
import com.android.systemui.scene.data.repository.sceneContainerRepository
import com.android.systemui.scene.shared.model.Overlays
import com.android.systemui.scene.shared.model.Scenes
import com.android.systemui.scene.transitionState
import com.android.systemui.testKosmos
import com.android.systemui.util.settings.fakeGlobalSettings
import com.google.common.truth.Truth.assertThat
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.MockitoAnnotations

@SmallTest
@RunWith(AndroidJUnit4::class)
@EnableSceneContainer
class BouncerInteractorTest : SysuiTestCase() {

    private val kosmos = testKosmos()
    private val testScope = kosmos.testScope
    private val authenticationInteractor = kosmos.authenticationInteractor
    private val uiEventLoggerFake = kosmos.uiEventLoggerFake

    private val underTest: BouncerInteractor by lazy { kosmos.bouncerInteractor }
    private val testableResources by lazy { kosmos.testableContext.orCreateTestableResources }

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)

        overrideResource(R.string.keyguard_enter_your_pin, MESSAGE_ENTER_YOUR_PIN)
        overrideResource(R.string.keyguard_enter_your_password, MESSAGE_ENTER_YOUR_PASSWORD)
        overrideResource(R.string.keyguard_enter_your_pattern, MESSAGE_ENTER_YOUR_PATTERN)
        overrideResource(R.string.kg_wrong_pin, MESSAGE_WRONG_PIN)
        overrideResource(R.string.kg_wrong_password, MESSAGE_WRONG_PASSWORD)
        overrideResource(R.string.kg_wrong_pattern, MESSAGE_WRONG_PATTERN)
    }

    @Test
    fun pinAuthMethod_sim_skipsAuthentication() =
        testScope.runTest {
            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Sim
            )
            runCurrent()

            // We rely on TelephonyManager to authenticate the sim card.
            // Additionally, authenticating the sim card does not unlock the device.
            // Thus, when auth method is sim, we expect to skip here.
            assertThat(underTest.authenticate(FakeAuthenticationRepository.DEFAULT_PIN))
                .isEqualTo(AuthenticationResult.SKIPPED)
            assertThat(uiEventLoggerFake.numLogs()).isEqualTo(0)
        }

    @Test
    fun pinAuthMethod_tryAutoConfirm_withAutoConfirmPin() =
        testScope.runTest {
            val isAutoConfirmEnabled by collectLastValue(underTest.isAutoConfirmEnabled)

            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Pin
            )
            runCurrent()
            kosmos.fakeAuthenticationRepository.setAutoConfirmFeatureEnabled(true)
            assertThat(isAutoConfirmEnabled).isTrue()

            // Incomplete input.
            assertThat(underTest.authenticate(listOf(1, 2), tryAutoConfirm = true))
                .isEqualTo(AuthenticationResult.SKIPPED)

            // Wrong 6-digit pin
            assertThat(underTest.authenticate(listOf(1, 2, 3, 5, 5, 6), tryAutoConfirm = true))
                .isEqualTo(AuthenticationResult.FAILED)
            assertThat(uiEventLoggerFake[0].eventId)
                .isEqualTo(BouncerUiEvent.BOUNCER_PASSWORD_FAILURE.id)

            // Correct input.
            assertThat(
                    underTest.authenticate(
                        FakeAuthenticationRepository.DEFAULT_PIN,
                        tryAutoConfirm = true,
                    )
                )
                .isEqualTo(AuthenticationResult.SUCCEEDED)
            assertThat(uiEventLoggerFake[1].eventId)
                .isEqualTo(BouncerUiEvent.BOUNCER_PASSWORD_SUCCESS.id)
            assertThat(uiEventLoggerFake.numLogs()).isEqualTo(2)
        }

    @Test
    fun pinAuthMethod_tryAutoConfirm_withoutAutoConfirmPin() =
        testScope.runTest {
            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Pin
            )
            runCurrent()

            // Incomplete input.
            assertThat(underTest.authenticate(listOf(1, 2), tryAutoConfirm = true))
                .isEqualTo(AuthenticationResult.SKIPPED)

            // Correct input.
            assertThat(
                    underTest.authenticate(
                        FakeAuthenticationRepository.DEFAULT_PIN,
                        tryAutoConfirm = true,
                    )
                )
                .isEqualTo(AuthenticationResult.SKIPPED)
        }

    @Test
    fun passwordAuthMethod() =
        testScope.runTest {
            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Password
            )
            runCurrent()

            // Wrong input.
            assertThat(underTest.authenticate("alohamora".toList()))
                .isEqualTo(AuthenticationResult.FAILED)
            assertThat(uiEventLoggerFake[0].eventId)
                .isEqualTo(BouncerUiEvent.BOUNCER_PASSWORD_FAILURE.id)

            // Too short input.
            assertThat(
                    underTest.authenticate(
                        buildList {
                            repeat(kosmos.fakeAuthenticationRepository.minPasswordLength - 1) { time
                                ->
                                add("$time")
                            }
                        }
                    )
                )
                .isEqualTo(AuthenticationResult.SKIPPED)

            // Correct input.
            assertThat(underTest.authenticate("password".toList()))
                .isEqualTo(AuthenticationResult.SUCCEEDED)
            assertThat(uiEventLoggerFake[1].eventId)
                .isEqualTo(BouncerUiEvent.BOUNCER_PASSWORD_SUCCESS.id)
            assertThat(uiEventLoggerFake.numLogs()).isEqualTo(2)
        }

    @Test
    fun patternAuthMethod() =
        testScope.runTest {
            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Pattern
            )
            runCurrent()

            // Wrong input.
            val wrongPattern =
                listOf(
                    AuthenticationPatternCoordinate(1, 2),
                    AuthenticationPatternCoordinate(1, 1),
                    AuthenticationPatternCoordinate(0, 0),
                    AuthenticationPatternCoordinate(0, 1),
                )
            assertThat(wrongPattern).isNotEqualTo(FakeAuthenticationRepository.PATTERN)
            assertThat(wrongPattern.size)
                .isAtLeast(kosmos.fakeAuthenticationRepository.minPatternLength)
            assertThat(underTest.authenticate(wrongPattern)).isEqualTo(AuthenticationResult.FAILED)
            assertThat(uiEventLoggerFake[0].eventId)
                .isEqualTo(BouncerUiEvent.BOUNCER_PASSWORD_FAILURE.id)

            // Too short input.
            val tooShortPattern =
                FakeAuthenticationRepository.PATTERN.subList(
                    0,
                    kosmos.fakeAuthenticationRepository.minPatternLength - 1,
                )
            assertThat(underTest.authenticate(tooShortPattern))
                .isEqualTo(AuthenticationResult.SKIPPED)

            // Correct input.
            assertThat(underTest.authenticate(FakeAuthenticationRepository.PATTERN))
                .isEqualTo(AuthenticationResult.SUCCEEDED)
            assertThat(uiEventLoggerFake[1].eventId)
                .isEqualTo(BouncerUiEvent.BOUNCER_PASSWORD_SUCCESS.id)
            assertThat(uiEventLoggerFake.numLogs()).isEqualTo(2)
        }

    @Test
    fun lockoutStarted() =
        testScope.runTest {
            val lockoutStartedEvents by collectValues(underTest.onLockoutStarted)

            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Pin
            )
            assertThat(lockoutStartedEvents).isEmpty()

            // Try the wrong PIN repeatedly, until lockout is triggered:
            repeat(FakeAuthenticationRepository.MAX_FAILED_AUTH_TRIES_BEFORE_LOCKOUT) { times ->
                // Wrong PIN.
                assertThat(underTest.authenticate(listOf(6, 7, 8, 9)))
                    .isEqualTo(AuthenticationResult.FAILED)
                if (times < FakeAuthenticationRepository.MAX_FAILED_AUTH_TRIES_BEFORE_LOCKOUT - 1) {
                    assertThat(lockoutStartedEvents).isEmpty()
                }
            }
            assertThat(authenticationInteractor.lockoutEndTimestamp).isNotNull()
            assertThat(lockoutStartedEvents.size).isEqualTo(1)

            // Advance the time to finish the lockout:
            advanceTimeBy(FakeAuthenticationRepository.LOCKOUT_DURATION_SECONDS.seconds)
            assertThat(authenticationInteractor.lockoutEndTimestamp).isNull()
            assertThat(lockoutStartedEvents.size).isEqualTo(1)

            // Trigger lockout again:
            repeat(FakeAuthenticationRepository.MAX_FAILED_AUTH_TRIES_BEFORE_LOCKOUT) {
                // Wrong PIN.
                underTest.authenticate(listOf(6, 7, 8, 9))
            }
            assertThat(lockoutStartedEvents.size).isEqualTo(2)
        }

    @Test
    fun imeHiddenEvent_isTriggered() =
        testScope.runTest {
            val imeHiddenEvent by collectLastValue(underTest.onImeHiddenByUser)
            runCurrent()

            underTest.onImeHiddenByUser()
            runCurrent()

            assertThat(imeHiddenEvent).isNotNull()
        }

    @Test
    fun intentionalUserInputEvent_registersTouchEvent() =
        testScope.runTest {
            assertThat(kosmos.fakePowerRepository.userTouchRegistered).isFalse()
            underTest.onIntentionalUserInput()
            assertThat(kosmos.fakePowerRepository.userTouchRegistered).isTrue()
        }

    @Test
    fun intentionalUserInputEvent_notifiesFaceAuthInteractor() =
        testScope.runTest {
            val isFaceAuthRunning by
                collectLastValue(kosmos.fakeDeviceEntryFaceAuthRepository.isAuthRunning)
            kosmos.deviceEntryFaceAuthInteractor.onDeviceLifted()
            runCurrent()
            assertThat(isFaceAuthRunning).isTrue()

            underTest.onIntentionalUserInput()
            runCurrent()

            assertThat(isFaceAuthRunning).isFalse()
        }

    @Test
    fun verifyOneHandedModeUsesTheConfigValue() =
        testScope.runTest {
            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Pin
            )
            testableResources.addOverride(R.bool.can_use_one_handed_bouncer, false)
            val oneHandedModelSupported by collectLastValue(underTest.isOneHandedModeSupported)

            assertThat(oneHandedModelSupported).isFalse()

            testableResources.addOverride(R.bool.can_use_one_handed_bouncer, true)
            kosmos.fakeConfigurationRepository.onAnyConfigurationChange()
            runCurrent()

            assertThat(oneHandedModelSupported).isTrue()

            testableResources.removeOverride(R.bool.can_use_one_handed_bouncer)
        }

    @Test
    fun verifyPreferredInputSideUsesTheSettingValue_Left() =
        testScope.runTest {
            val preferredInputSide by collectLastValue(underTest.preferredBouncerInputSide)
            kosmos.bouncerRepository.setPreferredBouncerInputSide(BouncerInputSide.LEFT)
            runCurrent()

            assertThat(preferredInputSide).isEqualTo(BouncerInputSide.LEFT)
        }

    @Test
    fun verifyPreferredInputSideUsesTheSettingValue_Right() =
        testScope.runTest {
            val preferredInputSide by collectLastValue(underTest.preferredBouncerInputSide)
            underTest.setPreferredBouncerInputSide(BouncerInputSide.RIGHT)
            runCurrent()

            assertThat(preferredInputSide).isEqualTo(BouncerInputSide.RIGHT)

            underTest.setPreferredBouncerInputSide(BouncerInputSide.LEFT)
            runCurrent()

            assertThat(preferredInputSide).isEqualTo(BouncerInputSide.LEFT)
        }

    @Test
    fun preferredInputSide_defaultsToRight_whenUserSwitcherIsEnabled() =
        testScope.runTest {
            testableResources.addOverride(R.bool.config_enableBouncerUserSwitcher, true)
            kosmos.fakeFeatureFlagsClassic.set(FULL_SCREEN_USER_SWITCHER, true)
            kosmos.bouncerRepository.preferredBouncerInputSide.value = null
            val preferredInputSide by collectLastValue(underTest.preferredBouncerInputSide)

            assertThat(preferredInputSide).isEqualTo(BouncerInputSide.RIGHT)
            testableResources.removeOverride(R.bool.config_enableBouncerUserSwitcher)
        }

    @Test
    fun preferredInputSide_defaultsToLeft_whenUserSwitcherIsNotEnabledAndOneHandedModeIsEnabled() =
        testScope.runTest {
            testableResources.addOverride(R.bool.config_enableBouncerUserSwitcher, false)
            kosmos.fakeFeatureFlagsClassic.set(FULL_SCREEN_USER_SWITCHER, true)
            testableResources.addOverride(R.bool.can_use_one_handed_bouncer, true)
            kosmos.fakeGlobalSettings.putInt(ONE_HANDED_KEYGUARD_SIDE, -1)
            val preferredInputSide by collectLastValue(underTest.preferredBouncerInputSide)

            assertThat(preferredInputSide).isEqualTo(BouncerInputSide.LEFT)
            testableResources.removeOverride(R.bool.config_enableBouncerUserSwitcher)
            testableResources.removeOverride(R.bool.can_use_one_handed_bouncer)
        }

    @Test
    fun bouncerExpansion_lockscreenToBouncer() =
        kosmos.runTest {
            val bouncerExpansion by collectLastValue(underTest.bouncerExpansion)

            val progress = MutableStateFlow(0f)
            kosmos.sceneContainerRepository.setTransitionState(transitionState)
            transitionState.value =
                ObservableTransitionState.Transition.showOverlay(
                    overlay = Overlays.Bouncer,
                    fromScene = Scenes.Lockscreen,
                    currentOverlays = flowOf(emptySet()),
                    progress = progress,
                    isInitiatedByUserInput = false,
                    isUserInputOngoing = flowOf(false),
                )

            assertThat(bouncerExpansion).isEqualTo(0f)

            progress.value = 1f
            assertThat(bouncerExpansion).isEqualTo(1f)
        }

    @Test
    fun bouncerExpansion_BouncerToLockscreen() =
        kosmos.runTest {
            val bouncerExpansion by collectLastValue(underTest.bouncerExpansion)

            val progress = MutableStateFlow(0f)
            kosmos.sceneContainerRepository.setTransitionState(transitionState)
            transitionState.value =
                ObservableTransitionState.Transition.hideOverlay(
                    overlay = Overlays.Bouncer,
                    toScene = Scenes.Lockscreen,
                    currentOverlays = flowOf(emptySet()),
                    progress = progress,
                    isInitiatedByUserInput = false,
                    isUserInputOngoing = flowOf(false),
                )

            assertThat(bouncerExpansion).isEqualTo(1f)

            progress.value = 1f
            assertThat(bouncerExpansion).isEqualTo(0f)
        }

    @Test
    fun bouncerExpansion_shadeToLockscreenUnderBouncer() =
        kosmos.runTest {
            val bouncerExpansion by collectLastValue(underTest.bouncerExpansion)

            val progress = MutableStateFlow(0f)
            kosmos.sceneContainerRepository.setTransitionState(transitionState)
            transitionState.value =
                ObservableTransitionState.Transition(
                    fromScene = Scenes.Shade,
                    toScene = Scenes.Lockscreen,
                    currentScene = flowOf(Scenes.Lockscreen),
                    progress = progress,
                    isInitiatedByUserInput = false,
                    isUserInputOngoing = flowOf(false),
                    currentOverlays = setOf(Overlays.Bouncer),
                )

            assertThat(bouncerExpansion).isEqualTo(1f)

            progress.value = 1f
            assertThat(bouncerExpansion).isEqualTo(1f)
        }

    companion object {
        private const val MESSAGE_ENTER_YOUR_PIN = "Enter your PIN"
        private const val MESSAGE_ENTER_YOUR_PASSWORD = "Enter your password"
        private const val MESSAGE_ENTER_YOUR_PATTERN = "Enter your pattern"
        private const val MESSAGE_WRONG_PIN = "Wrong PIN"
        private const val MESSAGE_WRONG_PASSWORD = "Wrong password"
        private const val MESSAGE_WRONG_PATTERN = "Wrong pattern"
    }
}
