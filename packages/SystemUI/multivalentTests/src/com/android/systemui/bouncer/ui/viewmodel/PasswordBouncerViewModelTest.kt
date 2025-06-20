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

package com.android.systemui.bouncer.ui.viewmodel

import android.content.pm.UserInfo
import android.platform.test.annotations.EnableFlags
import android.view.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.authentication.data.repository.fakeAuthenticationRepository
import com.android.systemui.authentication.domain.interactor.authenticationInteractor
import com.android.systemui.authentication.shared.model.AuthenticationMethodModel
import com.android.systemui.bouncer.domain.interactor.bouncerInteractor
import com.android.systemui.coroutines.collectLastValue
import com.android.systemui.coroutines.collectValues
import com.android.systemui.flags.EnableSceneContainer
import com.android.systemui.inputmethod.data.model.InputMethodModel
import com.android.systemui.inputmethod.data.repository.fakeInputMethodRepository
import com.android.systemui.inputmethod.domain.interactor.inputMethodInteractor
import com.android.systemui.kosmos.testScope
import com.android.systemui.lifecycle.activateIn
import com.android.systemui.res.R
import com.android.systemui.scene.domain.interactor.sceneInteractor
import com.android.systemui.scene.shared.model.Overlays
import com.android.systemui.testKosmos
import com.android.systemui.user.data.model.SelectedUserModel
import com.android.systemui.user.data.model.SelectionStatus
import com.android.systemui.user.data.repository.fakeUserRepository
import com.android.systemui.user.domain.interactor.selectedUserInteractor
import com.google.common.truth.Truth.assertThat
import java.util.UUID
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@SmallTest
@RunWith(AndroidJUnit4::class)
class PasswordBouncerViewModelTest : SysuiTestCase() {

    private val kosmos = testKosmos()
    private val testScope = kosmos.testScope
    private val authenticationInteractor by lazy { kosmos.authenticationInteractor }
    private val sceneInteractor by lazy { kosmos.sceneInteractor }
    private val bouncerInteractor by lazy { kosmos.bouncerInteractor }
    private val selectedUserInteractor by lazy { kosmos.selectedUserInteractor }
    private val inputMethodInteractor by lazy { kosmos.inputMethodInteractor }
    private val isInputEnabled = MutableStateFlow(true)

    private val underTest by lazy {
        kosmos.passwordBouncerViewModelFactory.create(
            isInputEnabled = isInputEnabled,
            onIntentionalUserInput = {},
        )
    }

    @Before
    fun setUp() {
        overrideResource(R.string.keyguard_enter_your_password, ENTER_YOUR_PASSWORD)
        overrideResource(R.string.kg_wrong_password, WRONG_PASSWORD)
        underTest.activateIn(testScope)
    }

    @Test
    fun onShown() =
        testScope.runTest {
            val currentOverlays by collectLastValue(sceneInteractor.currentOverlays)
            val password by collectLastValue(underTest.password)
            lockDeviceAndOpenPasswordBouncer()

            assertThat(password).isEmpty()
            assertThat(currentOverlays).contains(Overlays.Bouncer)
            assertThat(underTest.authenticationMethod).isEqualTo(AuthenticationMethodModel.Password)
        }

    @Test
    fun onHidden_resetsPasswordInputAndMessage() =
        testScope.runTest {
            val password by collectLastValue(underTest.password)
            lockDeviceAndOpenPasswordBouncer()

            underTest.onPasswordInputChanged("password")
            assertThat(password).isNotEmpty()

            underTest.onHidden()
            assertThat(password).isEmpty()
        }

    @Test
    fun onPasswordInputChanged() =
        testScope.runTest {
            val currentOverlays by collectLastValue(sceneInteractor.currentOverlays)
            val password by collectLastValue(underTest.password)
            lockDeviceAndOpenPasswordBouncer()

            underTest.onPasswordInputChanged("password")

            assertThat(password).isEqualTo("password")
            assertThat(currentOverlays).contains(Overlays.Bouncer)
        }

    @Test
    fun onAuthenticateKeyPressed_whenCorrect() =
        testScope.runTest {
            val authResult by collectLastValue(authenticationInteractor.onAuthenticationResult)
            lockDeviceAndOpenPasswordBouncer()

            underTest.onPasswordInputChanged("password")
            underTest.onAuthenticateKeyPressed()

            assertThat(authResult).isTrue()
        }

    @Test
    fun onAuthenticateKeyPressed_whenWrong() =
        testScope.runTest {
            val password by collectLastValue(underTest.password)
            lockDeviceAndOpenPasswordBouncer()

            underTest.onPasswordInputChanged("wrong")
            underTest.onAuthenticateKeyPressed()

            assertThat(password).isEmpty()
        }

    @Test
    fun onAuthenticateKeyPressed_whenEmpty() =
        testScope.runTest {
            val password by collectLastValue(underTest.password)
            kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
                AuthenticationMethodModel.Password
            )
            showBouncer()

            // No input entered.

            underTest.onAuthenticateKeyPressed()

            assertThat(password).isEmpty()
        }

    @Test
    fun onAuthenticateKeyPressed_correctAfterWrong() =
        testScope.runTest {
            val authResult by collectLastValue(authenticationInteractor.onAuthenticationResult)
            val password by collectLastValue(underTest.password)
            lockDeviceAndOpenPasswordBouncer()

            // Enter the wrong password:
            underTest.onPasswordInputChanged("wrong")
            underTest.onAuthenticateKeyPressed()
            assertThat(password).isEqualTo("")
            assertThat(authResult).isFalse()

            // Enter the correct password:
            underTest.onPasswordInputChanged("password")

            underTest.onAuthenticateKeyPressed()

            assertThat(authResult).isTrue()
        }

    @Test
    fun onShown_againAfterSceneChange_resetsPassword() =
        testScope.runTest {
            val currentOverlays by collectLastValue(sceneInteractor.currentOverlays)
            val password by collectLastValue(underTest.password)
            lockDeviceAndOpenPasswordBouncer()

            // The user types a password.
            underTest.onPasswordInputChanged("password")
            assertThat(password).isEqualTo("password")

            // The user doesn't confirm the password, but navigates back to the lockscreen instead.
            hideBouncer()

            // The user navigates to the bouncer again.
            showBouncer()

            // Ensure the previously-entered password is not shown.
            assertThat(password).isEmpty()
            assertThat(currentOverlays).contains(Overlays.Bouncer)
        }

    @Test
    fun onImeDismissed() =
        testScope.runTest {
            val events by collectValues(bouncerInteractor.onImeHiddenByUser)
            assertThat(events).isEmpty()

            underTest.onImeDismissed()
            assertThat(events).hasSize(1)
        }

    @Test
    fun isTextFieldFocusRequested_initiallyTrue() =
        testScope.runTest {
            val isTextFieldFocusRequested by collectLastValue(underTest.isTextFieldFocusRequested)
            assertThat(isTextFieldFocusRequested).isTrue()
        }

    @Test
    fun isTextFieldFocusRequested_focusGained_becomesFalse() =
        testScope.runTest {
            val isTextFieldFocusRequested by collectLastValue(underTest.isTextFieldFocusRequested)

            underTest.onTextFieldFocusChanged(isFocused = true)

            assertThat(isTextFieldFocusRequested).isFalse()
        }

    @Test
    fun isTextFieldFocusRequested_focusLost_becomesTrue() =
        testScope.runTest {
            val isTextFieldFocusRequested by collectLastValue(underTest.isTextFieldFocusRequested)
            underTest.onTextFieldFocusChanged(isFocused = true)

            underTest.onTextFieldFocusChanged(isFocused = false)

            assertThat(isTextFieldFocusRequested).isTrue()
        }

    @Test
    fun isTextFieldFocusRequested_focusLostWhileLockedOut_staysFalse() =
        testScope.runTest {
            val isTextFieldFocusRequested by collectLastValue(underTest.isTextFieldFocusRequested)
            underTest.onTextFieldFocusChanged(isFocused = true)
            setLockout(true)

            underTest.onTextFieldFocusChanged(isFocused = false)

            assertThat(isTextFieldFocusRequested).isFalse()
        }

    @Test
    fun isTextFieldFocusRequested_lockoutCountdownEnds_becomesTrue() =
        testScope.runTest {
            val isTextFieldFocusRequested by collectLastValue(underTest.isTextFieldFocusRequested)
            underTest.onTextFieldFocusChanged(isFocused = true)
            setLockout(true)
            underTest.onTextFieldFocusChanged(isFocused = false)

            setLockout(false)

            assertThat(isTextFieldFocusRequested).isTrue()
        }

    @Test
    fun isImeSwitcherButtonVisible() =
        testScope.runTest {
            val selectedUserId by collectLastValue(selectedUserInteractor.selectedUser)
            selectUser(USER_INFOS.first())

            enableInputMethodsForUser(checkNotNull(selectedUserId))

            // Assert initial value, before the UI subscribes.
            assertThat(underTest.isImeSwitcherButtonVisible.value).isFalse()

            // Subscription starts; verify a fresh value is fetched.
            val isImeSwitcherButtonVisible by collectLastValue(underTest.isImeSwitcherButtonVisible)
            assertThat(isImeSwitcherButtonVisible).isTrue()

            // Change the user, verify a fresh value is fetched.
            selectUser(USER_INFOS.last())

            assertThat(
                    inputMethodInteractor.hasMultipleEnabledImesOrSubtypes(
                        checkNotNull(selectedUserId)
                    )
                )
                .isFalse()
            assertThat(isImeSwitcherButtonVisible).isFalse()

            // Enable IMEs and add another subscriber; verify a fresh value is fetched.
            enableInputMethodsForUser(checkNotNull(selectedUserId))
            val collector2 by collectLastValue(underTest.isImeSwitcherButtonVisible)
            assertThat(collector2).isTrue()
        }

    @Test
    fun onImeSwitcherButtonClicked() =
        testScope.runTest {
            val displayId = 7
            assertThat(kosmos.fakeInputMethodRepository.inputMethodPickerShownDisplayId)
                .isNotEqualTo(displayId)

            underTest.onImeSwitcherButtonClicked(displayId)
            runCurrent()

            assertThat(kosmos.fakeInputMethodRepository.inputMethodPickerShownDisplayId)
                .isEqualTo(displayId)
        }

    @Test
    fun afterSuccessfulAuthentication_focusIsNotRequested() =
        testScope.runTest {
            val authResult by collectLastValue(authenticationInteractor.onAuthenticationResult)
            val textInputFocusRequested by collectLastValue(underTest.isTextFieldFocusRequested)
            lockDeviceAndOpenPasswordBouncer()

            // remove focus from text field
            underTest.onTextFieldFocusChanged(false)
            runCurrent()

            // focus should be requested
            assertThat(textInputFocusRequested).isTrue()

            // simulate text field getting focus
            underTest.onTextFieldFocusChanged(true)
            runCurrent()

            // focus should not be requested anymore
            assertThat(textInputFocusRequested).isFalse()

            // authenticate successfully.
            underTest.onPasswordInputChanged("password")
            underTest.onAuthenticateKeyPressed()
            runCurrent()

            assertThat(authResult).isTrue()

            // remove focus from text field
            underTest.onTextFieldFocusChanged(false)
            runCurrent()
            // focus should not be requested again
            assertThat(textInputFocusRequested).isFalse()
        }

    @EnableFlags(com.android.systemui.Flags.FLAG_COMPOSE_BOUNCER)
    @Test
    fun consumeConfirmKeyEvents_toPreventItFromPropagating() =
        testScope.runTest { verifyConfirmKeyEventsBehavior(keyUpEventConsumed = true) }

    @EnableFlags(com.android.systemui.Flags.FLAG_COMPOSE_BOUNCER)
    @EnableSceneContainer
    @Test
    fun noops_whenSceneContainerIsAlsoEnabled() =
        testScope.runTest { verifyConfirmKeyEventsBehavior(keyUpEventConsumed = false) }

    private fun verifyConfirmKeyEventsBehavior(keyUpEventConsumed: Boolean) {
        assertThat(underTest.onKeyEvent(KeyEventType.KeyDown, KeyEvent.KEYCODE_DPAD_CENTER))
            .isFalse()
        assertThat(underTest.onKeyEvent(KeyEventType.KeyUp, KeyEvent.KEYCODE_DPAD_CENTER))
            .isEqualTo(keyUpEventConsumed)

        assertThat(underTest.onKeyEvent(KeyEventType.KeyDown, KeyEvent.KEYCODE_ENTER)).isFalse()
        assertThat(underTest.onKeyEvent(KeyEventType.KeyUp, KeyEvent.KEYCODE_ENTER))
            .isEqualTo(keyUpEventConsumed)

        assertThat(underTest.onKeyEvent(KeyEventType.KeyDown, KeyEvent.KEYCODE_NUMPAD_ENTER))
            .isFalse()
        assertThat(underTest.onKeyEvent(KeyEventType.KeyUp, KeyEvent.KEYCODE_NUMPAD_ENTER))
            .isEqualTo(keyUpEventConsumed)

        // space is ignored.
        assertThat(underTest.onKeyEvent(KeyEventType.KeyUp, KeyEvent.KEYCODE_SPACE)).isFalse()
        assertThat(underTest.onKeyEvent(KeyEventType.KeyDown, KeyEvent.KEYCODE_SPACE)).isFalse()
    }

    private fun TestScope.showBouncer() {
        val currentOverlays by collectLastValue(sceneInteractor.currentOverlays)
        sceneInteractor.showOverlay(Overlays.Bouncer, "reason")
        runCurrent()

        assertThat(currentOverlays).contains(Overlays.Bouncer)
    }

    private fun TestScope.hideBouncer() {
        val currentOverlays by collectLastValue(sceneInteractor.currentOverlays)
        sceneInteractor.hideOverlay(Overlays.Bouncer, "reason")
        underTest.onHidden()
        runCurrent()

        assertThat(currentOverlays).doesNotContain(Overlays.Bouncer)
    }

    private fun TestScope.lockDeviceAndOpenPasswordBouncer() {
        kosmos.fakeAuthenticationRepository.setAuthenticationMethod(
            AuthenticationMethodModel.Password
        )
        showBouncer()
    }

    private suspend fun TestScope.setLockout(isLockedOut: Boolean, failedAttemptCount: Int = 5) {
        if (isLockedOut) {
            repeat(failedAttemptCount) {
                kosmos.fakeAuthenticationRepository.reportAuthenticationAttempt(false)
            }
            kosmos.fakeAuthenticationRepository.reportLockoutStarted(
                30.seconds.inWholeMilliseconds.toInt()
            )
        } else {
            kosmos.fakeAuthenticationRepository.reportAuthenticationAttempt(true)
        }
        isInputEnabled.value = !isLockedOut

        runCurrent()
    }

    private fun TestScope.selectUser(userInfo: UserInfo) {
        kosmos.fakeUserRepository.selectedUser.value =
            SelectedUserModel(
                userInfo = userInfo,
                selectionStatus = SelectionStatus.SELECTION_COMPLETE,
            )
        advanceTimeBy(PasswordBouncerViewModel.DELAY_TO_FETCH_IMES)
    }

    private suspend fun enableInputMethodsForUser(userId: Int) {
        kosmos.fakeInputMethodRepository.setEnabledInputMethods(
            userId,
            createInputMethodWithSubtypes(auxiliarySubtypes = 0, nonAuxiliarySubtypes = 0),
            createInputMethodWithSubtypes(auxiliarySubtypes = 0, nonAuxiliarySubtypes = 1),
        )
        assertThat(inputMethodInteractor.hasMultipleEnabledImesOrSubtypes(userId)).isTrue()
    }

    private fun createInputMethodWithSubtypes(
        auxiliarySubtypes: Int,
        nonAuxiliarySubtypes: Int,
    ): InputMethodModel {
        return InputMethodModel(
            userId = UUID.randomUUID().mostSignificantBits.toInt(),
            imeId = UUID.randomUUID().toString(),
            subtypes =
                List(auxiliarySubtypes + nonAuxiliarySubtypes) {
                    InputMethodModel.Subtype(subtypeId = it, isAuxiliary = it < auxiliarySubtypes)
                },
        )
    }

    companion object {
        private const val ENTER_YOUR_PASSWORD = "Enter your password"
        private const val WRONG_PASSWORD = "Wrong password"

        private val USER_INFOS =
            listOf(UserInfo(100, "First user", 0), UserInfo(101, "Second user", 0))
    }
}
