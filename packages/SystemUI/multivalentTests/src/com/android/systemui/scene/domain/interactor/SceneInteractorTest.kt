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

package com.android.systemui.scene.domain.interactor

import android.app.StatusBarManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.compose.animation.scene.ObservableTransitionState
import com.android.compose.animation.scene.ObservableTransitionState.Transition.ShowOrHideOverlay
import com.android.compose.animation.scene.SceneKey
import com.android.systemui.SysuiTestCase
import com.android.systemui.coroutines.collectLastValue
import com.android.systemui.deviceentry.domain.interactor.deviceUnlockedInteractor
import com.android.systemui.flags.EnableSceneContainer
import com.android.systemui.keyguard.data.repository.fakeDeviceEntryFingerprintAuthRepository
import com.android.systemui.keyguard.domain.interactor.keyguardEnabledInteractor
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.SuccessFingerprintAuthenticationStatus
import com.android.systemui.kosmos.collectLastValue
import com.android.systemui.kosmos.runCurrent
import com.android.systemui.kosmos.runTest
import com.android.systemui.kosmos.testScope
import com.android.systemui.scene.data.repository.Idle
import com.android.systemui.scene.data.repository.Transition
import com.android.systemui.scene.data.repository.sceneContainerRepository
import com.android.systemui.scene.data.repository.setSceneTransition
import com.android.systemui.scene.domain.resolver.homeSceneFamilyResolver
import com.android.systemui.scene.overlayKeys
import com.android.systemui.scene.sceneContainerConfig
import com.android.systemui.scene.sceneKeys
import com.android.systemui.scene.shared.model.Overlays
import com.android.systemui.scene.shared.model.SceneFamilies
import com.android.systemui.scene.shared.model.Scenes
import com.android.systemui.scene.shared.model.fakeSceneDataSource
import com.android.systemui.shade.domain.interactor.disableDualShade
import com.android.systemui.shade.domain.interactor.enableDualShade
import com.android.systemui.statusbar.disableflags.data.repository.fakeDisableFlagsRepository
import com.android.systemui.statusbar.disableflags.shared.model.DisableFlagsModel
import com.android.systemui.testKosmos
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify

@SmallTest
@RunWith(AndroidJUnit4::class)
@EnableSceneContainer
class SceneInteractorTest : SysuiTestCase() {

    private val kosmos = testKosmos()
    private val testScope = kosmos.testScope
    private val fakeSceneDataSource by lazy { kosmos.fakeSceneDataSource }
    private val underTest by lazy { kosmos.sceneInteractor }

    @Before
    fun setUp() {
        // Init lazy Fixtures. Accessing them once makes sure that the singletons are initialized
        // and therefore starts to collect StateFlows eagerly (when there are any).
        kosmos.deviceUnlockedInteractor
        kosmos.keyguardEnabledInteractor
    }

    // TODO(b/356596436): Add tests for showing, hiding, and replacing overlays after we've defined
    //  them.
    @Test
    fun allContentKeys() {
        assertThat(underTest.allContentKeys).isEqualTo(kosmos.sceneKeys + kosmos.overlayKeys)
    }

    @Test
    fun changeScene_toUnknownScene_doesNothing() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            val unknownScene = SceneKey("UNKNOWN")
            val previousScene = currentScene
            assertThat(previousScene).isNotEqualTo(unknownScene)
            underTest.changeScene(unknownScene, "reason")
            assertThat(currentScene).isEqualTo(previousScene)
        }

    @Test
    fun changeScene() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)

            underTest.changeScene(Scenes.Shade, "reason")
            assertThat(currentScene).isEqualTo(Scenes.Shade)
        }

    @Test
    fun changeScene_toGoneWhenUnl_doesNotThrow() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)

            kosmos.fakeDeviceEntryFingerprintAuthRepository.setAuthenticationStatus(
                SuccessFingerprintAuthenticationStatus(0, true)
            )
            runCurrent()

            underTest.changeScene(Scenes.Gone, "reason")
            assertThat(currentScene).isEqualTo(Scenes.Gone)
        }

    @Test(expected = IllegalStateException::class)
    fun changeScene_toGoneWhenStillLocked_throws() =
        testScope.runTest { underTest.changeScene(Scenes.Gone, "reason") }

    @Test
    fun changeScene_toGoneWhenTransitionToLockedFromGone() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            val transitionTo by collectLastValue(underTest.transitioningTo)
            kosmos.sceneContainerRepository.setTransitionState(
                flowOf(
                    ObservableTransitionState.Transition(
                        fromScene = Scenes.Gone,
                        toScene = Scenes.Lockscreen,
                        currentScene = flowOf(Scenes.Lockscreen),
                        progress = flowOf(.5f),
                        isInitiatedByUserInput = true,
                        isUserInputOngoing = flowOf(false),
                    )
                )
            )
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)
            assertThat(transitionTo).isEqualTo(Scenes.Lockscreen)

            underTest.changeScene(Scenes.Gone, "simulate double tap power")
            assertThat(currentScene).isEqualTo(Scenes.Gone)
        }

    @Test
    fun changeScene_toHomeSceneFamily() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)

            underTest.changeScene(SceneFamilies.Home, "reason")
            runCurrent()

            assertThat(currentScene).isEqualTo(kosmos.homeSceneFamilyResolver.resolvedScene.value)
        }

    @Test
    fun snapToScene_toUnknownScene_doesNothing() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            val previousScene = currentScene
            val unknownScene = SceneKey("UNKNOWN")
            assertThat(previousScene).isNotEqualTo(unknownScene)
            underTest.snapToScene(unknownScene, "reason")
            assertThat(currentScene).isEqualTo(previousScene)
        }

    @Test
    fun snapToScene() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)

            underTest.snapToScene(Scenes.Shade, "reason")
            assertThat(currentScene).isEqualTo(Scenes.Shade)
        }

    @Test
    fun snapToScene_toGoneWhenUnl_doesNotThrow() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)

            kosmos.fakeDeviceEntryFingerprintAuthRepository.setAuthenticationStatus(
                SuccessFingerprintAuthenticationStatus(0, true)
            )
            runCurrent()

            underTest.snapToScene(Scenes.Gone, "reason")
            assertThat(currentScene).isEqualTo(Scenes.Gone)
        }

    @Test(expected = IllegalStateException::class)
    fun snapToScene_toGoneWhenStillLocked_throws() =
        testScope.runTest { underTest.snapToScene(Scenes.Gone, "reason") }

    @Test
    fun snapToScene_toHomeSceneFamily() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)

            underTest.snapToScene(SceneFamilies.Home, "reason")
            runCurrent()

            assertThat(currentScene).isEqualTo(kosmos.homeSceneFamilyResolver.resolvedScene.value)
        }

    @Test
    fun sceneChanged_inDataSource() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)

            fakeSceneDataSource.changeScene(Scenes.Shade)

            assertThat(currentScene).isEqualTo(Scenes.Shade)
        }

    @Test
    fun transitionState() =
        testScope.runTest {
            val sceneContainerRepository = kosmos.sceneContainerRepository
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Idle(Scenes.Lockscreen)
                )
            sceneContainerRepository.setTransitionState(transitionState)
            val reflectedTransitionState by
                collectLastValue(sceneContainerRepository.transitionState)
            assertThat(reflectedTransitionState).isEqualTo(transitionState.value)

            val progress = MutableStateFlow(1f)
            transitionState.value =
                ObservableTransitionState.Transition(
                    fromScene = Scenes.Lockscreen,
                    toScene = Scenes.Shade,
                    currentScene = flowOf(Scenes.Shade),
                    progress = progress,
                    isInitiatedByUserInput = false,
                    isUserInputOngoing = flowOf(false),
                )
            assertThat(reflectedTransitionState).isEqualTo(transitionState.value)

            progress.value = 0.1f
            assertThat(reflectedTransitionState).isEqualTo(transitionState.value)

            progress.value = 0.9f
            assertThat(reflectedTransitionState).isEqualTo(transitionState.value)

            sceneContainerRepository.setTransitionState(null)
            assertThat(reflectedTransitionState)
                .isEqualTo(
                    ObservableTransitionState.Idle(kosmos.sceneContainerConfig.initialSceneKey)
                )
        }

    @Test
    fun transitioningTo_sceneChange() =
        testScope.runTest {
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Idle(underTest.currentScene.value)
                )
            underTest.setTransitionState(transitionState)

            val transitionTo by collectLastValue(underTest.transitioningTo)
            assertThat(transitionTo).isNull()

            underTest.changeScene(Scenes.Shade, "reason")
            assertThat(transitionTo).isNull()

            val progress = MutableStateFlow(0f)
            transitionState.value =
                ObservableTransitionState.Transition(
                    fromScene = underTest.currentScene.value,
                    toScene = Scenes.Shade,
                    currentScene = flowOf(Scenes.Shade),
                    progress = progress,
                    isInitiatedByUserInput = false,
                    isUserInputOngoing = flowOf(false),
                )
            assertThat(transitionTo).isEqualTo(Scenes.Shade)

            progress.value = 0.5f
            assertThat(transitionTo).isEqualTo(Scenes.Shade)

            progress.value = 1f
            assertThat(transitionTo).isEqualTo(Scenes.Shade)

            transitionState.value = ObservableTransitionState.Idle(Scenes.Shade)
            assertThat(transitionTo).isNull()
        }

    @Test
    fun transitioningTo_overlayChange() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Idle(underTest.currentScene.value)
                )
            underTest.setTransitionState(transitionState)

            val transitionTo by collectLastValue(underTest.transitioningTo)
            assertThat(transitionTo).isNull()

            underTest.showOverlay(Overlays.NotificationsShade, "reason")
            assertThat(transitionTo).isNull()

            val progress = MutableStateFlow(0f)
            transitionState.value =
                ShowOrHideOverlay(
                    overlay = Overlays.NotificationsShade,
                    fromContent = underTest.currentScene.value,
                    toContent = Overlays.NotificationsShade,
                    currentScene = underTest.currentScene.value,
                    currentOverlays = underTest.currentOverlays,
                    progress = progress,
                    isInitiatedByUserInput = true,
                    isUserInputOngoing = flowOf(true),
                    previewProgress = flowOf(0f),
                    isInPreviewStage = flowOf(false),
                )
            assertThat(transitionTo).isEqualTo(Overlays.NotificationsShade)

            progress.value = 0.5f
            assertThat(transitionTo).isEqualTo(Overlays.NotificationsShade)

            progress.value = 1f
            assertThat(transitionTo).isEqualTo(Overlays.NotificationsShade)

            transitionState.value =
                ObservableTransitionState.Idle(
                    currentScene = underTest.currentScene.value,
                    currentOverlays = setOf(Overlays.NotificationsShade),
                )
            assertThat(transitionTo).isNull()
        }

    @Test
    fun isTransitionUserInputOngoing_idle_false() =
        testScope.runTest {
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Idle(Scenes.Shade)
                )
            val isTransitionUserInputOngoing by
                collectLastValue(underTest.isTransitionUserInputOngoing)
            underTest.setTransitionState(transitionState)

            assertThat(isTransitionUserInputOngoing).isFalse()
        }

    @Test
    fun isTransitionUserInputOngoing_transition_true() =
        testScope.runTest {
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Transition(
                        fromScene = Scenes.Shade,
                        toScene = Scenes.Lockscreen,
                        currentScene = flowOf(Scenes.Shade),
                        progress = flowOf(0.5f),
                        isInitiatedByUserInput = true,
                        isUserInputOngoing = flowOf(true),
                    )
                )
            val isTransitionUserInputOngoing by
                collectLastValue(underTest.isTransitionUserInputOngoing)
            underTest.setTransitionState(transitionState)

            assertThat(isTransitionUserInputOngoing).isTrue()
        }

    @Test
    fun isTransitionUserInputOngoing_updateMidTransition_false() =
        testScope.runTest {
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Transition(
                        fromScene = Scenes.Shade,
                        toScene = Scenes.Lockscreen,
                        currentScene = flowOf(Scenes.Shade),
                        progress = flowOf(0.5f),
                        isInitiatedByUserInput = true,
                        isUserInputOngoing = flowOf(true),
                    )
                )
            val isTransitionUserInputOngoing by
                collectLastValue(underTest.isTransitionUserInputOngoing)
            underTest.setTransitionState(transitionState)

            assertThat(isTransitionUserInputOngoing).isTrue()

            transitionState.value =
                ObservableTransitionState.Transition(
                    fromScene = Scenes.Shade,
                    toScene = Scenes.Lockscreen,
                    currentScene = flowOf(Scenes.Lockscreen),
                    progress = flowOf(0.6f),
                    isInitiatedByUserInput = true,
                    isUserInputOngoing = flowOf(false),
                )

            assertThat(isTransitionUserInputOngoing).isFalse()
        }

    @Test
    fun isTransitionUserInputOngoing_updateOnIdle_false() =
        testScope.runTest {
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Transition(
                        fromScene = Scenes.Shade,
                        toScene = Scenes.Lockscreen,
                        currentScene = flowOf(Scenes.Shade),
                        progress = flowOf(0.5f),
                        isInitiatedByUserInput = true,
                        isUserInputOngoing = flowOf(true),
                    )
                )
            val isTransitionUserInputOngoing by
                collectLastValue(underTest.isTransitionUserInputOngoing)
            underTest.setTransitionState(transitionState)

            assertThat(isTransitionUserInputOngoing).isTrue()

            transitionState.value = ObservableTransitionState.Idle(currentScene = Scenes.Lockscreen)

            assertThat(isTransitionUserInputOngoing).isFalse()
        }

    @Test
    fun isVisible() =
        testScope.runTest {
            val isVisible by collectLastValue(underTest.isVisible)
            assertThat(isVisible).isTrue()

            underTest.setVisible(false, "reason")
            assertThat(isVisible).isFalse()

            underTest.setVisible(true, "reason")
            assertThat(isVisible).isTrue()
        }

    @Test
    fun isVisible_duringRemoteUserInteraction_forcedVisible() =
        testScope.runTest {
            underTest.setVisible(false, "reason")
            val isVisible by collectLastValue(underTest.isVisible)
            assertThat(isVisible).isFalse()
            underTest.onRemoteUserInputStarted("reason")
            assertThat(isVisible).isTrue()

            underTest.onUserInputFinished()

            assertThat(isVisible).isFalse()
        }

    @Test
    fun resolveSceneFamily_home() =
        testScope.runTest {
            assertThat(underTest.resolveSceneFamily(SceneFamilies.Home).first())
                .isEqualTo(kosmos.homeSceneFamilyResolver.resolvedScene.value)
        }

    @Test
    fun resolveSceneFamily_nonFamily() =
        testScope.runTest {
            val resolved = underTest.resolveSceneFamily(Scenes.Gone).toList()
            assertThat(resolved).containsExactly(Scenes.Gone).inOrder()
        }

    @Test
    fun transitionValue_test_idle() =
        testScope.runTest {
            val transitionValue by collectLastValue(underTest.transitionProgress(Scenes.Gone))

            kosmos.setSceneTransition(Idle(Scenes.Gone))
            assertThat(transitionValue).isEqualTo(1f)

            kosmos.setSceneTransition(Idle(Scenes.Lockscreen))
            assertThat(transitionValue).isEqualTo(0f)
        }

    @Test
    fun transitionValue_test_transitions() =
        testScope.runTest {
            val transitionValue by collectLastValue(underTest.transitionProgress(Scenes.Gone))
            val progress = MutableStateFlow(0f)

            kosmos.setSceneTransition(
                Transition(from = Scenes.Lockscreen, to = Scenes.Gone, progress = progress)
            )
            assertThat(transitionValue).isEqualTo(0f)

            progress.value = 0.4f
            assertThat(transitionValue).isEqualTo(0.4f)

            kosmos.setSceneTransition(
                Transition(from = Scenes.Gone, to = Scenes.Lockscreen, progress = progress)
            )
            progress.value = 0.7f
            assertThat(transitionValue).isEqualTo(0.3f)

            kosmos.setSceneTransition(
                Transition(from = Scenes.Lockscreen, to = Scenes.Shade, progress = progress)
            )
            progress.value = 0.9f
            assertThat(transitionValue).isEqualTo(0f)
        }

    @Test
    fun changeScene_toGone_whenKeyguardDisabled_doesNotThrow() =
        testScope.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)
            kosmos.keyguardEnabledInteractor.notifyKeyguardEnabled(false)

            underTest.changeScene(Scenes.Gone, "")

            assertThat(currentScene).isEqualTo(Scenes.Gone)
        }

    @Test
    fun showOverlay_overlayDisabled_doesNothing() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            val currentOverlays by collectLastValue(underTest.currentOverlays)
            val disabledOverlay = Overlays.QuickSettingsShade
            fakeDisableFlagsRepository.disableFlags.value =
                DisableFlagsModel(disable2 = StatusBarManager.DISABLE2_QUICK_SETTINGS)
            assertThat(disabledContentInteractor.isDisabled(disabledOverlay)).isTrue()
            assertThat(currentOverlays).doesNotContain(disabledOverlay)

            underTest.showOverlay(disabledOverlay, "reason")

            assertThat(currentOverlays).doesNotContain(disabledOverlay)
        }

    @Test
    fun replaceOverlay_withDisabledOverlay_doesNothing() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            val currentOverlays by collectLastValue(underTest.currentOverlays)
            val showingOverlay = Overlays.NotificationsShade
            underTest.showOverlay(showingOverlay, "reason")
            assertThat(currentOverlays).isEqualTo(setOf(showingOverlay))
            val disabledOverlay = Overlays.QuickSettingsShade
            fakeDisableFlagsRepository.disableFlags.value =
                DisableFlagsModel(disable2 = StatusBarManager.DISABLE2_QUICK_SETTINGS)
            assertThat(disabledContentInteractor.isDisabled(disabledOverlay)).isTrue()

            underTest.replaceOverlay(showingOverlay, disabledOverlay, "reason")

            assertThat(currentOverlays).isEqualTo(setOf(showingOverlay))
        }

    @Test
    fun changeScene_toDisabledScene_doesNothing() =
        kosmos.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            val disabledScene = Scenes.Shade
            fakeDisableFlagsRepository.disableFlags.value =
                DisableFlagsModel(disable2 = StatusBarManager.DISABLE2_NOTIFICATION_SHADE)
            assertThat(disabledContentInteractor.isDisabled(disabledScene)).isTrue()
            assertThat(currentScene).isNotEqualTo(disabledScene)

            underTest.changeScene(disabledScene, "reason")

            assertThat(currentScene).isNotEqualTo(disabledScene)
        }

    @Test
    fun transitionAnimations() =
        kosmos.runTest {
            val isVisible by collectLastValue(underTest.isVisible)
            assertThat(isVisible).isTrue()

            underTest.setVisible(false, "test")
            assertThat(isVisible).isFalse()

            underTest.onTransitionAnimationStart()
            // One animation is active, forced visible.
            assertThat(isVisible).isTrue()

            underTest.onTransitionAnimationEnd()
            // No more active animations, not forced visible.
            assertThat(isVisible).isFalse()

            underTest.onTransitionAnimationStart()
            // One animation is active, forced visible.
            assertThat(isVisible).isTrue()

            underTest.onTransitionAnimationCancelled()
            // No more active animations, not forced visible.
            assertThat(isVisible).isFalse()

            underTest.setVisible(true, "test")
            assertThat(isVisible).isTrue()

            underTest.onTransitionAnimationStart()
            underTest.onTransitionAnimationStart()
            // Two animations are active, forced visible.
            assertThat(isVisible).isTrue()

            underTest.setVisible(false, "test")
            // Two animations are active, forced visible.
            assertThat(isVisible).isTrue()

            underTest.onTransitionAnimationEnd()
            // One animation is still active, forced visible.
            assertThat(isVisible).isTrue()

            underTest.onTransitionAnimationEnd()
            // No more active animations, not forced visible.
            assertThat(isVisible).isFalse()
        }

    @Test(expected = IllegalStateException::class)
    fun changeScene_toIncorrectShade_crashes() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            underTest.changeScene(Scenes.Shade, "reason")
        }

    @Test(expected = IllegalStateException::class)
    fun changeScene_toIncorrectQuickSettings_crashes() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            underTest.changeScene(Scenes.QuickSettings, "reason")
        }

    @Test(expected = IllegalStateException::class)
    fun snapToScene_toIncorrectShade_crashes() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            underTest.snapToScene(Scenes.Shade, "reason")
        }

    @Test(expected = IllegalStateException::class)
    fun snapToScene_toIncorrectQuickSettings_crashes() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            underTest.changeScene(Scenes.QuickSettings, "reason")
        }

    @Test(expected = IllegalStateException::class)
    fun showOverlay_incorrectShadeOverlay_crashes() =
        kosmos.runTest {
            disableDualShade()
            runCurrent()
            underTest.showOverlay(Overlays.NotificationsShade, "reason")
        }

    @Test(expected = IllegalStateException::class)
    fun showOverlay_incorrectQuickSettingsOverlay_crashes() =
        kosmos.runTest {
            disableDualShade()
            runCurrent()
            underTest.showOverlay(Overlays.QuickSettingsShade, "reason")
        }

    @Test
    fun instantlyShowOverlay() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            val currentScene by collectLastValue(underTest.currentScene)
            val currentOverlays by collectLastValue(underTest.currentOverlays)
            val originalScene = currentScene
            assertThat(currentOverlays).isEmpty()

            val overlay = Overlays.NotificationsShade
            underTest.instantlyShowOverlay(overlay, "reason")
            runCurrent()

            assertThat(currentScene).isEqualTo(originalScene)
            assertThat(currentOverlays).contains(overlay)
        }

    @Test
    fun instantlyHideOverlay() =
        kosmos.runTest {
            enableDualShade()
            runCurrent()
            val currentScene by collectLastValue(underTest.currentScene)
            val currentOverlays by collectLastValue(underTest.currentOverlays)
            val overlay = Overlays.QuickSettingsShade
            underTest.showOverlay(overlay, "reason")
            runCurrent()
            val originalScene = currentScene
            assertThat(currentOverlays).contains(overlay)

            underTest.instantlyHideOverlay(overlay, "reason")
            runCurrent()

            assertThat(currentScene).isEqualTo(originalScene)
            assertThat(currentOverlays).isEmpty()
        }

    @Test
    fun changeScene_notifiesAboutToChangeListener() =
        kosmos.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            // Unlock so transitioning to the Gone scene becomes possible.
            kosmos.fakeDeviceEntryFingerprintAuthRepository.setAuthenticationStatus(
                SuccessFingerprintAuthenticationStatus(0, true)
            )
            runCurrent()
            underTest.changeScene(toScene = Scenes.Gone, loggingReason = "")
            runCurrent()
            assertThat(currentScene).isEqualTo(Scenes.Gone)

            val processor = mock<SceneInteractor.OnSceneAboutToChangeListener>()
            underTest.registerSceneStateProcessor(processor)

            underTest.changeScene(
                toScene = Scenes.Lockscreen,
                sceneState = KeyguardState.AOD,
                loggingReason = "",
            )
            runCurrent()
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)

            verify(processor).onSceneAboutToChange(Scenes.Lockscreen, KeyguardState.AOD)
        }

    @Test
    fun changeScene_noOp_whenFromAndToAreTheSame() =
        kosmos.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            val processor = mock<SceneInteractor.OnSceneAboutToChangeListener>()
            underTest.registerSceneStateProcessor(processor)

            underTest.changeScene(toScene = checkNotNull(currentScene), loggingReason = "")

            verify(processor, never()).onSceneAboutToChange(any(), any())
        }

    @Test
    fun changeScene_sameScene_withFreeze() =
        kosmos.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)
            val processor = mock<SceneInteractor.OnSceneAboutToChangeListener>()
            underTest.registerSceneStateProcessor(processor)
            verify(processor, never()).onSceneAboutToChange(any(), any())
            assertThat(fakeSceneDataSource.freezeAndAnimateToCurrentStateCallCount).isEqualTo(0)

            underTest.changeScene(
                toScene = Scenes.Lockscreen,
                loggingReason = "test",
                sceneState = KeyguardState.AOD,
                forceSettleToTargetScene = true,
            )

            verify(processor).onSceneAboutToChange(Scenes.Lockscreen, KeyguardState.AOD)
            assertThat(fakeSceneDataSource.freezeAndAnimateToCurrentStateCallCount).isEqualTo(1)
        }

    @Test
    fun changeScene_sameScene_withoutFreeze() =
        kosmos.runTest {
            val currentScene by collectLastValue(underTest.currentScene)
            assertThat(currentScene).isEqualTo(Scenes.Lockscreen)
            val processor = mock<SceneInteractor.OnSceneAboutToChangeListener>()
            underTest.registerSceneStateProcessor(processor)
            verify(processor, never()).onSceneAboutToChange(any(), any())
            assertThat(fakeSceneDataSource.freezeAndAnimateToCurrentStateCallCount).isEqualTo(0)

            underTest.changeScene(
                toScene = Scenes.Lockscreen,
                loggingReason = "test",
                sceneState = KeyguardState.AOD,
                forceSettleToTargetScene = false,
            )

            verify(processor, never()).onSceneAboutToChange(any(), any())
            assertThat(fakeSceneDataSource.freezeAndAnimateToCurrentStateCallCount).isEqualTo(0)
        }

    @Test
    fun topmostContent_sceneChange_noOverlays() =
        kosmos.runTest {
            val topmostContent by collectLastValue(underTest.topmostContent)

            kosmos.fakeDeviceEntryFingerprintAuthRepository.setAuthenticationStatus(
                SuccessFingerprintAuthenticationStatus(0, true)
            )

            underTest.snapToScene(Scenes.Lockscreen, "reason")

            assertThat(topmostContent).isEqualTo(Scenes.Lockscreen)

            underTest.changeScene(Scenes.Gone, "reason")

            assertThat(topmostContent).isEqualTo(Scenes.Gone)
        }

    @Test
    fun topmostContent_sceneChange_withOverlay() =
        kosmos.runTest {
            kosmos.enableDualShade()
            runCurrent()

            val topmostContent by collectLastValue(underTest.topmostContent)

            kosmos.fakeDeviceEntryFingerprintAuthRepository.setAuthenticationStatus(
                SuccessFingerprintAuthenticationStatus(0, true)
            )

            underTest.snapToScene(Scenes.Lockscreen, "reason")
            underTest.showOverlay(Overlays.NotificationsShade, "reason")

            assertThat(topmostContent).isEqualTo(Overlays.NotificationsShade)

            underTest.changeScene(Scenes.Gone, "reason")

            assertThat(topmostContent).isEqualTo(Overlays.NotificationsShade)
        }

    @Test
    fun topmostContent_overlayChange_higherZOrder() =
        kosmos.runTest {
            kosmos.enableDualShade()
            runCurrent()

            val topmostContent by collectLastValue(underTest.topmostContent)

            kosmos.fakeDeviceEntryFingerprintAuthRepository.setAuthenticationStatus(
                SuccessFingerprintAuthenticationStatus(0, true)
            )

            underTest.snapToScene(Scenes.Lockscreen, "reason")
            underTest.showOverlay(Overlays.NotificationsShade, "reason")

            assertThat(topmostContent).isEqualTo(Overlays.NotificationsShade)

            underTest.showOverlay(Overlays.QuickSettingsShade, "reason")

            assertThat(topmostContent).isEqualTo(Overlays.QuickSettingsShade)
        }

    @Test
    fun topmostContent_overlayChange_lowerZOrder() =
        kosmos.runTest {
            kosmos.enableDualShade()
            runCurrent()

            val topmostContent by collectLastValue(underTest.topmostContent)

            kosmos.fakeDeviceEntryFingerprintAuthRepository.setAuthenticationStatus(
                SuccessFingerprintAuthenticationStatus(0, true)
            )

            underTest.snapToScene(Scenes.Lockscreen, "reason")
            underTest.showOverlay(Overlays.QuickSettingsShade, "reason")

            assertThat(topmostContent).isEqualTo(Overlays.QuickSettingsShade)

            underTest.showOverlay(Overlays.NotificationsShade, "reason")

            assertThat(topmostContent).isEqualTo(Overlays.QuickSettingsShade)
        }
}
