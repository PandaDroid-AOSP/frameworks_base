/*
 * Copyright (C) 2022 The Android Open Source Project
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

import android.app.StatusBarManager.CAMERA_LAUNCH_SOURCE_POWER_DOUBLE_TAP
import android.platform.test.annotations.DisableFlags
import android.platform.test.annotations.EnableFlags
import android.platform.test.flag.junit.FlagsParameterization
import androidx.test.filters.SmallTest
import com.android.compose.animation.scene.ObservableTransitionState
import com.android.keyguard.KeyguardSecurityModel
import com.android.keyguard.KeyguardSecurityModel.SecurityMode.PIN
import com.android.systemui.Flags
import com.android.systemui.Flags.FLAG_COMMUNAL_HUB
import com.android.systemui.Flags.FLAG_GLANCEABLE_HUB_V2
import com.android.systemui.Flags.glanceableHubV2
import com.android.systemui.SysuiTestCase
import com.android.systemui.bouncer.data.repository.fakeKeyguardBouncerRepository
import com.android.systemui.communal.domain.interactor.CommunalSceneTransitionInteractor
import com.android.systemui.communal.domain.interactor.communalSceneInteractor
import com.android.systemui.communal.domain.interactor.communalSceneTransitionInteractor
import com.android.systemui.communal.domain.interactor.setCommunalV2Available
import com.android.systemui.communal.domain.interactor.setCommunalV2ConfigEnabled
import com.android.systemui.communal.domain.interactor.setCommunalV2Enabled
import com.android.systemui.communal.shared.model.CommunalScenes
import com.android.systemui.flags.BrokenWithSceneContainer
import com.android.systemui.flags.DisableSceneContainer
import com.android.systemui.flags.FakeFeatureFlags
import com.android.systemui.flags.Flags.COMMUNAL_SERVICE_ENABLED
import com.android.systemui.flags.andSceneContainer
import com.android.systemui.flags.fakeFeatureFlagsClassic
import com.android.systemui.keyguard.data.repository.fakeKeyguardRepository
import com.android.systemui.keyguard.data.repository.fakeKeyguardTransitionRepositorySpy
import com.android.systemui.keyguard.data.repository.keyguardTransitionRepository
import com.android.systemui.keyguard.shared.model.BiometricUnlockMode
import com.android.systemui.keyguard.shared.model.DozeStateModel
import com.android.systemui.keyguard.shared.model.DozeTransitionModel
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.StatusBarState
import com.android.systemui.keyguard.shared.model.TransitionState
import com.android.systemui.keyguard.shared.model.TransitionStep
import com.android.systemui.keyguard.util.KeyguardTransitionRepositorySpySubject.Companion.assertThat
import com.android.systemui.kosmos.testScope
import com.android.systemui.power.domain.interactor.PowerInteractor.Companion.setAsleepForTest
import com.android.systemui.power.domain.interactor.PowerInteractor.Companion.setAwakeForTest
import com.android.systemui.power.domain.interactor.powerInteractor
import com.android.systemui.scene.shared.flag.SceneContainerFlag
import com.android.systemui.shade.shadeTestUtil
import com.android.systemui.testKosmos
import com.android.systemui.util.mockito.whenever
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.Mock
import org.mockito.Mockito.clearInvocations
import org.mockito.Mockito.reset
import org.mockito.MockitoAnnotations
import platform.test.runner.parameterized.ParameterizedAndroidJunit4
import platform.test.runner.parameterized.Parameters

/**
 * Class for testing user journeys through the interactors. They will all be activated during setup,
 * to ensure the expected transitions are still triggered.
 */
@SmallTest
@RunWith(ParameterizedAndroidJunit4::class)
class KeyguardTransitionScenariosTest(flags: FlagsParameterization?) : SysuiTestCase() {
    private val kosmos =
        testKosmos().apply {
            this.keyguardTransitionRepository = fakeKeyguardTransitionRepositorySpy
        }
    private val testScope = kosmos.testScope

    private val keyguardRepository by lazy { kosmos.fakeKeyguardRepository }
    private val keyguardInteractor by lazy { kosmos.keyguardInteractor }
    private val bouncerRepository by lazy { kosmos.fakeKeyguardBouncerRepository }
    private val shadeTestUtil by lazy { kosmos.shadeTestUtil }
    private val transitionRepository by lazy { kosmos.fakeKeyguardTransitionRepositorySpy }
    private lateinit var featureFlags: FakeFeatureFlags

    // Used to verify transition requests for test output
    @Mock private lateinit var keyguardSecurityModel: KeyguardSecurityModel

    private val fromLockscreenTransitionInteractor by lazy {
        kosmos.fromLockscreenTransitionInteractor
    }
    private val fromDreamingTransitionInteractor by lazy { kosmos.fromDreamingTransitionInteractor }
    private val fromDozingTransitionInteractor by lazy { kosmos.fromDozingTransitionInteractor }
    private val fromOccludedTransitionInteractor by lazy { kosmos.fromOccludedTransitionInteractor }
    private val fromGoneTransitionInteractor by lazy { kosmos.fromGoneTransitionInteractor }
    private val fromAodTransitionInteractor by lazy { kosmos.fromAodTransitionInteractor }
    private val fromAlternateBouncerTransitionInteractor by lazy {
        kosmos.fromAlternateBouncerTransitionInteractor
    }
    private val fromPrimaryBouncerTransitionInteractor by lazy {
        kosmos.fromPrimaryBouncerTransitionInteractor
    }
    private val fromGlanceableHubTransitionInteractor by lazy {
        kosmos.fromGlanceableHubTransitionInteractor
    }
    private val communalSceneTransitionInteractor by lazy {
        kosmos.communalSceneTransitionInteractor
    }

    private val powerInteractor by lazy { kosmos.powerInteractor }
    private val communalSceneInteractor by lazy { kosmos.communalSceneInteractor }

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

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)

        whenever(keyguardSecurityModel.getSecurityMode(anyInt())).thenReturn(PIN)

        mSetFlagsRule.enableFlags(FLAG_COMMUNAL_HUB)
        kosmos.fakeFeatureFlagsClassic.set(COMMUNAL_SERVICE_ENABLED, true)
        if (!SceneContainerFlag.isEnabled) {
            mSetFlagsRule.disableFlags(Flags.FLAG_KEYGUARD_WM_STATE_REFACTOR)
        }
        if (glanceableHubV2()) {
            kosmos.setCommunalV2ConfigEnabled(true)
        }
        featureFlags = FakeFeatureFlags()

        fromLockscreenTransitionInteractor.start()
        fromPrimaryBouncerTransitionInteractor.start()
        fromDreamingTransitionInteractor.start()
        fromAodTransitionInteractor.start()
        fromGoneTransitionInteractor.start()
        fromDozingTransitionInteractor.start()
        fromOccludedTransitionInteractor.start()
        fromAlternateBouncerTransitionInteractor.start()
        fromGlanceableHubTransitionInteractor.start()
        communalSceneTransitionInteractor.start()
    }

    @Test
    @DisableSceneContainer
    fun lockscreenToPrimaryBouncerViaBouncerShowingCall() =
        testScope.runTest {
            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.OFF, KeyguardState.LOCKSCREEN)

            // WHEN the primary bouncer is set to show
            bouncerRepository.setPrimaryShow(true)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.PRIMARY_BOUNCER,
                    from = KeyguardState.LOCKSCREEN,
                    ownerName =
                        "FromLockscreenTransitionInteractor" +
                            "(#listenForLockscreenToPrimaryBouncer)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun occludedToDozing() =
        testScope.runTest {
            // GIVEN a device with AOD not available
            keyguardRepository.setAodAvailable(false)
            runCurrent()

            // GIVEN a prior transition has run to OCCLUDED
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.OCCLUDED)

            // WHEN the device begins to sleep
            powerInteractor.setAsleepForTest()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.DOZING,
                    from = KeyguardState.OCCLUDED,
                    ownerName = "FromOccludedTransitionInteractor(Sleep transition triggered)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun occludedToAod() =
        testScope.runTest {
            // GIVEN a device with AOD available
            keyguardRepository.setAodAvailable(true)
            runCurrent()

            // GIVEN a prior transition has run to OCCLUDED
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.OCCLUDED)

            // WHEN the device begins to sleep
            powerInteractor.setAsleepForTest()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.AOD,
                    from = KeyguardState.OCCLUDED,
                    ownerName = "FromOccludedTransitionInteractor(Sleep transition triggered)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun lockscreenToDreaming() =
        testScope.runTest {
            // GIVEN a device that is not dreaming or dozing
            keyguardRepository.setDreamingWithOverlay(false)
            keyguardRepository.setDozeTransitionModel(
                DozeTransitionModel(from = DozeStateModel.DOZE, to = DozeStateModel.FINISH)
            )
            advanceTimeBy(600L)

            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.GONE, KeyguardState.LOCKSCREEN)

            // WHEN the device begins to dream
            keyguardRepository.setDreamingWithOverlay(true)
            advanceTimeBy(100L)

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.DREAMING,
                    from = KeyguardState.LOCKSCREEN,
                    ownerName = "FromLockscreenTransitionInteractor",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun lockscreenToDozing() =
        testScope.runTest {
            // GIVEN a device with AOD not available
            keyguardRepository.setAodAvailable(false)
            runCurrent()

            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.GONE, KeyguardState.LOCKSCREEN)

            // WHEN the device begins to sleep
            powerInteractor.setAsleepForTest()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.DOZING,
                    from = KeyguardState.LOCKSCREEN,
                    ownerName = "FromLockscreenTransitionInteractor(Sleep transition triggered)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun lockscreenToAod() =
        testScope.runTest {
            // GIVEN a device with AOD available
            keyguardRepository.setAodAvailable(true)
            runCurrent()

            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.GONE, KeyguardState.LOCKSCREEN)

            // WHEN the device begins to sleep
            powerInteractor.setAsleepForTest()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.AOD,
                    from = KeyguardState.LOCKSCREEN,
                    ownerName = "FromLockscreenTransitionInteractor(Sleep transition triggered)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun dozingToLockscreen() =
        testScope.runTest {
            // GIVEN a prior transition has run to DOZING
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DOZING)
            runCurrent()

            // WHEN the device begins to wake
            keyguardRepository.setKeyguardShowing(true)
            powerInteractor.setAwakeForTest()
            advanceTimeBy(60L)

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.LOCKSCREEN,
                    from = KeyguardState.DOZING,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun dozingToLockscreenCannotBeInterruptedByDreaming() =
        testScope.runTest {
            transitionRepository.sendTransitionSteps(
                KeyguardState.LOCKSCREEN,
                KeyguardState.DOZING,
                testScheduler,
            )
            // GIVEN a prior transition has started to LOCKSCREEN
            transitionRepository.sendTransitionStep(
                TransitionStep(
                    from = KeyguardState.DOZING,
                    to = KeyguardState.LOCKSCREEN,
                    value = 0f,
                    transitionState = TransitionState.STARTED,
                    ownerName = "KeyguardTransitionScenariosTest",
                )
            )
            runCurrent()
            transitionRepository.sendTransitionStep(
                TransitionStep(
                    from = KeyguardState.DOZING,
                    to = KeyguardState.LOCKSCREEN,
                    value = 0.5f,
                    transitionState = TransitionState.RUNNING,
                    ownerName = "KeyguardTransitionScenariosTest",
                )
            )
            runCurrent()
            reset(transitionRepository)

            // WHEN a signal comes that dreaming is enabled
            keyguardRepository.setDreamingWithOverlay(true)
            advanceTimeBy(100L)

            // THEN the transition is ignored
            assertThat(transitionRepository).noTransitionsStarted()

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun dozingToGoneWithUnlock() =
        testScope.runTest {
            // GIVEN a prior transition has run to DOZING
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DOZING)
            runCurrent()

            // WHEN biometrics succeeds with wake and unlock mode
            powerInteractor.setAwakeForTest()
            keyguardRepository.setBiometricUnlockState(BiometricUnlockMode.WAKE_AND_UNLOCK)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.GONE,
                    from = KeyguardState.DOZING,
                    ownerName = "FromDozingTransitionInteractor(biometric wake and unlock)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun dozingToPrimaryBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to DOZING
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DOZING)
            runCurrent()

            // WHEN awaked by a request to show the primary bouncer, as can happen if SPFS is
            // touched after boot
            powerInteractor.setAwakeForTest()
            bouncerRepository.setPrimaryShow(true)
            advanceTimeBy(60L)

            assertThat(transitionRepository)
                .startedTransition(
                    from = KeyguardState.DOZING,
                    to = KeyguardState.PRIMARY_BOUNCER,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    /** This handles security method NONE and screen off with lock timeout */
    @Test
    @DisableSceneContainer
    fun dreamingToGoneWithKeyguardNotShowing() =
        testScope.runTest {
            // Setup - Move past initial delay with [KeyguardInteractor#isAbleToDream]
            advanceTimeBy(600L)

            // GIVEN a prior transition has run to DREAMING
            keyguardRepository.setDreamingWithOverlay(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DREAMING)
            advanceTimeBy(60L)

            // WHEN the device wakes up without a keyguard
            keyguardRepository.setKeyguardShowing(false)
            keyguardRepository.setKeyguardDismissible(true)
            keyguardRepository.setDreamingWithOverlay(false)
            advanceTimeBy(60L)

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.GONE,
                    from = KeyguardState.DREAMING,
                    ownerName = "FromDreamingTransitionInteractor",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun goneToDozing() =
        testScope.runTest {
            // GIVEN a device with AOD not available
            keyguardRepository.setAodAvailable(false)
            runCurrent()

            // GIVEN a prior transition has run to GONE
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GONE)

            // WHEN the device begins to sleep
            powerInteractor.setAsleepForTest()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.DOZING,
                    from = KeyguardState.GONE,
                    ownerName = "FromGoneTransitionInteractor(Sleep transition triggered)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun goneToAod() =
        testScope.runTest {
            // GIVEN a device with AOD available
            keyguardRepository.setAodAvailable(true)
            runCurrent()

            // GIVEN a prior transition has run to GONE
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GONE)

            // WHEN the device begins to sleep
            powerInteractor.setAsleepForTest()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.AOD,
                    from = KeyguardState.GONE,
                    ownerName = "FromGoneTransitionInteractor(Sleep transition triggered)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun goneToLockscreen() =
        testScope.runTest {
            // GIVEN a prior transition has run to GONE
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GONE)

            // WHEN the keyguard starts to show
            keyguardRepository.setKeyguardShowing(true)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.LOCKSCREEN,
                    from = KeyguardState.GONE,
                    ownerName =
                        "FromGoneTransitionInteractor" +
                            "(keyguard interactor says keyguard is showing)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun goneToOccluded() =
        testScope.runTest {
            // GIVEN a prior transition has run to GONE
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GONE)

            // WHEN an occluding app is running and showDismissibleKeyguard is called
            keyguardRepository.setKeyguardOccluded(true)
            keyguardRepository.showDismissibleKeyguard()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    from = KeyguardState.GONE,
                    to = KeyguardState.OCCLUDED,
                    ownerName =
                        "FromGoneTransitionInteractor" + "(Dismissible keyguard with occlusion)",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun goneToDreaming() =
        testScope.runTest {
            // Setup - Move past initial delay with [KeyguardInteractor#isAbleToDream]
            advanceTimeBy(600L)

            // GIVEN a prior transition has run to GONE
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GONE)

            // WHEN the device begins to dream
            keyguardRepository.setDreamingWithOverlay(true)
            advanceTimeBy(100L)

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.DREAMING,
                    from = KeyguardState.GONE,
                    ownerName = "FromGoneTransitionInteractor",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun goneToGlanceableHub_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN a prior transition has run to GONE
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GONE)

            // WHEN the glanceable hub is shown
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.GLANCEABLE_HUB,
                    from = KeyguardState.GONE,
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    animatorAssertion = { it.isNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun alternateBouncerToPrimaryBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            runTransitionAndSetWakefulness(
                KeyguardState.LOCKSCREEN,
                KeyguardState.ALTERNATE_BOUNCER,
            )

            // WHEN the alternateBouncer stops showing and then the primary bouncer shows
            bouncerRepository.setPrimaryShow(true)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.PRIMARY_BOUNCER,
                    from = KeyguardState.ALTERNATE_BOUNCER,
                    ownerName = "FromAlternateBouncerTransitionInteractor",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun alternateBouncerToAod() =
        testScope.runTest {
            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            bouncerRepository.setAlternateVisible(true)
            runTransitionAndSetWakefulness(
                KeyguardState.LOCKSCREEN,
                KeyguardState.ALTERNATE_BOUNCER,
            )

            // GIVEN the primary bouncer isn't showing, aod available and starting to sleep
            bouncerRepository.setPrimaryShow(false)
            keyguardRepository.setAodAvailable(true)
            powerInteractor.setAsleepForTest()

            // WHEN the alternateBouncer stops showing
            bouncerRepository.setAlternateVisible(false)
            advanceTimeBy(200L)

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.AOD,
                    from = KeyguardState.ALTERNATE_BOUNCER,
                    ownerName = "FromAlternateBouncerTransitionInteractor",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun alternateBouncerToDozing() =
        testScope.runTest {
            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            bouncerRepository.setAlternateVisible(true)
            runTransitionAndSetWakefulness(
                KeyguardState.LOCKSCREEN,
                KeyguardState.ALTERNATE_BOUNCER,
            )

            // GIVEN the primary bouncer isn't showing, aod not available and starting to sleep
            // to sleep
            bouncerRepository.setPrimaryShow(false)
            keyguardRepository.setAodAvailable(false)
            powerInteractor.setAsleepForTest()

            // WHEN the alternateBouncer stops showing
            bouncerRepository.setAlternateVisible(false)
            advanceTimeBy(200L)

            assertThat(transitionRepository)
                .startedTransition(
                    to = KeyguardState.DOZING,
                    from = KeyguardState.ALTERNATE_BOUNCER,
                    ownerName = "FromAlternateBouncerTransitionInteractor",
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun alternateBouncerToLockscreen() =
        testScope.runTest {
            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            bouncerRepository.setAlternateVisible(true)
            runTransitionAndSetWakefulness(
                KeyguardState.LOCKSCREEN,
                KeyguardState.ALTERNATE_BOUNCER,
            )

            // GIVEN the primary bouncer isn't showing and device not sleeping
            bouncerRepository.setPrimaryShow(false)

            // WHEN the alternateBouncer stops showing
            bouncerRepository.setAlternateVisible(false)
            advanceTimeBy(200L)

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromAlternateBouncerTransitionInteractor",
                    from = KeyguardState.ALTERNATE_BOUNCER,
                    to = KeyguardState.LOCKSCREEN,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun alternateBouncerToGone() =
        testScope.runTest {
            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            bouncerRepository.setAlternateVisible(true)
            runTransitionAndSetWakefulness(
                KeyguardState.LOCKSCREEN,
                KeyguardState.ALTERNATE_BOUNCER,
            )

            // GIVEN the keyguard is going away
            keyguardRepository.setKeyguardGoingAway(true)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromAlternateBouncerTransitionInteractor",
                    from = KeyguardState.ALTERNATE_BOUNCER,
                    to = KeyguardState.GONE,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun alternateBouncerToGlanceableHub() =
        testScope.runTest {
            // GIVEN the device is idle on the glanceable hub
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()
            clearInvocations(transitionRepository)

            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            bouncerRepository.setAlternateVisible(true)
            runTransitionAndSetWakefulness(
                KeyguardState.LOCKSCREEN,
                KeyguardState.ALTERNATE_BOUNCER,
            )

            // GIVEN the primary bouncer isn't showing and device not sleeping
            bouncerRepository.setPrimaryShow(false)

            // WHEN the alternateBouncer stops showing
            bouncerRepository.setAlternateVisible(false)
            advanceTimeBy(200L)

            // THEN a transition to GLANCEABLE_HUB should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = FromAlternateBouncerTransitionInteractor::class.simpleName,
                    from = KeyguardState.ALTERNATE_BOUNCER,
                    to = KeyguardState.GLANCEABLE_HUB,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun primaryBouncerToAod() =
        testScope.runTest {
            // GIVEN aod available
            keyguardRepository.setAodAvailable(true)
            runCurrent()

            // GIVEN a prior transition has run to PRIMARY_BOUNCER
            bouncerRepository.setPrimaryShow(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.PRIMARY_BOUNCER)

            powerInteractor.setAsleepForTest()

            // WHEN the primaryBouncer stops showing
            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            // THEN a transition to AOD should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName =
                        "FromPrimaryBouncerTransitionInteractor" + "(Sleep transition triggered)",
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.AOD,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun primaryBouncerToDozing() =
        testScope.runTest {
            // GIVEN a prior transition has run to PRIMARY_BOUNCER
            bouncerRepository.setPrimaryShow(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.PRIMARY_BOUNCER)

            // GIVEN aod not available and starting to sleep to sleep
            keyguardRepository.setAodAvailable(false)
            powerInteractor.setAsleepForTest()

            // WHEN the primaryBouncer stops showing
            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            // THEN a transition to DOZING should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName =
                        "FromPrimaryBouncerTransitionInteractor" + "(Sleep transition triggered)",
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.DOZING,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun primaryBouncerToLockscreen() =
        testScope.runTest {
            // GIVEN a prior transition has run to PRIMARY_BOUNCER
            bouncerRepository.setPrimaryShow(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.PRIMARY_BOUNCER)

            // WHEN the primaryBouncer stops showing
            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            // THEN a transition to LOCKSCREEN should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromPrimaryBouncerTransitionInteractor",
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.LOCKSCREEN,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun primaryBouncerToGlanceableHub() =
        testScope.runTest {
            // GIVEN the device is idle on the glanceable hub
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()

            // GIVEN a prior transition has run to PRIMARY_BOUNCER
            bouncerRepository.setPrimaryShow(true)
            runTransitionAndSetWakefulness(
                KeyguardState.GLANCEABLE_HUB,
                KeyguardState.PRIMARY_BOUNCER,
            )

            // WHEN the primaryBouncer stops showing
            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            // THEN a transition to LOCKSCREEN should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = FromPrimaryBouncerTransitionInteractor::class.simpleName,
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.GLANCEABLE_HUB,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    @DisableFlags(FLAG_GLANCEABLE_HUB_V2)
    fun primaryBouncerToGlanceableHubWhileDreaming() =
        testScope.runTest {
            // Setup - Move past initial delay with [KeyguardInteractor#isAbleToDream]
            advanceTimeBy(600L)

            // GIVEN the device is idle on the glanceable hub
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()

            // GIVEN a prior transition has run to PRIMARY_BOUNCER
            bouncerRepository.setPrimaryShow(true)
            runTransitionAndSetWakefulness(
                KeyguardState.GLANCEABLE_HUB,
                KeyguardState.PRIMARY_BOUNCER,
            )

            // GIVEN that we are dreaming and occluded
            keyguardRepository.setDreaming(true)
            keyguardRepository.setKeyguardOccluded(true)
            advanceTimeBy(60L)

            // WHEN the primaryBouncer stops showing
            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            // THEN a transition to GLANCEABLE_HUB should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = FromPrimaryBouncerTransitionInteractor::class.simpleName,
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.GLANCEABLE_HUB,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun occludedToGone() =
        testScope.runTest {
            // GIVEN a device on lockscreen
            keyguardRepository.setKeyguardShowing(true)
            runCurrent()

            // GIVEN a prior transition has run to OCCLUDED
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.OCCLUDED)
            keyguardRepository.setKeyguardOccluded(true)
            runCurrent()

            // WHEN keyguard goes away
            keyguardRepository.setKeyguardShowing(false)
            // AND occlusion ends
            keyguardRepository.setKeyguardOccluded(false)
            runCurrent()

            // THEN a transition to GONE should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromOccludedTransitionInteractor",
                    from = KeyguardState.OCCLUDED,
                    to = KeyguardState.GONE,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun occludedToLockscreen() =
        testScope.runTest {
            // GIVEN a device on lockscreen
            keyguardRepository.setKeyguardShowing(true)
            runCurrent()

            // GIVEN a prior transition has run to OCCLUDED
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.OCCLUDED)
            keyguardRepository.setKeyguardOccluded(true)
            runCurrent()

            // WHEN occlusion ends
            keyguardRepository.setKeyguardOccluded(false)
            runCurrent()

            // THEN a transition to LOCKSCREEN should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromOccludedTransitionInteractor",
                    from = KeyguardState.OCCLUDED,
                    to = KeyguardState.LOCKSCREEN,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun occludedToGlanceableHub_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN a prior transition has run to OCCLUDED from GLANCEABLE_HUB
            runTransitionAndSetWakefulness(KeyguardState.GLANCEABLE_HUB, KeyguardState.OCCLUDED)
            keyguardRepository.setKeyguardOccluded(true)
            runCurrent()

            // GIVEN a device on lockscreen and communal is available
            kosmos.setCommunalV2Available(true)
            runCurrent()

            // WHEN occlusion ends
            keyguardRepository.setKeyguardOccluded(false)
            runCurrent()

            // THEN a transition to GLANCEABLE_HUB should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.OCCLUDED,
                    to = KeyguardState.GLANCEABLE_HUB,
                    animatorAssertion = { it.isNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun occludedToAlternateBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to OCCLUDED
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.OCCLUDED)
            keyguardRepository.setKeyguardOccluded(true)
            runCurrent()

            // WHEN alternate bouncer shows
            bouncerRepository.setAlternateVisible(true)
            runCurrent()

            // THEN a transition to AlternateBouncer should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromOccludedTransitionInteractor",
                    from = KeyguardState.OCCLUDED,
                    to = KeyguardState.ALTERNATE_BOUNCER,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun occludedToPrimaryBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to OCCLUDED
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.OCCLUDED)
            keyguardRepository.setKeyguardOccluded(true)
            runCurrent()

            // WHEN primary bouncer shows
            bouncerRepository.setPrimaryShow(true)
            runCurrent()

            // THEN a transition to AlternateBouncer should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromOccludedTransitionInteractor",
                    from = KeyguardState.OCCLUDED,
                    to = KeyguardState.PRIMARY_BOUNCER,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun primaryBouncerToOccluded() =
        testScope.runTest {
            // GIVEN a prior transition has run to PRIMARY_BOUNCER
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.PRIMARY_BOUNCER)
            bouncerRepository.setPrimaryShow(true)
            runCurrent()

            // WHEN the keyguard is occluded and primary bouncer stops showing
            keyguardRepository.setKeyguardOccluded(true)
            bouncerRepository.setPrimaryShow(false)
            runCurrent()

            // THEN a transition to OCCLUDED should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromPrimaryBouncerTransitionInteractor",
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.OCCLUDED,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun dozingToOccluded() =
        testScope.runTest {
            // GIVEN a prior transition has run to DOZING
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DOZING)
            runCurrent()

            // WHEN the keyguard is occluded and device wakes up
            keyguardRepository.setKeyguardOccluded(true)
            keyguardRepository.setKeyguardShowing(true)
            powerInteractor.setAwakeForTest()
            advanceTimeBy(60L)

            // THEN a transition to OCCLUDED should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromDozingTransitionInteractor",
                    from = KeyguardState.DOZING,
                    to = KeyguardState.OCCLUDED,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun dreamingToOccluded() =
        testScope.runTest {
            // GIVEN a prior transition has run to DREAMING
            keyguardRepository.setDreaming(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DREAMING)
            runCurrent()

            // WHEN the keyguard is occluded and device wakes up and is no longer dreaming
            keyguardRepository.setDreaming(false)
            keyguardRepository.setKeyguardOccluded(true)
            testScheduler.advanceTimeBy(150) // The dreaming and occluded signals are debounced.
            runCurrent()

            // THEN a transition to OCCLUDED should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromDreamingTransitionInteractor(Occluded but no longer dreaming)",
                    from = KeyguardState.DREAMING,
                    to = KeyguardState.OCCLUDED,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    @EnableFlags(Flags.FLAG_RESTART_DREAM_ON_UNOCCLUDE)
    fun dreamingToOccludedToDreaming() =
        testScope.runTest {
            // GIVEN a device on lockscreen
            keyguardRepository.setKeyguardShowing(true)
            runCurrent()

            // Given a device that is dreaming
            keyguardRepository.setDreaming(true)

            // GIVEN a prior transition has run to OCCLUDED
            runTransitionAndSetWakefulness(KeyguardState.DREAMING, KeyguardState.OCCLUDED)
            keyguardRepository.setKeyguardOccluded(true)
            runCurrent()

            // WHEN occlusion ends
            keyguardRepository.setKeyguardOccluded(false)
            runCurrent()

            // THEN a transition to DREAMING should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = FromOccludedTransitionInteractor::class.simpleName,
                    from = KeyguardState.OCCLUDED,
                    to = KeyguardState.DREAMING,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun dreamingToPrimaryBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to DREAMING
            keyguardRepository.setDreaming(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DREAMING)
            runCurrent()

            // WHEN the primary bouncer is set to show
            bouncerRepository.setPrimaryShow(true)
            runCurrent()

            // THEN a transition to PRIMARY_BOUNCER should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromDreamingTransitionInteractor",
                    from = KeyguardState.DREAMING,
                    to = KeyguardState.PRIMARY_BOUNCER,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    fun dreamingToAod() =
        testScope.runTest {
            // GIVEN a prior transition has run to DREAMING
            keyguardRepository.setDreaming(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DREAMING)
            runCurrent()

            // WHEN the device starts DOZE_AOD
            keyguardRepository.setDozeTransitionModel(
                DozeTransitionModel(from = DozeStateModel.INITIALIZED, to = DozeStateModel.DOZE_AOD)
            )
            runCurrent()

            // THEN a transition to AOD should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromDreamingTransitionInteractor",
                    from = KeyguardState.DREAMING,
                    to = KeyguardState.AOD,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun dreamingToGlanceableHub_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN a prior transition has run to DREAMING
            keyguardRepository.setDreaming(true)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.DREAMING)
            runCurrent()

            // WHEN a transition to the glanceable hub starts
            val currentScene = CommunalScenes.Blank
            val targetScene = CommunalScenes.Communal

            val progress = MutableStateFlow(0f)
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Transition(
                        fromScene = currentScene,
                        toScene = targetScene,
                        currentScene = flowOf(targetScene),
                        progress = progress,
                        isInitiatedByUserInput = false,
                        isUserInputOngoing = flowOf(false),
                    )
                )
            communalSceneInteractor.setTransitionState(transitionState)
            progress.value = .1f
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.DREAMING,
                    to = KeyguardState.GLANCEABLE_HUB,
                    animatorAssertion = { it.isNull() }, // transition should be manually animated
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun lockscreenToOccluded() =
        testScope.runTest {
            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.GONE, KeyguardState.LOCKSCREEN)
            runCurrent()

            // WHEN the keyguard is occluded
            keyguardRepository.setKeyguardOccluded(true)
            runCurrent()

            // THEN a transition to OCCLUDED should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromLockscreenTransitionInteractor",
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.OCCLUDED,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun aodToPrimaryBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to AOD
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.AOD)
            runCurrent()

            // WHEN the primary bouncer is set to show
            bouncerRepository.setPrimaryShow(true)
            runCurrent()

            // THEN a transition to OCCLUDED should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = "FromAodTransitionInteractor",
                    from = KeyguardState.AOD,
                    to = KeyguardState.PRIMARY_BOUNCER,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun lockscreenToOccluded_fromCameraGesture() =
        testScope.runTest {
            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.AOD, KeyguardState.LOCKSCREEN)
            runCurrent()

            // WHEN the device begins to sleep (first power button press), which starts
            // LS -> DOZING...
            powerInteractor.setAsleepForTest()
            runCurrent()
            reset(transitionRepository)

            // ...AND WHEN the camera gesture is detected quickly afterwards
            keyguardInteractor.onCameraLaunchDetected(CAMERA_LAUNCH_SOURCE_POWER_DOUBLE_TAP)
            runCurrent()

            // THEN a transition from DOZING => OCCLUDED should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName =
                        "FromDozingTransitionInteractor" +
                            "(keyguardInteractor.onCameraLaunchDetected)",
                    from = KeyguardState.DOZING,
                    to = KeyguardState.OCCLUDED,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun lockscreenToPrimaryBouncerDragging() =
        testScope.runTest {
            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.AOD, KeyguardState.LOCKSCREEN)
            runCurrent()

            // GIVEN the keyguard is showing locked
            keyguardRepository.setStatusBarState(StatusBarState.KEYGUARD)
            runCurrent()
            shadeTestUtil.setTracking(true)
            shadeTestUtil.setShadeExpansion(.9f)
            runCurrent()

            // THEN a transition from LOCKSCREEN => PRIMARY_BOUNCER should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName =
                        "FromLockscreenTransitionInteractor" +
                            "(#listenForLockscreenToPrimaryBouncerDragging)",
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.PRIMARY_BOUNCER,
                    animatorAssertion = { it.isNull() }, // dragging should be manually animated
                )

            // WHEN the user stops dragging and shade is back to expanded
            clearInvocations(transitionRepository)
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.PRIMARY_BOUNCER)
            shadeTestUtil.setTracking(false)
            shadeTestUtil.setShadeExpansion(1f)
            runCurrent()

            // THEN a transition from LOCKSCREEN => PRIMARY_BOUNCER should occur
            assertThat(transitionRepository)
                .startedTransition(
                    from = KeyguardState.PRIMARY_BOUNCER,
                    to = KeyguardState.LOCKSCREEN,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun lockscreenToGlanceableHub_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN a prior transition has run to LOCKSCREEN
            runTransitionAndSetWakefulness(KeyguardState.AOD, KeyguardState.LOCKSCREEN)
            runCurrent()

            // WHEN a glanceable hub transition starts
            val currentScene = CommunalScenes.Blank
            val targetScene = CommunalScenes.Communal

            val progress = MutableStateFlow(0f)
            val transitionState =
                MutableStateFlow<ObservableTransitionState>(
                    ObservableTransitionState.Transition(
                        fromScene = currentScene,
                        toScene = targetScene,
                        currentScene = flowOf(targetScene),
                        progress = progress,
                        isInitiatedByUserInput = false,
                        isUserInputOngoing = flowOf(false),
                    )
                )
            communalSceneInteractor.setTransitionState(transitionState)
            progress.value = .1f
            runCurrent()

            // THEN a transition from LOCKSCREEN => GLANCEABLE_HUB should occur
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.LOCKSCREEN,
                    to = KeyguardState.GLANCEABLE_HUB,
                    animatorAssertion = { it.isNull() }, // transition should be manually animated
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun glanceableHubToDozing_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN a prior transition has run to GLANCEABLE_HUB
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()
            clearInvocations(transitionRepository)

            // WHEN the device begins to sleep
            powerInteractor.setAsleepForTest()
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.GLANCEABLE_HUB,
                    to = KeyguardState.DOZING,
                    animatorAssertion = { it.isNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun glanceableHubToPrimaryBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GLANCEABLE_HUB)

            // WHEN the primary bouncer shows
            bouncerRepository.setPrimaryShow(true)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = FromGlanceableHubTransitionInteractor::class.simpleName,
                    from = KeyguardState.GLANCEABLE_HUB,
                    to = KeyguardState.PRIMARY_BOUNCER,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun glanceableHubToAlternateBouncer() =
        testScope.runTest {
            // GIVEN a prior transition has run to ALTERNATE_BOUNCER
            runTransitionAndSetWakefulness(KeyguardState.LOCKSCREEN, KeyguardState.GLANCEABLE_HUB)

            // WHEN the primary bouncer shows
            bouncerRepository.setAlternateVisible(true)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = FromGlanceableHubTransitionInteractor::class.simpleName,
                    from = KeyguardState.GLANCEABLE_HUB,
                    to = KeyguardState.ALTERNATE_BOUNCER,
                    animatorAssertion = { it.isNotNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun glanceableHubToOccluded_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN device is not dreaming
            keyguardRepository.setDreaming(false)

            // GIVEN a prior transition has run to GLANCEABLE_HUB
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()
            clearInvocations(transitionRepository)

            // WHEN the keyguard is occluded
            keyguardRepository.setKeyguardOccluded(true)
            advanceTimeBy(200.milliseconds)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.GLANCEABLE_HUB,
                    to = KeyguardState.OCCLUDED,
                    animatorAssertion = { it.isNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    fun glanceableHubToGone_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN a prior transition has run to GLANCEABLE_HUB
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()
            clearInvocations(transitionRepository)

            // WHEN keyguard goes away
            keyguardRepository.setKeyguardGoingAway(true)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.GLANCEABLE_HUB,
                    to = KeyguardState.GONE,
                    animatorAssertion = { it.isNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @DisableSceneContainer
    @EnableFlags(FLAG_GLANCEABLE_HUB_V2)
    fun glanceableHubToDreaming_v2() =
        testScope.runTest {
            kosmos.setCommunalV2Enabled(true)

            // GIVEN a device that is not dreaming or dozing
            keyguardRepository.setDreamingWithOverlay(false)
            keyguardRepository.setDozeTransitionModel(
                DozeTransitionModel(from = DozeStateModel.DOZE, to = DozeStateModel.FINISH)
            )
            advanceTimeBy(600.milliseconds)

            // GIVEN a prior transition has run to glanceable hub
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()
            clearInvocations(transitionRepository)

            keyguardRepository.setDreamingWithOverlay(true)
            advanceTimeBy(100.milliseconds)

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.GLANCEABLE_HUB,
                    to = KeyguardState.DREAMING,
                    animatorAssertion = { it.isNull() },
                )

            coroutineContext.cancelChildren()
        }

    @Test
    @BrokenWithSceneContainer(339465026)
    fun glanceableHubToOccludedDoesNotTriggerWhenDreamStateChanges_communalKtfRefactor() =
        testScope.runTest {
            // GIVEN that we are dreaming and not dozing
            powerInteractor.setAwakeForTest()
            keyguardRepository.setDreaming(true)
            keyguardRepository.setKeyguardOccluded(true)
            keyguardRepository.setDozeTransitionModel(
                DozeTransitionModel(from = DozeStateModel.DOZE, to = DozeStateModel.FINISH)
            )
            advanceTimeBy(700.milliseconds)
            clearInvocations(transitionRepository)

            // GIVEN a prior transition has run to GLANCEABLE_HUB
            communalSceneInteractor.changeScene(CommunalScenes.Communal, "test")
            runCurrent()
            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.DREAMING,
                    to = KeyguardState.GLANCEABLE_HUB,
                )
            clearInvocations(transitionRepository)

            // WHEN dream ends but we are still occluded
            keyguardRepository.setDreaming(false)
            runCurrent()
            assertThat(transitionRepository).noTransitionsStarted()

            // Simulate occlusion signal changing due to dream terminating and then occluding again
            // due to a new activity starting a couple milliseconds later.
            keyguardRepository.setKeyguardOccluded(false)
            advanceTimeBy(10.milliseconds)
            keyguardRepository.setKeyguardOccluded(true)
            advanceTimeBy(200.milliseconds)
            runCurrent()

            assertThat(transitionRepository)
                .startedTransition(
                    ownerName = CommunalSceneTransitionInteractor::class.simpleName,
                    from = KeyguardState.GLANCEABLE_HUB,
                    to = KeyguardState.OCCLUDED,
                )

            coroutineContext.cancelChildren()
        }

    private suspend fun TestScope.runTransitionAndSetWakefulness(
        from: KeyguardState,
        to: KeyguardState,
    ) {
        transitionRepository.sendTransitionStep(
            TransitionStep(
                from = from,
                to = to,
                value = 0f,
                transitionState = TransitionState.STARTED,
            )
        )
        runCurrent()
        transitionRepository.sendTransitionStep(
            TransitionStep(
                from = from,
                to = to,
                value = 0.5f,
                transitionState = TransitionState.RUNNING,
            )
        )
        runCurrent()
        transitionRepository.sendTransitionStep(
            TransitionStep(
                from = from,
                to = to,
                value = 1f,
                transitionState = TransitionState.FINISHED,
            )
        )
        runCurrent()
        reset(transitionRepository)

        if (KeyguardState.deviceIsAwakeInState(to)) {
            powerInteractor.setAwakeForTest()
        } else {
            powerInteractor.setAsleepForTest()
        }
    }
}
