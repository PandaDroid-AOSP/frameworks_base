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

package com.android.systemui.bouncer.ui.composable

import android.app.AlertDialog
import android.platform.test.annotations.MotionTest
import android.testing.TestableLooper.RunWithLooper
import android.view.View
import androidx.activity.BackEventCompat
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import com.android.compose.animation.scene.ContentScope
import com.android.compose.animation.scene.FeatureCaptures.elementAlpha
import com.android.compose.animation.scene.FeatureCaptures.elementScale
import com.android.compose.animation.scene.ObservableTransitionState
import com.android.compose.animation.scene.SceneKey
import com.android.compose.animation.scene.UserAction
import com.android.compose.animation.scene.UserActionResult
import com.android.compose.animation.scene.isElement
import com.android.compose.theme.PlatformTheme
import com.android.systemui.SysuiTestCase
import com.android.systemui.bouncer.ui.BouncerDialogFactory
import com.android.systemui.bouncer.ui.viewmodel.BouncerOverlayContentViewModel
import com.android.systemui.bouncer.ui.viewmodel.BouncerUserActionsViewModel
import com.android.systemui.bouncer.ui.viewmodel.bouncerOverlayContentViewModel
import com.android.systemui.flags.EnableSceneContainer
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.Kosmos.Fixture
import com.android.systemui.lifecycle.ExclusiveActivatable
import com.android.systemui.lifecycle.rememberViewModel
import com.android.systemui.motion.createSysUiComposeMotionTestRule
import com.android.systemui.qs.ui.viewmodel.fakeQsSceneAdapter
import com.android.systemui.scene.domain.interactor.sceneInteractor
import com.android.systemui.scene.domain.startable.sceneContainerStartable
import com.android.systemui.scene.sceneContainerViewModelFactory
import com.android.systemui.scene.sceneTransitionsBuilder
import com.android.systemui.scene.shared.model.Overlays
import com.android.systemui.scene.shared.model.SceneContainerConfig
import com.android.systemui.scene.shared.model.Scenes
import com.android.systemui.scene.shared.model.sceneDataSourceDelegator
import com.android.systemui.scene.ui.composable.Scene
import com.android.systemui.scene.ui.composable.SceneContainer
import com.android.systemui.scene.ui.view.sceneJankMonitorFactory
import com.android.systemui.testKosmos
import kotlin.test.Ignore
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.mock
import platform.test.motion.compose.ComposeFeatureCaptures.positionInRoot
import platform.test.motion.compose.ComposeRecordingSpec
import platform.test.motion.compose.MotionControl
import platform.test.motion.compose.feature
import platform.test.motion.compose.recordMotion
import platform.test.motion.compose.runTest
import platform.test.screenshot.DeviceEmulationSpec
import platform.test.screenshot.Displays.Phone

/** MotionTest for the Bouncer Predictive Back animation */
@LargeTest
@RunWith(AndroidJUnit4::class)
@RunWithLooper
@EnableSceneContainer
@MotionTest
class BouncerPredictiveBackTest : SysuiTestCase() {

    private val deviceSpec = DeviceEmulationSpec(Phone)
    private val kosmos = testKosmos()

    @get:Rule val motionTestRule = createSysUiComposeMotionTestRule(kosmos, deviceSpec)
    private val androidComposeTestRule =
        motionTestRule.toolkit.composeContentTestRule as AndroidComposeTestRule<*, *>

    private val sceneInteractor by lazy { kosmos.sceneInteractor }
    private val Kosmos.sceneKeys by Fixture { listOf(Scenes.Lockscreen) }
    private val Kosmos.initialSceneKey by Fixture { Scenes.Lockscreen }
    private val Kosmos.sceneContainerConfig by Fixture {
        val navigationDistances = mapOf(Scenes.Lockscreen to 1)
        SceneContainerConfig(
            sceneKeys,
            initialSceneKey,
            emptyList(),
            navigationDistances,
            sceneTransitionsBuilder,
        )
    }
    private val view = mock<View>()

    private val transitionState by lazy {
        MutableStateFlow<ObservableTransitionState>(
            ObservableTransitionState.Idle(kosmos.sceneContainerConfig.initialSceneKey)
        )
    }

    private val sceneContainerViewModel by lazy {
        kosmos.sceneContainerViewModelFactory
            .create(view) {}
            .apply { setTransitionState(transitionState) }
    }

    private val bouncerDialogFactory =
        object : BouncerDialogFactory {
            override fun invoke(): AlertDialog {
                throw AssertionError()
            }
        }
    private val bouncerSceneActionsViewModelFactory =
        object : BouncerUserActionsViewModel.Factory {
            override fun create() = BouncerUserActionsViewModel()
        }
    private lateinit var mBouncerOverlayContentViewModel: BouncerOverlayContentViewModel
    private val mBouncerOverlayContentViewModelFactory =
        object : BouncerOverlayContentViewModel.Factory {
            override fun create() = mBouncerOverlayContentViewModel
        }
    private val bouncerScene =
        BouncerOverlay(
            bouncerSceneActionsViewModelFactory,
            mBouncerOverlayContentViewModelFactory,
            bouncerDialogFactory,
        )

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)

        mBouncerOverlayContentViewModel = kosmos.bouncerOverlayContentViewModel

        val startable = kosmos.sceneContainerStartable
        startable.start()
    }

    @Test
    @Ignore("b/394049206: Update the goldens and re-enable this test.")
    fun bouncerPredictiveBackMotion() =
        motionTestRule.runTest(timeout = 30.seconds) {
            val motion =
                recordMotion(
                    content = { play ->
                        PlatformTheme {
                            BackGestureAnimation(play)
                            SceneContainer(
                                viewModel =
                                    rememberViewModel("BouncerPredictiveBackTest") {
                                        sceneContainerViewModel
                                    },
                                sceneByKey = mapOf(Scenes.Lockscreen to FakeLockscreen()),
                                initialSceneKey = Scenes.Lockscreen,
                                transitionsBuilder = kosmos.sceneTransitionsBuilder,
                                overlayByKey = mapOf(Overlays.Bouncer to bouncerScene),
                                dataSourceDelegator = kosmos.sceneDataSourceDelegator,
                                qsSceneAdapter = { kosmos.fakeQsSceneAdapter },
                                sceneJankMonitorFactory = kosmos.sceneJankMonitorFactory,
                            )
                        }
                    },
                    ComposeRecordingSpec(
                        MotionControl(
                            delayRecording = {
                                awaitCondition {
                                    sceneInteractor.transitionState.value.isTransitioning()
                                }
                            }
                        ) {
                            awaitCondition {
                                sceneInteractor.transitionState.value.isIdle(Scenes.Lockscreen)
                            }
                        }
                    ) {
                        feature(isElement(Bouncer.Elements.Content), elementAlpha, "content_alpha")
                        feature(isElement(Bouncer.Elements.Content), elementScale, "content_scale")
                        feature(
                            isElement(Bouncer.Elements.Content),
                            positionInRoot,
                            "content_offset",
                        )
                        feature(
                            isElement(Bouncer.Elements.Background),
                            elementAlpha,
                            "background_alpha",
                        )
                    },
                )

            assertThat(motion).timeSeriesMatchesGolden()
        }

    @Composable
    private fun BackGestureAnimation(play: Boolean) {
        val backProgress = remember { Animatable(0f) }

        LaunchedEffect(play) {
            if (play) {
                val dispatcher = androidComposeTestRule.activity.onBackPressedDispatcher
                androidComposeTestRule.runOnUiThread {
                    dispatcher.dispatchOnBackStarted(backEvent())
                }
                backProgress.animateTo(
                    targetValue = 1f,
                    animationSpec = tween(durationMillis = 500),
                ) {
                    androidComposeTestRule.runOnUiThread {
                        dispatcher.dispatchOnBackProgressed(
                            backEvent(progress = backProgress.value)
                        )
                        if (backProgress.value == 1f) {
                            dispatcher.onBackPressed()
                        }
                    }
                }
            }
        }
    }

    private fun backEvent(progress: Float = 0f): BackEventCompat {
        return BackEventCompat(
            touchX = 0f,
            touchY = 0f,
            progress = progress,
            swipeEdge = BackEventCompat.EDGE_LEFT,
        )
    }

    private class FakeLockscreen : ExclusiveActivatable(), Scene {
        override val key: SceneKey = Scenes.Lockscreen
        override val userActions: Flow<Map<UserAction, UserActionResult>> = flowOf()

        @Composable
        override fun ContentScope.Content(modifier: Modifier) {
            Box(modifier = modifier, contentAlignment = Alignment.Center) {
                Text(text = "Fake Lockscreen")
            }
        }

        override suspend fun onActivated() = awaitCancellation()
    }
}
