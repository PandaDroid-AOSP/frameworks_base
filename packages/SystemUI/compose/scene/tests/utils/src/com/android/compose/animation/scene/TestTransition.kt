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

package com.android.compose.animation.scene

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.SemanticsNodeInteractionsProvider
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.lerp
import androidx.compose.ui.util.lerp
import kotlinx.coroutines.CoroutineScope
import platform.test.motion.MotionTestRule
import platform.test.motion.RecordedMotion
import platform.test.motion.compose.ComposeRecordingSpec
import platform.test.motion.compose.ComposeToolkit
import platform.test.motion.compose.MotionControl
import platform.test.motion.compose.feature
import platform.test.motion.compose.recordMotion
import platform.test.motion.golden.FeatureCapture
import platform.test.motion.golden.TimeSeriesCaptureScope

@DslMarker annotation class TransitionTestDsl

@TransitionTestDsl
interface TransitionTestBuilder {
    /**
     * Assert on the state of the layout before the transition starts.
     *
     * This should be called maximum once, before [at] or [after] is called.
     */
    fun before(builder: TransitionTestAssertionScope.() -> Unit)

    /**
     * Assert on the state of the layout during the transition at [timestamp].
     *
     * This should be called after [before] is called and before [after] is called. Successive calls
     * to [at] must be called with increasing [timestamp].
     *
     * Important: [timestamp] must be a multiple of 16 (the duration of a frame on the JVM/Android).
     * There is no intermediary state between `t` and `t + 16` , so testing transitions outside of
     * `t = 0`, `t = 16`, `t = 32`, etc does not make sense.
     *
     * @param builder the builder can run assertions and is passed the CoroutineScope such that the
     *   test can start transitions at any desired point in time.
     */
    fun at(timestamp: Long, builder: TransitionTestAssertionScope.() -> Unit)

    /**
     * Run the same assertion for all frames of a transition.
     *
     * @param totalFrames needs to be the exact number of frames of the transition that is run,
     *   otherwise the passed progress will be incorrect. That is the duration in ms divided by 16.
     * @param builder is passed a progress Float which can be used to calculate values for the
     *   specific frame. Or use [AutoTransitionTestAssertionScope.interpolate].
     */
    fun atAllFrames(totalFrames: Int, builder: AutoTransitionTestAssertionScope.(Float) -> Unit)

    /**
     * Assert on the state of the layout after the transition finished.
     *
     * This should be called maximum once, after [before] or [at] is called.
     */
    fun after(builder: TransitionTestAssertionScope.() -> Unit)
}

@TransitionTestDsl
interface TransitionTestAssertionScope : CoroutineScope {
    /**
     * Assert on [element].
     *
     * Note that presence/value assertions on the returned [SemanticsNodeInteraction] will fail if 0
     * or more than 1 elements matched [element]. If you need to assert on a shared element that
     * will be present multiple times in the layout during transitions, specify the [scene] in which
     * you are matching.
     */
    fun onElement(element: ElementKey, scene: SceneKey? = null): SemanticsNodeInteraction
}

interface AutoTransitionTestAssertionScope : TransitionTestAssertionScope {

    /** Linear interpolate [from] and [to] with the current progress of the transition. */
    fun <T> interpolate(from: T, to: T): T
}

val Default4FrameLinearTransition: TransitionBuilder.() -> Unit = {
    spec = tween(16 * 4, easing = LinearEasing)
}

/**
 * Test the transition between [fromSceneContent] and [toSceneContent] at different points in time.
 *
 * @sample com.android.compose.animation.scene.transformation.TranslateTest
 */
fun ComposeContentTestRule.testTransition(
    fromSceneContent: @Composable ContentScope.() -> Unit,
    toSceneContent: @Composable ContentScope.() -> Unit,
    transition: TransitionBuilder.() -> Unit = Default4FrameLinearTransition,
    layoutModifier: Modifier = Modifier,
    fromScene: SceneKey = TestScenes.SceneA,
    toScene: SceneKey = TestScenes.SceneB,
    changeState: CoroutineScope.(MutableSceneTransitionLayoutState) -> Unit = { state ->
        state.setTargetScene(toScene, animationScope = this)
    },
    builder: TransitionTestBuilder.() -> Unit,
) {
    testTransition(
        state = {
            rememberMutableSceneTransitionLayoutState(
                fromScene,
                transitions { from(fromScene, to = toScene, builder = transition) },
            )
        },
        changeState = changeState,
        transitionLayout = { state ->
            SceneTransitionLayout(state, layoutModifier, implicitTestTags = true) {
                scene(fromScene, content = fromSceneContent)
                scene(toScene, content = toSceneContent)
            }
        },
        builder = builder,
    )
}

/** Test the transition when showing [overlay] from [fromScene]. */
fun ComposeContentTestRule.testShowOverlayTransition(
    fromSceneContent: @Composable ContentScope.() -> Unit,
    overlayContent: @Composable ContentScope.() -> Unit,
    transition: TransitionBuilder.() -> Unit,
    fromScene: SceneKey = TestScenes.SceneA,
    overlay: OverlayKey = TestOverlays.OverlayA,
    builder: TransitionTestBuilder.() -> Unit,
) {
    testTransition(
        state = {
            rememberMutableSceneTransitionLayoutState(
                fromScene,
                transitions = transitions { from(fromScene, overlay, builder = transition) },
            )
        },
        transitionLayout = { state ->
            SceneTransitionLayout(state, implicitTestTags = true) {
                scene(fromScene) { fromSceneContent() }
                overlay(overlay) { overlayContent() }
            }
        },
        changeState = { state -> state.showOverlay(overlay, animationScope = this) },
        builder = builder,
    )
}

/** Test the transition when hiding [overlay] to [toScene]. */
fun ComposeContentTestRule.testHideOverlayTransition(
    toSceneContent: @Composable ContentScope.() -> Unit,
    overlayContent: @Composable ContentScope.() -> Unit,
    transition: TransitionBuilder.() -> Unit,
    toScene: SceneKey = TestScenes.SceneA,
    overlay: OverlayKey = TestOverlays.OverlayA,
    builder: TransitionTestBuilder.() -> Unit,
) {
    testTransition(
        state = {
            rememberMutableSceneTransitionLayoutState(
                toScene,
                initialOverlays = setOf(overlay),
                transitions = transitions { from(overlay, toScene, builder = transition) },
            )
        },
        transitionLayout = { state ->
            SceneTransitionLayout(state, implicitTestTags = true) {
                scene(toScene) { toSceneContent() }
                overlay(overlay) { overlayContent() }
            }
        },
        changeState = { state -> state.hideOverlay(overlay, animationScope = this) },
        builder = builder,
    )
}

/** Test the transition when replace [from] to [to]. */
fun ComposeContentTestRule.testReplaceOverlayTransition(
    fromContent: @Composable ContentScope.() -> Unit,
    toContent: @Composable ContentScope.() -> Unit,
    transition: TransitionBuilder.() -> Unit,
    currentSceneContent: @Composable ContentScope.() -> Unit = { Box(Modifier.fillMaxSize()) },
    fromAlignment: Alignment = Alignment.Center,
    toAlignment: Alignment = Alignment.Center,
    from: OverlayKey = TestOverlays.OverlayA,
    to: OverlayKey = TestOverlays.OverlayB,
    currentScene: SceneKey = TestScenes.SceneA,
    builder: TransitionTestBuilder.() -> Unit,
) {
    testTransition(
        state = {
            rememberMutableSceneTransitionLayoutState(
                currentScene,
                initialOverlays = setOf(from),
                transitions = transitions { from(from, to, builder = transition) },
            )
        },
        transitionLayout = { state ->
            SceneTransitionLayout(state, implicitTestTags = true) {
                scene(currentScene) { currentSceneContent() }
                overlay(from, alignment = fromAlignment) { fromContent() }
                overlay(to, alignment = toAlignment) { toContent() }
            }
        },
        changeState = { state -> state.replaceOverlay(from, to, animationScope = this) },
        builder = builder,
    )
}

data class TransitionRecordingSpec(
    val recordBefore: Boolean = true,
    val recordAfter: Boolean = true,
    val timeSeriesCapture: TimeSeriesCaptureScope<SemanticsNodeInteractionsProvider>.() -> Unit,
)

/** Captures the feature using [capture] on the [element]. */
fun TimeSeriesCaptureScope<SemanticsNodeInteractionsProvider>.featureOfElement(
    element: ElementKey,
    capture: FeatureCapture<SemanticsNode, *>,
    name: String = "${element.debugName}_${capture.name}",
) {
    feature(isElement(element), capture, name)
}

/** Records the transition between two scenes of [transitionLayout][SceneTransitionLayout]. */
fun MotionTestRule<ComposeToolkit>.recordTransition(
    fromSceneContent: @Composable ContentScope.() -> Unit,
    toSceneContent: @Composable ContentScope.() -> Unit,
    transition: TransitionBuilder.() -> Unit,
    recordingSpec: TransitionRecordingSpec,
    layoutModifier: Modifier = Modifier,
    fromScene: SceneKey = TestScenes.SceneA,
    toScene: SceneKey = TestScenes.SceneB,
): RecordedMotion {
    lateinit var state: MutableSceneTransitionLayoutState
    return recordMotion(
        content = { play ->
            state =
                rememberMutableSceneTransitionLayoutState(
                    fromScene,
                    transitions { from(fromScene, to = toScene, builder = transition) },
                )
            LaunchedEffect(play) {
                if (play) {
                    state.setTargetScene(toScene, animationScope = this)
                }
            }

            SceneTransitionLayout(state, layoutModifier, implicitTestTags = true) {
                scene(fromScene, content = fromSceneContent)
                scene(toScene, content = toSceneContent)
            }
        },
        ComposeRecordingSpec(
            MotionControl(delayRecording = { awaitCondition { state.isTransitioning() } }) {
                awaitCondition { !state.isTransitioning() }
            },
            recordBefore = recordingSpec.recordBefore,
            recordAfter = recordingSpec.recordAfter,
            timeSeriesCapture = recordingSpec.timeSeriesCapture,
        ),
    )
}

/** Test the transition from [state] to [to]. */
fun ComposeContentTestRule.testTransition(
    state: MutableSceneTransitionLayoutState,
    to: SceneKey,
    transitionLayout: @Composable (state: MutableSceneTransitionLayoutState) -> Unit,
    builder: TransitionTestBuilder.() -> Unit,
) {
    val currentScene = state.transitionState.currentScene
    check(currentScene != to) {
        "The 'to' scene (${to.debugName}) should be different from the state current scene " +
            "(${currentScene.debugName})"
    }

    testTransition(
        state = { state },
        changeState = { state -> state.setTargetScene(to, animationScope = this) },
        transitionLayout = transitionLayout,
        builder = builder,
    )
}

fun ComposeContentTestRule.testNestedTransition(
    states: List<MutableSceneTransitionLayoutState>,
    changeState: CoroutineScope.(states: List<MutableSceneTransitionLayoutState>) -> Unit,
    transitionLayout: @Composable (states: List<MutableSceneTransitionLayoutState>) -> Unit,
    builder: TransitionTestBuilder.() -> Unit,
) {
    testTransition(
        state = { states[0] },
        changeState = { changeState(states) },
        transitionLayout = { transitionLayout(states) },
        builder = builder,
    )
}

/** Test the transition from [state] to [to]. */
private fun ComposeContentTestRule.testTransition(
    state: @Composable () -> MutableSceneTransitionLayoutState,
    changeState: CoroutineScope.(MutableSceneTransitionLayoutState) -> Unit,
    transitionLayout: @Composable (state: MutableSceneTransitionLayoutState) -> Unit,
    builder: TransitionTestBuilder.() -> Unit,
) {
    lateinit var coroutineScope: CoroutineScope
    lateinit var layoutState: MutableSceneTransitionLayoutState
    setContent {
        layoutState = state()
        coroutineScope = rememberCoroutineScope()
        transitionLayout(layoutState)
    }

    val assertionScope =
        object : AutoTransitionTestAssertionScope, CoroutineScope by coroutineScope {

            var progress = 0f

            override fun onElement(
                element: ElementKey,
                scene: SceneKey?,
            ): SemanticsNodeInteraction {
                return onNode(isElement(element, scene))
            }

            override fun <T> interpolate(from: T, to: T): T {
                @Suppress("UNCHECKED_CAST")
                return when {
                    from is Float && to is Float -> lerp(from, to, progress)
                    from is Int && to is Int -> lerp(from, to, progress)
                    from is Long && to is Long -> lerp(from, to, progress)
                    from is Dp && to is Dp -> lerp(from, to, progress)
                    from is Scale && to is Scale ->
                        Scale(
                            lerp(from.scaleX, to.scaleX, progress),
                            lerp(from.scaleY, to.scaleY, progress),
                            interpolate(from.pivot, to.pivot),
                        )

                    from is Offset && to is Offset ->
                        Offset(lerp(from.x, to.x, progress), lerp(from.y, to.y, progress))

                    else ->
                        throw UnsupportedOperationException(
                            "Interpolation not supported for this type"
                        )
                }
                    as T
            }
        }

    // Wait for the UI to be idle then test the before state.
    waitForIdle()
    val test = transitionTest(builder)
    test.before(assertionScope)

    // Manually advance the clock to the start of the animation.
    mainClock.autoAdvance = false

    // Change the current scene.
    runOnUiThread { coroutineScope.changeState(layoutState) }
    waitForIdle()
    mainClock.advanceTimeByFrame()
    waitForIdle()

    var currentTime = 0L
    // Test the assertions at specific points in time.
    test.timestamps.forEach { tsAssertion ->
        if (tsAssertion.timestampDelta > 0L) {
            mainClock.advanceTimeBy(tsAssertion.timestampDelta)
            waitForIdle()
            currentTime += tsAssertion.timestampDelta.toInt()
        }

        assertionScope.progress = tsAssertion.progress
        try {
            tsAssertion.assertion(assertionScope, tsAssertion.progress)
        } catch (assertionError: AssertionError) {
            if (assertionScope.progress > 0) {
                throw AssertionError(
                    "Transition assertion failed at ${currentTime}ms " +
                        "at progress: ${assertionScope.progress}f",
                    assertionError,
                )
            }
            throw assertionError
        }
    }

    // Go to the end state and test it.
    mainClock.autoAdvance = true
    waitForIdle()
    test.after(assertionScope)
}

private fun transitionTest(builder: TransitionTestBuilder.() -> Unit): TransitionTest {
    // Collect the assertion lambdas in [TransitionTest]. Note that the ordering is forced by the
    // builder, e.g. `before {}` must be called before everything else, then `at {}` (in increasing
    // order of timestamp), then `after {}`. That way the test code is run with the same order as it
    // is written, to avoid confusion.

    val impl =
        object : TransitionTestBuilder {
                var before: (TransitionTestAssertionScope.() -> Unit)? = null
                var after: (TransitionTestAssertionScope.() -> Unit)? = null
                val timestamps = mutableListOf<TimestampAssertion>()

                private var currentTimestamp = 0L

                override fun before(builder: TransitionTestAssertionScope.() -> Unit) {
                    check(before == null) { "before {} must be called maximum once" }
                    check(after == null) { "before {} must be called before after {}" }
                    check(timestamps.isEmpty()) { "before {} must be called before at(...) {}" }

                    before = builder
                }

                override fun at(timestamp: Long, builder: TransitionTestAssertionScope.() -> Unit) {
                    check(after == null) { "at(...) {} must be called before after {}" }
                    check(timestamp >= currentTimestamp) {
                        "at(...) must be called with timestamps in increasing order"
                    }
                    check(timestamp % 16 == 0L) {
                        "timestamp must be a multiple of the frame time (16ms)"
                    }

                    val delta = timestamp - currentTimestamp
                    currentTimestamp = timestamp

                    timestamps.add(TimestampAssertion(delta, { builder() }, 0f))
                }

                override fun atAllFrames(
                    totalFrames: Int,
                    builder: AutoTransitionTestAssertionScope.(Float) -> Unit,
                ) {
                    check(after == null) { "atFrames(...) {} must be called before after {}" }
                    check(currentTimestamp == 0L) {
                        "atFrames(...) can't be called multiple times or after at(...)"
                    }

                    for (frame in 0 until totalFrames) {
                        val timestamp = frame * 16L
                        val delta = timestamp - currentTimestamp
                        val progress = frame.toFloat() / totalFrames
                        currentTimestamp = timestamp
                        timestamps.add(TimestampAssertion(delta, builder, progress))
                    }
                }

                override fun after(builder: TransitionTestAssertionScope.() -> Unit) {
                    check(after == null) { "after {} must be called maximum once" }
                    after = builder
                }
            }
            .apply(builder)

    return TransitionTest(
        before = impl.before ?: {},
        timestamps = impl.timestamps,
        after = impl.after ?: {},
    )
}

private class TransitionTest(
    val before: TransitionTestAssertionScope.() -> Unit,
    val after: TransitionTestAssertionScope.() -> Unit,
    val timestamps: List<TimestampAssertion>,
)

private class TimestampAssertion(
    val timestampDelta: Long,
    val assertion: AutoTransitionTestAssertionScope.(Float) -> Unit,
    val progress: Float,
)
