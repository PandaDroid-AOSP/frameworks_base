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

package com.android.compose.animation.scene.content.state

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.AnimationVector1D
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.runtime.Stable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.android.compose.animation.scene.ContentKey
import com.android.compose.animation.scene.MutableSceneTransitionLayoutState
import com.android.compose.animation.scene.OverlayKey
import com.android.compose.animation.scene.ProgressVisibilityThreshold
import com.android.compose.animation.scene.SceneKey
import com.android.compose.animation.scene.SceneTransitionLayoutImpl
import com.android.compose.animation.scene.TransformationSpec
import com.android.compose.animation.scene.TransformationSpecImpl
import com.android.compose.animation.scene.TransitionKey
import com.android.internal.jank.Cuj.CujType
import com.android.mechanics.GestureContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

/** The state associated to a [SceneTransitionLayout] at some specific point in time. */
@Stable
sealed interface TransitionState {
    /**
     * The current effective scene. If a new scene transition was triggered, it would start from
     * this scene.
     *
     * For instance, when swiping from scene A to scene B, the [currentScene] is A when the swipe
     * gesture starts, but then if the user flings their finger and commits the transition to scene
     * B, then [currentScene] becomes scene B even if the transition is not finished yet and is
     * still animating to settle to scene B.
     */
    val currentScene: SceneKey

    /**
     * The current set of overlays. This represents the set of overlays that will be visible on
     * screen once all transitions are finished.
     *
     * @see MutableSceneTransitionLayoutState.showOverlay
     * @see MutableSceneTransitionLayoutState.hideOverlay
     * @see MutableSceneTransitionLayoutState.replaceOverlay
     */
    val currentOverlays: Set<OverlayKey>

    /** The scene [currentScene] is idle. */
    data class Idle(
        override val currentScene: SceneKey,
        override val currentOverlays: Set<OverlayKey> = emptySet(),
    ) : TransitionState

    sealed class Transition(
        val fromContent: ContentKey,
        val toContent: ContentKey,
        val replacedTransition: Transition? = null,
    ) : TransitionState {
        /** A transition animating between [fromScene] and [toScene]. */
        abstract class ChangeScene(
            /** The scene this transition is starting from. Can't be the same as toScene */
            val fromScene: SceneKey,

            /** The scene this transition is going to. Can't be the same as fromScene */
            val toScene: SceneKey,

            /** The transition that `this` transition is replacing, if any. */
            replacedTransition: Transition? = null,
        ) : Transition(fromScene, toScene, replacedTransition) {
            final override val currentOverlays: Set<OverlayKey>
                get() {
                    // The set of overlays does not change in a [ChangeCurrentScene] transition.
                    return currentOverlaysWhenTransitionStarted
                }

            override fun toString(): String {
                return "ChangeScene(fromScene=$fromScene, toScene=$toScene)"
            }
        }

        /**
         * A transition that is animating one or more overlays and for which [currentOverlays] will
         * change over the course of the transition.
         */
        sealed class OverlayTransition(
            fromContent: ContentKey,
            toContent: ContentKey,
            replacedTransition: Transition?,
        ) : Transition(fromContent, toContent, replacedTransition) {
            final override val currentScene: SceneKey
                get() {
                    // The current scene does not change during overlay transitions.
                    return currentSceneWhenTransitionStarted
                }

            // Note: We use deriveStateOf() so that the computed set is cached and reused when the
            // inputs of the computations don't change, to avoid recomputing and allocating a new
            // set every time currentOverlays is called (which is every frame and for each element).
            final override val currentOverlays: Set<OverlayKey> by derivedStateOf {
                computeCurrentOverlays()
            }

            protected abstract fun computeCurrentOverlays(): Set<OverlayKey>
        }

        /** The [overlay] is either showing from [fromOrToScene] or hiding into [fromOrToScene]. */
        abstract class ShowOrHideOverlay(
            val overlay: OverlayKey,
            val fromOrToScene: SceneKey,
            fromContent: ContentKey,
            toContent: ContentKey,
            replacedTransition: Transition? = null,
        ) : OverlayTransition(fromContent, toContent, replacedTransition) {
            /**
             * Whether [overlay] is effectively shown. For instance, this will be `false` when
             * starting a swipe transition to show [overlay] and will be `true` only once the swipe
             * transition is committed.
             */
            abstract val isEffectivelyShown: Boolean

            init {
                check(
                    (fromContent == fromOrToScene && toContent == overlay) ||
                        (fromContent == overlay && toContent == fromOrToScene)
                )
            }

            final override fun computeCurrentOverlays(): Set<OverlayKey> {
                return if (isEffectivelyShown) {
                    currentOverlaysWhenTransitionStarted + overlay
                } else {
                    currentOverlaysWhenTransitionStarted - overlay
                }
            }

            override fun toString(): String {
                val isShowing = overlay == toContent
                return "ShowOrHideOverlay(overlay=$overlay, fromOrToScene=$fromOrToScene, " +
                    "isShowing=$isShowing)"
            }
        }

        /** We are transitioning from [fromOverlay] to [toOverlay]. */
        abstract class ReplaceOverlay(
            val fromOverlay: OverlayKey,
            val toOverlay: OverlayKey,
            replacedTransition: Transition? = null,
        ) :
            OverlayTransition(
                fromContent = fromOverlay,
                toContent = toOverlay,
                replacedTransition,
            ) {
            /**
             * The current effective overlay, either [fromOverlay] or [toOverlay]. For instance,
             * this will be [fromOverlay] when starting a swipe transition that replaces
             * [fromOverlay] by [toOverlay] and will [toOverlay] once the swipe transition is
             * committed.
             */
            abstract val effectivelyShownOverlay: OverlayKey

            init {
                check(fromOverlay != toOverlay)
            }

            final override fun computeCurrentOverlays(): Set<OverlayKey> {
                return when (effectivelyShownOverlay) {
                    fromOverlay ->
                        computeCurrentOverlays(include = fromOverlay, exclude = toOverlay)
                    toOverlay -> computeCurrentOverlays(include = toOverlay, exclude = fromOverlay)
                    else ->
                        error(
                            "effectivelyShownOverlay=$effectivelyShownOverlay, should be " +
                                "equal to fromOverlay=$fromOverlay or toOverlay=$toOverlay"
                        )
                }
            }

            private fun computeCurrentOverlays(
                include: OverlayKey,
                exclude: OverlayKey,
            ): Set<OverlayKey> {
                return buildSet {
                    addAll(currentOverlaysWhenTransitionStarted)
                    remove(exclude)
                    add(include)
                }
            }

            override fun toString(): String {
                return "ReplaceOverlay(fromOverlay=$fromOverlay, toOverlay=$toOverlay)"
            }
        }

        /**
         * The current scene and overlays observed right when this transition started. These are set
         * when this transition is started in
         * [com.android.compose.animation.scene.MutableSceneTransitionLayoutStateImpl.startTransition].
         */
        internal lateinit var currentSceneWhenTransitionStarted: SceneKey
        internal lateinit var currentOverlaysWhenTransitionStarted: Set<OverlayKey>

        /**
         * The key of this transition. This should usually be null, but it can be specified to use a
         * specific set of transformations associated to this transition.
         */
        open val key: TransitionKey? = null

        /**
         * The progress of the transition. This is usually in the `[0; 1]` range, but it can also be
         * less than `0` or greater than `1` when using transitions with a spring AnimationSpec or
         * when flinging quickly during a swipe gesture.
         */
        abstract val progress: Float

        /** The current velocity of [progress], in progress units. */
        abstract val progressVelocity: Float

        /** Whether the transition was triggered by user input rather than being programmatic. */
        abstract val isInitiatedByUserInput: Boolean

        /** Whether user input is currently driving the transition. */
        abstract val isUserInputOngoing: Boolean

        /** Additional gesture context whenever the transition is driven by a user gesture. */
        abstract val gestureContext: GestureContext?

        /**
         * True when the transition reached the end and the progress won't be updated anymore.
         *
         * [isProgressStable] will be `true` before this [Transition] is completed while there are
         * still custom transition animations settling.
         */
        var isProgressStable: Boolean by mutableStateOf(false)
            private set

        /** The CUJ covered by this transition. */
        @CujType
        val cuj: Int?
            get() = _cuj

        /**
         * The progress of the preview transition. This is usually in the `[0; 1]` range, but it can
         * also be less than `0` or greater than `1` when using transitions with a spring
         * AnimationSpec or when flinging quickly during a swipe gesture.
         */
        internal open val previewProgress: Float = 0f

        /** The current velocity of [previewProgress], in progress units. */
        internal open val previewProgressVelocity: Float = 0f

        /** Whether the transition is currently in the preview stage */
        internal open val isInPreviewStage: Boolean = false

        /**
         * The current [TransformationSpecImpl] and other values associated to this transition from
         * the spec.
         *
         * Important: These will be set exactly once, when this transition is
         * [started][MutableSceneTransitionLayoutStateImpl.startTransition].
         */
        internal var transformationSpec: TransformationSpecImpl = TransformationSpec.Empty
        internal var previewTransformationSpec: TransformationSpecImpl? = null
        internal var _cuj: Int? = null

        /**
         * An animatable that animates from 1f to 0f. This will be used to nicely animate the sudden
         * jump of values when this transitions interrupts another one.
         */
        private var interruptionDecay: Animatable<Float, AnimationVector1D>? = null

        /**
         * The coroutine scope associated to this transition.
         *
         * This coroutine scope can be used to launch animations associated to this transition,
         * which will not finish until at least one animation/job is still running in the scope.
         *
         * Important: Make sure to never launch long-running jobs in this scope, otherwise the
         * transition will never be considered as finished.
         */
        internal val coroutineScope: CoroutineScope
            get() =
                _coroutineScope
                    ?: error(
                        "Transition.coroutineScope can only be accessed once the transition was " +
                            "started "
                    )

        private var _coroutineScope: CoroutineScope? = null

        init {
            check(fromContent != toContent)
            check(
                replacedTransition == null ||
                    (replacedTransition.fromContent == fromContent &&
                        replacedTransition.toContent == toContent)
            )
        }

        /**
         * Whether we are transitioning. If [from] or [to] is empty, we will also check that they
         * match the contents we are animating from and/or to.
         */
        fun isTransitioning(from: ContentKey? = null, to: ContentKey? = null): Boolean {
            return (from == null || fromContent == from) && (to == null || toContent == to)
        }

        /** Whether we are transitioning from [content] to [other], or from [other] to [content]. */
        fun isTransitioningBetween(content: ContentKey, other: ContentKey): Boolean {
            return isTransitioning(from = content, to = other) ||
                isTransitioning(from = other, to = content)
        }

        /** Whether we are transitioning from or to [content]. */
        fun isTransitioningFromOrTo(content: ContentKey): Boolean {
            return fromContent == content || toContent == content
        }

        /**
         * Return [progress] if [content] is equal to [toContent], `1f - progress` if [content] is
         * equal to [fromContent], and throw otherwise.
         */
        fun progressTo(content: ContentKey): Float {
            return when (content) {
                toContent -> progress
                fromContent -> 1f - progress
                else ->
                    throw IllegalArgumentException(
                        "content ($content) should be either toContent ($toContent) or " +
                            "fromContent ($fromContent)"
                    )
            }
        }

        /** Whether [fromContent] is effectively the current content of the transition. */
        internal fun isFromCurrentContent() = isCurrentContent(expectedFrom = true)

        /** Whether [toContent] is effectively the current content of the transition. */
        internal fun isToCurrentContent() = isCurrentContent(expectedFrom = false)

        private fun isCurrentContent(expectedFrom: Boolean): Boolean {
            val expectedContent = if (expectedFrom) fromContent else toContent
            return when (this) {
                is ChangeScene -> currentScene == expectedContent
                is ReplaceOverlay -> effectivelyShownOverlay == expectedContent
                is ShowOrHideOverlay -> isEffectivelyShown == (expectedContent == overlay)
            }
        }

        /** Run this transition and return once it is finished. */
        protected abstract suspend fun run()

        /**
         * Freeze this transition state so that neither [currentScene] nor [currentOverlays] will
         * change in the future, and animate the progress towards that state. For instance, a
         * [Transition.ChangeScene] should animate the progress to 0f if its [currentScene] is equal
         * to its [fromScene][Transition.ChangeScene.fromScene] or animate it to 1f if its equal to
         * its [toScene][Transition.ChangeScene.toScene].
         *
         * This is called when this transition is interrupted (replaced) by another transition.
         */
        abstract fun freezeAndAnimateToCurrentState()

        internal suspend fun runInternal() {
            check(_coroutineScope == null) { "A Transition can be started only once." }
            coroutineScope {
                _coroutineScope = this
                try {
                    run()
                } finally {
                    isProgressStable = true
                }
            }
        }

        internal open fun interruptionProgress(layoutImpl: SceneTransitionLayoutImpl): Float {
            if (replacedTransition != null) {
                return replacedTransition.interruptionProgress(layoutImpl)
            }

            fun create(): Animatable<Float, AnimationVector1D> {
                val animatable = Animatable(1f, visibilityThreshold = ProgressVisibilityThreshold)
                layoutImpl.animationScope.launch {
                    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
                    animatable.animateTo(
                        targetValue = 0f,
                        // Quickly animate (use fast) the current transition and without bounces
                        // (use effects). A new transition will start soon.
                        animationSpec = layoutImpl.state.motionScheme.fastEffectsSpec(),
                    )
                }

                return animatable
            }

            val animatable = interruptionDecay ?: create().also { interruptionDecay = it }
            return animatable.value
        }
    }

    companion object {
        const val DistanceUnspecified = 0f
    }
}
