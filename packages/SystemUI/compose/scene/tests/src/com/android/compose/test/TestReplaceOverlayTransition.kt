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

package com.android.compose.test

import com.android.compose.animation.scene.OverlayKey
import com.android.compose.animation.scene.SceneTransitionLayoutImpl
import com.android.compose.animation.scene.content.state.TransitionState.Transition
import com.android.mechanics.GestureContext
import kotlinx.coroutines.CompletableDeferred

/** A [Transition.ShowOrHideOverlay] for tests that will be finished once [finish] is called. */
abstract class TestReplaceOverlayTransition(
    fromOverlay: OverlayKey,
    toOverlay: OverlayKey,
    replacedTransition: Transition?,
) :
    Transition.ReplaceOverlay(
        fromOverlay = fromOverlay,
        toOverlay = toOverlay,
        replacedTransition = replacedTransition,
    ) {
    private val finishCompletable = CompletableDeferred<Unit>()

    override suspend fun run() {
        finishCompletable.await()
    }

    /** Finish this transition. */
    fun finish() {
        finishCompletable.complete(Unit)
    }
}

/** A utility to easily create a [TestReplaceOverlayTransition] in tests. */
fun transition(
    from: OverlayKey,
    to: OverlayKey,
    effectivelyShownOverlay: () -> OverlayKey = { to },
    progress: () -> Float = { 0f },
    progressVelocity: () -> Float = { 0f },
    previewProgress: () -> Float = { 0f },
    previewProgressVelocity: () -> Float = { 0f },
    isInPreviewStage: () -> Boolean = { false },
    interruptionProgress: () -> Float = { 0f },
    isInitiatedByUserInput: Boolean = false,
    isUserInputOngoing: Boolean = false,
    onFreezeAndAnimate: ((TestReplaceOverlayTransition) -> Unit)? = null,
    replacedTransition: Transition? = null,
): TestReplaceOverlayTransition {
    return object : TestReplaceOverlayTransition(from, to, replacedTransition) {
        override val effectivelyShownOverlay: OverlayKey
            get() = effectivelyShownOverlay()

        override val progress: Float
            get() = progress()

        override val progressVelocity: Float
            get() = progressVelocity()

        override val previewProgress: Float
            get() = previewProgress()

        override val previewProgressVelocity: Float
            get() = previewProgressVelocity()

        override val isInPreviewStage: Boolean
            get() = isInPreviewStage()

        override val isInitiatedByUserInput: Boolean = isInitiatedByUserInput
        override val isUserInputOngoing: Boolean = isUserInputOngoing
        override val gestureContext: GestureContext? = null

        override fun freezeAndAnimateToCurrentState() {
            if (onFreezeAndAnimate != null) {
                onFreezeAndAnimate(this)
            } else {
                finish()
            }
        }

        override fun interruptionProgress(layoutImpl: SceneTransitionLayoutImpl): Float {
            return interruptionProgress()
        }
    }
}
