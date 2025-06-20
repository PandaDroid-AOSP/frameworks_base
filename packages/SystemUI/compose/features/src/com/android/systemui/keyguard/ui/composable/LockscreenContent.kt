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

package com.android.systemui.keyguard.ui.composable

import android.view.View
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import com.android.compose.animation.scene.ContentScope
import com.android.internal.jank.Cuj
import com.android.internal.jank.Cuj.CujType
import com.android.internal.jank.InteractionJankMonitor
import com.android.systemui.compose.modifiers.sysuiResTag
import com.android.systemui.keyguard.domain.interactor.KeyguardClockInteractor
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.transition.KeyguardTransitionAnimationCallback
import com.android.systemui.keyguard.ui.composable.blueprint.ComposableLockscreenSceneBlueprint
import com.android.systemui.keyguard.ui.viewmodel.LockscreenContentViewModel
import com.android.systemui.lifecycle.rememberViewModel
import com.android.systemui.notifications.ui.composable.NotificationLockscreenScrim
import com.android.systemui.statusbar.notification.stack.ui.viewmodel.NotificationLockscreenScrimViewModel

/**
 * Renders the content of the lockscreen.
 *
 * This is separate from the [LockscreenScene] because it's meant to support usage of this UI from
 * outside the scene container framework.
 */
class LockscreenContent(
    private val viewModelFactory: LockscreenContentViewModel.Factory,
    private val notificationScrimViewModelFactory: NotificationLockscreenScrimViewModel.Factory,
    private val blueprints: Set<@JvmSuppressWildcards ComposableLockscreenSceneBlueprint>,
    private val clockInteractor: KeyguardClockInteractor,
    private val interactionJankMonitor: InteractionJankMonitor,
) {
    private val blueprintByBlueprintId: Map<String, ComposableLockscreenSceneBlueprint> by lazy {
        blueprints.associateBy { it.id }
    }

    @Composable
    fun ContentScope.Content(modifier: Modifier = Modifier) {
        val view = LocalView.current
        val viewModel =
            rememberViewModel("LockscreenContent-viewModel") {
                viewModelFactory.create(
                    keyguardTransitionAnimationCallback =
                        KeyguardTransitionAnimationCallbackImpl(view, interactionJankMonitor)
                )
            }
        val notificationLockscreenScrimViewModel =
            rememberViewModel("LockscreenContent-scrimViewModel") {
                notificationScrimViewModelFactory.create()
            }
        if (!viewModel.isContentVisible) {
            // If the content isn't supposed to be visible, show a large empty box as it's needed
            // for scene transition animations (can't just skip rendering everything or shared
            // elements won't have correct final/initial bounds from animating in and out of the
            // lockscreen scene).
            Box(modifier)
            return
        }

        DisposableEffect(view) {
            clockInteractor.clockEventController.registerListeners(view)

            onDispose { clockInteractor.clockEventController.unregisterListeners() }
        }

        val blueprint = blueprintByBlueprintId[viewModel.blueprintId] ?: return
        with(blueprint) {
            Content(viewModel, modifier.sysuiResTag("keyguard_root_view"))
            NotificationLockscreenScrim(notificationLockscreenScrimViewModel)
        }
    }
}

private class KeyguardTransitionAnimationCallbackImpl(
    private val view: View,
    private val interactionJankMonitor: InteractionJankMonitor,
) : KeyguardTransitionAnimationCallback {

    override fun onAnimationStarted(from: KeyguardState, to: KeyguardState) {
        cujOrNull(from, to)?.let { cuj -> interactionJankMonitor.begin(view, cuj) }
    }

    override fun onAnimationEnded(from: KeyguardState, to: KeyguardState) {
        cujOrNull(from, to)?.let { cuj -> interactionJankMonitor.end(cuj) }
    }

    override fun onAnimationCanceled(from: KeyguardState, to: KeyguardState) {
        cujOrNull(from, to)?.let { cuj -> interactionJankMonitor.cancel(cuj) }
    }

    @CujType
    private fun cujOrNull(from: KeyguardState, to: KeyguardState): Int? {
        return when {
            from == KeyguardState.AOD -> Cuj.CUJ_LOCKSCREEN_TRANSITION_FROM_AOD
            to == KeyguardState.AOD -> Cuj.CUJ_LOCKSCREEN_TRANSITION_TO_AOD
            else -> null
        }
    }
}
