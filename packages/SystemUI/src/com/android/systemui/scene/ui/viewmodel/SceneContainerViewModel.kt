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

package com.android.systemui.scene.ui.viewmodel

import android.view.MotionEvent
import android.view.View
import androidx.compose.runtime.getValue
import androidx.compose.ui.unit.dp
import com.android.app.tracing.coroutines.launchTraced as launch
import com.android.compose.animation.scene.ContentKey
import com.android.compose.animation.scene.DefaultEdgeDetector
import com.android.compose.animation.scene.ObservableTransitionState
import com.android.compose.animation.scene.OverlayKey
import com.android.compose.animation.scene.SceneKey
import com.android.compose.animation.scene.SwipeSourceDetector
import com.android.compose.animation.scene.UserAction
import com.android.compose.animation.scene.UserActionResult
import com.android.systemui.classifier.Classifier
import com.android.systemui.classifier.domain.interactor.FalsingInteractor
import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor
import com.android.systemui.keyguard.ui.viewmodel.AodBurnInViewModel
import com.android.systemui.keyguard.ui.viewmodel.KeyguardClockViewModel
import com.android.systemui.keyguard.ui.viewmodel.LightRevealScrimViewModel
import com.android.systemui.lifecycle.ExclusiveActivatable
import com.android.systemui.lifecycle.Hydrator
import com.android.systemui.power.domain.interactor.PowerInteractor
import com.android.systemui.scene.domain.interactor.SceneInteractor
import com.android.systemui.scene.shared.logger.SceneLogger
import com.android.systemui.scene.shared.model.Overlays
import com.android.systemui.scene.shared.model.Scenes
import com.android.systemui.scene.ui.composable.Overlay
import com.android.systemui.shade.domain.interactor.ShadeModeInteractor
import com.android.systemui.shade.shared.model.ShadeMode
import com.android.systemui.statusbar.domain.interactor.RemoteInputInteractor
import com.android.systemui.statusbar.notification.stack.ui.view.SharedNotificationContainer
import com.android.systemui.wallpapers.ui.viewmodel.WallpaperViewModel
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map

/** Models UI state for the scene container. */
class SceneContainerViewModel
@AssistedInject
constructor(
    private val sceneInteractor: SceneInteractor,
    private val falsingInteractor: FalsingInteractor,
    private val powerInteractor: PowerInteractor,
    shadeModeInteractor: ShadeModeInteractor,
    private val remoteInputInteractor: RemoteInputInteractor,
    private val logger: SceneLogger,
    hapticsViewModelFactory: SceneContainerHapticsViewModel.Factory,
    val lightRevealScrim: LightRevealScrimViewModel,
    val wallpaperViewModel: WallpaperViewModel,
    keyguardInteractor: KeyguardInteractor,
    val burnIn: AodBurnInViewModel,
    val clock: KeyguardClockViewModel,
    @Assisted view: View,
    @Assisted private val motionEventHandlerReceiver: (MotionEventHandler?) -> Unit,
) : ExclusiveActivatable() {

    /** The scene that should be rendered. */
    val currentScene: StateFlow<SceneKey> = sceneInteractor.currentScene

    private val hydrator = Hydrator("SceneContainerViewModel.hydrator")

    /** Whether the container is visible. */
    val isVisible: Boolean by hydrator.hydratedStateOf("isVisible", sceneInteractor.isVisible)

    val allContentKeys: List<ContentKey> = sceneInteractor.allContentKeys

    val hapticsViewModel: SceneContainerHapticsViewModel = hapticsViewModelFactory.create(view)

    /**
     * The [SwipeSourceDetector] to use for defining which areas of the screen can be defined in the
     * [UserAction]s for this container.
     */
    val swipeSourceDetector: SwipeSourceDetector by
        hydrator.hydratedStateOf(
            traceName = "swipeSourceDetector",
            initialValue = DefaultEdgeDetector,
            source =
                shadeModeInteractor.shadeMode.map {
                    if (it is ShadeMode.Dual) {
                        SceneContainerSwipeDetector(edgeSize = 40.dp)
                    } else {
                        DefaultEdgeDetector
                    }
                },
        )

    /** Amount of color saturation for the Flexi🥃 ribbon. */
    val ribbonColorSaturation: Float by
        hydrator.hydratedStateOf(
            traceName = "ribbonColorSaturation",
            source = keyguardInteractor.dozeAmount.map { 1 - it },
            initialValue = 1f,
        )

    override suspend fun onActivated(): Nothing {
        try {
            // Sends a MotionEventHandler to the owner of the view-model so they can report
            // MotionEvents into the view-model.
            motionEventHandlerReceiver(
                object : MotionEventHandler {
                    override fun onMotionEvent(motionEvent: MotionEvent) {
                        this@SceneContainerViewModel.onMotionEvent(motionEvent)
                    }

                    override fun onEmptySpaceMotionEvent(motionEvent: MotionEvent) {
                        this@SceneContainerViewModel.onEmptySpaceMotionEvent(motionEvent)
                    }

                    override fun onMotionEventComplete() {
                        this@SceneContainerViewModel.onMotionEventComplete()
                    }
                }
            )

            coroutineScope {
                launch { hydrator.activate() }
                launch("SceneContainerHapticsViewModel") { hapticsViewModel.activate() }
            }
            awaitCancellation()
        } finally {
            // Clears the previously-sent MotionEventHandler so the owner of the view-model releases
            // their reference to it.
            motionEventHandlerReceiver(null)
        }
    }

    /**
     * Binds the given flow so the system remembers it.
     *
     * Note that you must call this with `null` when the UI is done or risk a memory leak.
     */
    fun setTransitionState(transitionState: Flow<ObservableTransitionState>?) {
        sceneInteractor.setTransitionState(transitionState)
    }

    /**
     * Notifies that a [MotionEvent] is first seen at the top of the scene container UI. This
     * includes gestures on [SharedNotificationContainer] as well as the Composable scene container
     * hierarchy.
     *
     * Call this before the [MotionEvent] starts to propagate through the UI hierarchy.
     */
    fun onMotionEvent(event: MotionEvent) {
        powerInteractor.onUserTouch()
        falsingInteractor.onTouchEvent(event)
        if (
            event.actionMasked == MotionEvent.ACTION_UP ||
                event.actionMasked == MotionEvent.ACTION_CANCEL
        ) {
            sceneInteractor.onUserInputFinished()
        }
    }

    /**
     * Notifies that a [MotionEvent] has propagated through the entire [SharedNotificationContainer]
     * and Composable scene container hierarchy without being handled.
     *
     * Call this after the [MotionEvent] has finished propagating through the UI hierarchy.
     */
    fun onEmptySpaceMotionEvent(event: MotionEvent) {
        // check if the touch is outside the window and if remote input is active.
        // If true, close any active remote inputs.
        if (
            event.action == MotionEvent.ACTION_OUTSIDE &&
                (remoteInputInteractor.isRemoteInputActive as StateFlow).value
        ) {
            remoteInputInteractor.closeRemoteInputs()
        }
    }

    /**
     * Notifies that a scene container user interaction has begun.
     *
     * This is a user interaction that has reached the Composable hierarchy of the scene container,
     * rather than being handled by [SharedNotificationContainer].
     */
    fun onSceneContainerUserInputStarted() {
        sceneInteractor.onSceneContainerUserInputStarted()
    }

    /**
     * Notifies that a [MotionEvent] that was previously sent to [onMotionEvent] has passed through
     * the scene container UI.
     *
     * Call this after the [MotionEvent] propagates completely through the UI hierarchy.
     */
    fun onMotionEventComplete() {
        falsingInteractor.onMotionEventComplete()
    }

    /**
     * Returns `true` if a change to [toScene] is currently allowed; `false` otherwise.
     *
     * This is invoked only for user-initiated transitions. The goal is to check with the falsing
     * system whether the change from the current scene to the given scene should be rejected due to
     * it being a false touch.
     */
    fun canChangeScene(toScene: SceneKey): Boolean {
        return isInteractionAllowedByFalsing(toScene).also { sceneChangeAllowed ->
            if (sceneChangeAllowed) {
                // A scene change is guaranteed; log it.
                logger.logSceneChanged(
                    from = currentScene.value,
                    to = toScene,
                    sceneState = null,
                    reason = "user interaction",
                    isInstant = false,
                )
            } else {
                logger.logSceneChangeRejection(
                    from = currentScene.value,
                    to = toScene,
                    originalChangeReason = null,
                    rejectionReason = "Falsing: false touch detected",
                )
            }
        }
    }

    /**
     * Returns `true` if showing the [newlyShown] overlay is currently allowed; `false` otherwise.
     *
     * This is invoked only for user-initiated transitions. The goal is to check with the falsing
     * system whether the overlay change should be rejected due to it being a false touch.
     */
    fun canShowOrReplaceOverlay(
        newlyShown: OverlayKey,
        beingReplaced: OverlayKey? = null,
    ): Boolean {
        return isInteractionAllowedByFalsing(newlyShown).also {
            // An overlay change is guaranteed; log it.
            logger.logOverlayChangeRequested(
                from = beingReplaced,
                to = newlyShown,
                reason = "user interaction",
            )
        }
    }

    /**
     * Immediately resolves any scene families present in [actionResultMap] to their current
     * resolution target.
     */
    fun resolveSceneFamilies(
        actionResultMap: Map<UserAction, UserActionResult>
    ): Map<UserAction, UserActionResult> {
        return actionResultMap.mapValues { (_, actionResult) ->
            when (actionResult) {
                is UserActionResult.ChangeScene -> {
                    sceneInteractor.resolveSceneFamilyOrNull(actionResult.toScene)?.value?.let {
                        toScene ->
                        UserActionResult(
                            toScene = toScene,
                            transitionKey = actionResult.transitionKey,
                            requiresFullDistanceSwipe = actionResult.requiresFullDistanceSwipe,
                        )
                    }
                }
                // Overlay transitions don't use scene families, nothing to resolve.
                is UserActionResult.ShowOverlay,
                is UserActionResult.HideOverlay,
                is UserActionResult.ReplaceByOverlay -> null
            } ?: actionResult
        }
    }

    /**
     * Returns the [ContentKey] whose user actions should be active.
     *
     * @param overlayByKey Mapping of [Overlay] by [OverlayKey], ordered by z-order such that the
     *   last overlay is rendered on top of all other overlays.
     */
    fun getActionableContentKey(
        currentScene: SceneKey,
        currentOverlays: Set<OverlayKey>,
        overlayByKey: Map<OverlayKey, Overlay>,
    ): ContentKey {
        // Overlay actions take precedence over scene actions.
        return when (currentOverlays.size) {
            // No overlays, the scene is actionable.
            0 -> currentScene
            // Small optimization for the most common case.
            1 -> currentOverlays.first()
            // Find the top-most overlay by z-index.
            else ->
                checkNotNull(overlayByKey.asSequence().findLast { it.key in currentOverlays }?.key)
        }
    }

    /**
     * Returns a filtered version of [unfiltered], without action-result entries that would navigate
     * to disabled scenes.
     */
    fun filteredUserActions(
        unfiltered: Flow<Map<UserAction, UserActionResult>>
    ): Flow<Map<UserAction, UserActionResult>> {
        return sceneInteractor.filteredUserActions(unfiltered)
    }

    /**
     * Returns `true` if transitioning to [content] is permissible by the falsing system; `false`
     * otherwise.
     */
    private fun isInteractionAllowedByFalsing(content: ContentKey): Boolean {
        val interactionTypeOrNull =
            when (content) {
                Overlays.Bouncer -> Classifier.BOUNCER_UNLOCK
                Scenes.Gone -> Classifier.UNLOCK
                Scenes.Shade,
                Overlays.NotificationsShade -> Classifier.NOTIFICATION_DRAG_DOWN
                Scenes.QuickSettings,
                Overlays.QuickSettingsShade -> Classifier.QUICK_SETTINGS
                else -> null
            }

        return interactionTypeOrNull?.let { interactionType ->
            // It's important that the falsing system is always queried, even if no enforcement
            // will occur. This helps build up the right signal in the system.
            val isFalseTouch = falsingInteractor.isFalseTouch(interactionType)

            // Only enforce falsing if moving from the lockscreen scene to new content.
            val fromLockscreenScene = currentScene.value == Scenes.Lockscreen

            !fromLockscreenScene || !isFalseTouch
        } ?: true
    }

    /** Defines interface for classes that can handle externally-reported [MotionEvent]s. */
    interface MotionEventHandler {
        /** Notifies that a [MotionEvent] has occurred. */
        fun onMotionEvent(motionEvent: MotionEvent)

        /** Notifies that a [MotionEvent] has occurred outside the root window. */
        fun onEmptySpaceMotionEvent(motionEvent: MotionEvent)

        /**
         * Notifies that the previous [MotionEvent] reported by [onMotionEvent] has finished
         * processing.
         */
        fun onMotionEventComplete()
    }

    @AssistedFactory
    interface Factory {
        fun create(
            view: View,
            motionEventHandlerReceiver: (MotionEventHandler?) -> Unit,
        ): SceneContainerViewModel
    }
}
