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

import android.app.StatusBarManager
import android.graphics.Point
import android.util.Log
import android.util.MathUtils
import com.android.systemui.bouncer.data.repository.KeyguardBouncerRepository
import com.android.systemui.common.shared.model.NotificationContainerBounds
import com.android.systemui.common.ui.domain.interactor.ConfigurationInteractor
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Application
import com.android.systemui.keyguard.data.repository.KeyguardRepository
import com.android.systemui.keyguard.shared.model.BiometricUnlockModel
import com.android.systemui.keyguard.shared.model.CameraLaunchSourceModel
import com.android.systemui.keyguard.shared.model.CameraLaunchType
import com.android.systemui.keyguard.shared.model.DozeStateModel
import com.android.systemui.keyguard.shared.model.DozeStateModel.Companion.isDozeOff
import com.android.systemui.keyguard.shared.model.DozeTransitionModel
import com.android.systemui.keyguard.shared.model.Edge
import com.android.systemui.keyguard.shared.model.KeyguardState
import com.android.systemui.keyguard.shared.model.KeyguardState.ALTERNATE_BOUNCER
import com.android.systemui.keyguard.shared.model.KeyguardState.AOD
import com.android.systemui.keyguard.shared.model.KeyguardState.DOZING
import com.android.systemui.keyguard.shared.model.KeyguardState.GLANCEABLE_HUB
import com.android.systemui.keyguard.shared.model.KeyguardState.GONE
import com.android.systemui.keyguard.shared.model.KeyguardState.LOCKSCREEN
import com.android.systemui.keyguard.shared.model.KeyguardState.OCCLUDED
import com.android.systemui.keyguard.shared.model.StatusBarState
import com.android.systemui.log.table.TableLogBuffer
import com.android.systemui.log.table.logDiffsForTable
import com.android.systemui.res.R
import com.android.systemui.scene.domain.interactor.SceneInteractor
import com.android.systemui.scene.shared.flag.SceneContainerFlag
import com.android.systemui.scene.shared.model.Scenes
import com.android.systemui.shade.ShadeDisplayAware
import com.android.systemui.shade.data.repository.ShadeRepository
import com.android.systemui.util.kotlin.Utils.Companion.sample as sampleCombine
import com.android.systemui.util.kotlin.sample
import com.android.systemui.wallpapers.data.repository.WallpaperFocalAreaRepository
import javax.inject.Inject
import javax.inject.Provider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.combineTransform
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.transform

/**
 * Encapsulates business-logic related to the keyguard but not to a more specific part within it.
 */
@SysUISingleton
class KeyguardInteractor
@Inject
constructor(
    private val repository: KeyguardRepository,
    bouncerRepository: KeyguardBouncerRepository,
    private val wallpaperFocalAreaRepository: WallpaperFocalAreaRepository,
    @ShadeDisplayAware configurationInteractor: ConfigurationInteractor,
    shadeRepository: ShadeRepository,
    private val keyguardTransitionInteractor: KeyguardTransitionInteractor,
    sceneInteractorProvider: Provider<SceneInteractor>,
    private val fromGoneTransitionInteractor: Provider<FromGoneTransitionInteractor>,
    private val fromLockscreenTransitionInteractor: Provider<FromLockscreenTransitionInteractor>,
    private val fromOccludedTransitionInteractor: Provider<FromOccludedTransitionInteractor>,
    private val fromAlternateBouncerTransitionInteractor:
        Provider<FromAlternateBouncerTransitionInteractor>,
    @Application applicationScope: CoroutineScope,
) {
    // TODO(b/296118689): move to a repository
    private val _notificationPlaceholderBounds = MutableStateFlow(NotificationContainerBounds())

    /** Bounds of the notification container. */
    val notificationContainerBounds: StateFlow<NotificationContainerBounds> by lazy {
        SceneContainerFlag.assertInLegacyMode()
        combineTransform(
                _notificationPlaceholderBounds,
                keyguardTransitionInteractor.isInTransition(
                    edge = Edge.create(from = LOCKSCREEN, to = AOD)
                ),
                shadeRepository.isShadeLayoutWide,
                configurationInteractor.dimensionPixelSize(R.dimen.keyguard_split_shade_top_margin),
            ) { bounds, isTransitioningToAod, useSplitShade, keyguardSplitShadeTopMargin ->
                if (isTransitioningToAod) {
                    // Keep bounds stable during this transition, to prevent cases like smartspace
                    // popping in and adjusting the bounds. A prime example would be media playing,
                    // which then updates smartspace on transition to AOD.
                    return@combineTransform
                }

                // We offset the placeholder bounds by the configured top margin to account for
                // legacy placement behavior within notifications for splitshade.
                emit(
                    if (useSplitShade) {
                        bounds.copy(bottom = bounds.bottom - keyguardSplitShadeTopMargin)
                    } else {
                        bounds
                    }
                )
            }
            .stateIn(
                scope = applicationScope,
                started = SharingStarted.WhileSubscribed(),
                initialValue = NotificationContainerBounds(),
            )
    }

    fun setNotificationContainerBounds(position: NotificationContainerBounds) {
        SceneContainerFlag.assertInLegacyMode()
        _notificationPlaceholderBounds.value = position
    }

    /** Whether the system is in doze mode. */
    val isDozing: StateFlow<Boolean> = repository.isDozing

    /** Receive an event for doze time tick */
    val dozeTimeTick: Flow<Long> = repository.dozeTimeTick

    /** Whether Always-on Display mode is available. */
    val isAodAvailable: StateFlow<Boolean> = repository.isAodAvailable

    /**
     * The amount of doze the system is in, where `1.0` is fully dozing and `0.0` is not dozing at
     * all.
     */
    val dozeAmount: Flow<Float> =
        if (SceneContainerFlag.isEnabled) {
            isAodAvailable.flatMapLatest { isAodAvailable ->
                if (isAodAvailable) {
                    keyguardTransitionInteractor.transitionValue(AOD)
                } else {
                    keyguardTransitionInteractor.transitionValue(DOZING)
                }
            }
        } else {
            repository.linearDozeAmount
        }

    /** Doze transition information. */
    val dozeTransitionModel: Flow<DozeTransitionModel> = repository.dozeTransitionModel

    val isPulsing: Flow<Boolean> = dozeTransitionModel.map { it.to == DozeStateModel.DOZE_PULSING }

    /** Whether the system is dreaming with an overlay active */
    val isDreamingWithOverlay: Flow<Boolean> = repository.isDreamingWithOverlay

    /**
     * Whether the system is dreaming. [KeyguardRepository.isDreaming] will be always be true when
     * [isDozing] is true, but not vice-versa. Also accounts for [isDreamingWithOverlay].
     */
    val isDreaming: StateFlow<Boolean> =
        merge(repository.isDreaming, repository.isDreamingWithOverlay)
            .stateIn(
                scope = applicationScope,
                started = SharingStarted.Eagerly,
                initialValue = false,
            )

    /** Whether any dreaming is running, including the doze dream. */
    val isDreamingAny: Flow<Boolean> = repository.isDreaming

    /** Event for when the camera gesture is detected */
    val onCameraLaunchDetected: Flow<CameraLaunchSourceModel> =
        repository.onCameraLaunchDetected.filter { it.type != CameraLaunchType.IGNORE }

    /** Event for when an unlocked keyguard has been requested, such as on device fold */
    val showDismissibleKeyguard: Flow<Long> = repository.showDismissibleKeyguard.asStateFlow()

    /**
     * Dozing and dreaming have overlapping events. If the doze state remains in FINISH, it means
     * that doze mode is not running and DREAMING is ok to commence.
     *
     * Allow a brief moment to prevent rapidly oscillating between true/false signals. The amount of
     * time is [IS_ABLE_TO_DREAM_DELAY_MS] - consumers should consider waiting for that long before
     * examining the value of this flow, to let other consumers have enough time to also see that
     * same new value.
     */
    @OptIn(FlowPreview::class)
    val isAbleToDream: Flow<Boolean> =
        dozeTransitionModel
            .flatMapLatest { dozeTransitionModel ->
                if (isDozeOff(dozeTransitionModel.to)) {
                    // When dozing stops, it is a very early signal that the device is exiting the
                    // dream state. DreamManagerService eventually notifies window manager, which
                    // invokes SystemUI through KeyguardService. Because of this substantial delay,
                    // do not immediately process any dreaming information when exiting AOD. It
                    // should actually be quite strange to leave AOD and then go straight to
                    // DREAMING so this should be fine.
                    delay(IS_ABLE_TO_DREAM_DELAY_MS)
                    isDreaming.debounce(50L)
                } else {
                    flowOf(false)
                }
            }
            .stateIn(
                scope = applicationScope,
                started = SharingStarted.WhileSubscribed(),
                initialValue = false,
            )

    /** Whether the keyguard is showing or not. */
    @Deprecated("Use KeyguardTransitionInteractor + KeyguardState")
    val isKeyguardShowing: StateFlow<Boolean> = repository.isKeyguardShowing

    /** Whether the keyguard is dismissible or not. */
    val isKeyguardDismissible: StateFlow<Boolean> = repository.isKeyguardDismissible

    /** Whether the keyguard is occluded (covered by an activity). */
    @Deprecated("Use KeyguardTransitionInteractor + KeyguardState.OCCLUDED")
    val isKeyguardOccluded: StateFlow<Boolean> = repository.isKeyguardOccluded

    /** Whether the keyguard is going away. */
    @Deprecated("Use KeyguardTransitionInteractor + KeyguardState.GONE")
    val isKeyguardGoingAway: StateFlow<Boolean> = repository.isKeyguardGoingAway.asStateFlow()

    /** Keyguard can be clipped at the top as the shade is dragged */
    val topClippingBounds: Flow<Int?> by lazy {
        combineTransform(
                keyguardTransitionInteractor
                    .transitionValue(content = Scenes.Gone, stateWithoutSceneContainer = GONE)
                    .map { it == 1f }
                    .onStart { emit(false) }
                    .distinctUntilChanged(),
                repository.topClippingBounds,
            ) { isGone, topClippingBounds ->
                if (!isGone) {
                    emit(topClippingBounds)
                }
            }
            .distinctUntilChanged()
    }

    /** Last point that [KeyguardRootView] view was tapped */
    val lastRootViewTapPosition: Flow<Point?> = repository.lastRootViewTapPosition.asStateFlow()

    /** Is the ambient indication area visible? */
    val ambientIndicationVisible: Flow<Boolean> = repository.ambientIndicationVisible.asStateFlow()

    /** Whether the primary bouncer is showing or not. */
    @JvmField val primaryBouncerShowing: StateFlow<Boolean> = bouncerRepository.primaryBouncerShow

    /** Whether the alternate bouncer is showing or not. */
    val alternateBouncerShowing: Flow<Boolean> =
        bouncerRepository.alternateBouncerVisible.sample(isAbleToDream) {
            alternateBouncerVisible,
            isAbleToDream ->
            if (isAbleToDream) {
                // If the alternate bouncer will show over a dream, it is likely that the dream has
                // requested a dismissal, which will stop the dream. By delaying this slightly, the
                // DREAMING->LOCKSCREEN transition will now happen first, followed by
                // LOCKSCREEN->ALTERNATE_BOUNCER.
                delay(600L)
            }
            alternateBouncerVisible
        }

    /** Observable for the [StatusBarState] */
    val statusBarState: StateFlow<StatusBarState> = repository.statusBarState

    /** Observable for [BiometricUnlockModel] when biometrics are used to unlock the device. */
    val biometricUnlockState: StateFlow<BiometricUnlockModel> = repository.biometricUnlockState

    /** Keyguard is present and is not occluded. */
    val isKeyguardVisible: Flow<Boolean> =
        combine(isKeyguardShowing, isKeyguardOccluded) { showing, occluded -> showing && !occluded }

    /**
     * Event types that affect whether secure camera is active. Only used by [isSecureCameraActive].
     */
    private enum class SecureCameraRelatedEventType {
        KeyguardBecameVisible,
        PrimaryBouncerBecameVisible,
        SecureCameraLaunched,
    }

    /** Whether camera is launched over keyguard. */
    val isSecureCameraActive: Flow<Boolean> =
        merge(
                onCameraLaunchDetected
                    .filter { it.type == CameraLaunchType.POWER_DOUBLE_TAP }
                    .map { SecureCameraRelatedEventType.SecureCameraLaunched },
                isKeyguardVisible
                    .filter { it }
                    .map { SecureCameraRelatedEventType.KeyguardBecameVisible },
                primaryBouncerShowing
                    .filter { it }
                    .map { SecureCameraRelatedEventType.PrimaryBouncerBecameVisible },
            )
            .map {
                when (it) {
                    SecureCameraRelatedEventType.SecureCameraLaunched -> true
                    // When secure camera is closed, either the keyguard or the primary bouncer will
                    // have to show, so those events tell us that secure camera is no longer active.
                    SecureCameraRelatedEventType.KeyguardBecameVisible -> false
                    SecureCameraRelatedEventType.PrimaryBouncerBecameVisible -> false
                }
            }
            .onStart { emit(false) }
            .distinctUntilChanged()

    /** The approximate location on the screen of the fingerprint sensor, if one is available. */
    val fingerprintSensorLocation: Flow<Point?> = repository.fingerprintSensorLocation

    /** The approximate location on the screen of the face unlock sensor, if one is available. */
    val faceSensorLocation: Flow<Point?> = repository.faceSensorLocation

    /** Temporary shim for fading out content when the brightness slider is used */
    @Deprecated("SceneContainer uses NotificationStackAppearanceInteractor")
    val panelAlpha: StateFlow<Float> = repository.panelAlpha.asStateFlow()

    /** Sets the zoom out scale of spatial model pushback from e.g. pulling down the shade. */
    val zoomOut: StateFlow<Float> = repository.zoomOut

    /**
     * When the lockscreen can be dismissed, emit an alpha value as the user swipes up. This is
     * useful just before the code commits to moving to GONE.
     *
     * This uses legacyShadeExpansion to process swipe up events. In the future, the touch input
     * signal should be sent directly to transitions.
     */
    val dismissAlpha: Flow<Float> =
        shadeRepository.legacyShadeExpansion
            .sampleCombine(
                keyguardTransitionInteractor.currentKeyguardState,
                keyguardTransitionInteractor.transitionState,
                isKeyguardDismissible,
                keyguardTransitionInteractor.isFinishedIn(Scenes.Communal, GLANCEABLE_HUB),
            )
            .filter { (_, _, step, _, _) -> !step.transitionState.isTransitioning() }
            .transform {
                (
                    legacyShadeExpansion,
                    currentKeyguardState,
                    step,
                    isKeyguardDismissible,
                    onGlanceableHub) ->
                if (
                    statusBarState.value == StatusBarState.KEYGUARD &&
                        isKeyguardDismissible &&
                        currentKeyguardState == LOCKSCREEN &&
                        legacyShadeExpansion != 1f
                ) {
                    emit(MathUtils.constrainedMap(0f, 1f, 0.82f, 1f, legacyShadeExpansion))
                } else if (
                    !onGlanceableHub &&
                        isKeyguardDismissible &&
                        (legacyShadeExpansion == 0f || legacyShadeExpansion == 1f)
                ) {
                    // Resets alpha state
                    emit(1f)
                }
            }
            .onStart { emit(1f) }
            .distinctUntilChanged()

    val keyguardTranslationY: Flow<Float> =
        configurationInteractor
            .dimensionPixelSize(R.dimen.keyguard_translate_distance_on_swipe_up)
            .flatMapLatest { translationDistance ->
                combineTransform(
                    shadeRepository.legacyShadeExpansion.onStart { emit(0f) },
                    keyguardTransitionInteractor.transitionValue(GONE).onStart { emit(0f) },
                ) { legacyShadeExpansion, goneValue ->
                    val isLegacyShadeInResetPosition =
                        legacyShadeExpansion == 0f || legacyShadeExpansion == 1f
                    if (goneValue == 1f || (goneValue == 0f && isLegacyShadeInResetPosition)) {
                        // Reset the translation value
                        emit(0f)
                    } else if (!isLegacyShadeInResetPosition) {
                        // On swipe up, translate the keyguard to reveal the bouncer, OR a GONE
                        // transition is running, which means this is a swipe to dismiss. Values of
                        // 0f and 1f need to be ignored in the legacy shade expansion. These can
                        // flip arbitrarily as the legacy shade is reset, and would cause the
                        // translation value to jump around unexpectedly.
                        emit(MathUtils.lerp(translationDistance, 0, legacyShadeExpansion))
                    }
                }
            }
            .stateIn(
                scope = applicationScope,
                started = SharingStarted.WhileSubscribed(),
                initialValue = 0f,
            )

    /** Whether to animate the next doze mode transition. */
    val animateDozingTransitions: Flow<Boolean> by lazy {
        if (SceneContainerFlag.isEnabled) {
            sceneInteractorProvider
                .get()
                .transitioningTo
                .map { it == Scenes.Lockscreen }
                .distinctUntilChanged()
                .flatMapLatest { isTransitioningToLockscreenScene ->
                    if (isTransitioningToLockscreenScene) {
                        flowOf(false)
                    } else {
                        repository.animateBottomAreaDozingTransitions
                    }
                }
        } else {
            repository.animateBottomAreaDozingTransitions
        }
    }

    /** Which keyguard state to use when the device goes to sleep. */
    val asleepKeyguardState: StateFlow<KeyguardState> =
        repository.isAodAvailable
            .map { aodAvailable -> if (aodAvailable) AOD else DOZING }
            .stateIn(applicationScope, SharingStarted.Eagerly, DOZING)

    /**
     * Whether the primary authentication is required for the given user due to lockdown or
     * encryption after reboot.
     */
    val isEncryptedOrLockdown: Flow<Boolean> = repository.isEncryptedOrLockdown

    fun dozeTransitionTo(vararg states: DozeStateModel): Flow<DozeTransitionModel> {
        return dozeTransitionModel.filter { states.contains(it.to) }
    }

    fun isKeyguardShowing(): Boolean {
        return repository.isKeyguardShowing()
    }

    private fun cameraLaunchSourceIntToType(value: Int): CameraLaunchType {
        return when (value) {
            StatusBarManager.CAMERA_LAUNCH_SOURCE_WIGGLE -> CameraLaunchType.WIGGLE
            StatusBarManager.CAMERA_LAUNCH_SOURCE_POWER_DOUBLE_TAP ->
                CameraLaunchType.POWER_DOUBLE_TAP
            StatusBarManager.CAMERA_LAUNCH_SOURCE_LIFT_TRIGGER -> CameraLaunchType.LIFT_TRIGGER
            StatusBarManager.CAMERA_LAUNCH_SOURCE_QUICK_AFFORDANCE ->
                CameraLaunchType.QUICK_AFFORDANCE
            else -> throw IllegalArgumentException("Invalid CameraLaunchType value: $value")
        }
    }

    /** Sets whether quick settings or quick-quick settings is visible. */
    fun setQuickSettingsVisible(isVisible: Boolean) {
        repository.setQuickSettingsVisible(isVisible)
    }

    fun setPanelAlpha(alpha: Float) {
        repository.setPanelAlpha(alpha)
    }

    fun setZoomOut(zoomOutFromShadeRadius: Float) {
        repository.setZoomOut(zoomOutFromShadeRadius)
    }

    fun setAnimateDozingTransitions(animate: Boolean) {
        repository.setAnimateDozingTransitions(animate)
    }

    fun setLastRootViewTapPosition(point: Point?) {
        repository.lastRootViewTapPosition.value = point
    }

    fun setAmbientIndicationVisible(isVisible: Boolean) {
        repository.ambientIndicationVisible.value = isVisible
    }

    fun keyguardDoneAnimationsFinished() {
        repository.keyguardDoneAnimationsFinished()
    }

    fun setTopClippingBounds(top: Int?) {
        repository.topClippingBounds.value = top
    }

    fun setDreaming(isDreaming: Boolean) {
        repository.setDreaming(isDreaming)
    }

    /** Temporary shim, until [KeyguardWmStateRefactor] is enabled */
    fun showKeyguard() {
        fromGoneTransitionInteractor.get().showKeyguard()
    }

    /** Temporary shim, until [KeyguardWmStateRefactor] is enabled */
    fun showGlanceableHub(): Boolean {
        return fromGoneTransitionInteractor.get().showGlanceableHub()
    }

    /** Temporary shim, until [KeyguardWmStateRefactor] is enabled */
    fun dismissKeyguard() {
        when (keyguardTransitionInteractor.transitionState.value.to) {
            LOCKSCREEN -> fromLockscreenTransitionInteractor.get().dismissKeyguard()
            OCCLUDED -> fromOccludedTransitionInteractor.get().dismissFromOccluded()
            ALTERNATE_BOUNCER ->
                fromAlternateBouncerTransitionInteractor.get().dismissAlternateBouncer()
            else -> Log.v(TAG, "Keyguard was dismissed, no direct transition call needed")
        }
    }

    fun onCameraLaunchDetected(source: Int) {
        repository.onCameraLaunchDetected.value =
            CameraLaunchSourceModel(type = cameraLaunchSourceIntToType(source))
    }

    fun showDismissibleKeyguard() {
        repository.showDismissibleKeyguard()
    }

    fun setShortcutAbsoluteTop(top: Float) {
        wallpaperFocalAreaRepository.setShortcutAbsoluteTop(top)
    }

    fun setIsKeyguardGoingAway(isGoingAway: Boolean) {
        repository.isKeyguardGoingAway.value = isGoingAway
    }

    fun setNotificationStackAbsoluteBottom(bottom: Float) {
        wallpaperFocalAreaRepository.setNotificationStackAbsoluteBottom(bottom)
    }

    suspend fun hydrateTableLogBuffer(tableLogBuffer: TableLogBuffer) {
        isDozing
            .logDiffsForTable(
                tableLogBuffer = tableLogBuffer,
                columnName = "isDozing",
                initialValue = isDozing.value,
            )
            .collect()
    }

    companion object {
        private const val TAG = "KeyguardInteractor"
        /**
         * Amount of time that [KeyguardInteractor.isAbleToDream] is delayed; consumers of that flow
         * should consider waiting this amount of time before check the value of this flow, to let
         * other consumers have enough time to see the new value.
         */
        const val IS_ABLE_TO_DREAM_DELAY_MS = 500L
    }
}
