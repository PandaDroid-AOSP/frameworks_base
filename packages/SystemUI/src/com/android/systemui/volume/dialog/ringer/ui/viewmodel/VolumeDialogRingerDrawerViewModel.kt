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

package com.android.systemui.volume.dialog.ringer.ui.viewmodel

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager.RINGER_MODE_NORMAL
import android.media.AudioManager.RINGER_MODE_SILENT
import android.media.AudioManager.RINGER_MODE_VIBRATE
import android.media.AudioManager.STREAM_RING
import android.os.VibrationEffect
import android.widget.Toast
import com.android.internal.R as internalR
import com.android.internal.logging.UiEventLogger
import com.android.settingslib.Utils
import com.android.settingslib.notification.domain.interactor.NotificationsSoundPolicyInteractor
import com.android.settingslib.volume.shared.model.AudioStream
import com.android.settingslib.volume.shared.model.RingerMode
import com.android.systemui.dagger.qualifiers.Application
import com.android.systemui.dagger.qualifiers.Background
import com.android.systemui.res.R
import com.android.systemui.statusbar.VibratorHelper
import com.android.systemui.statusbar.policy.ConfigurationController
import com.android.systemui.statusbar.policy.onConfigChanged
import com.android.systemui.util.time.SystemClock
import com.android.systemui.volume.Events
import com.android.systemui.volume.dialog.dagger.scope.VolumeDialog
import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogScope
import com.android.systemui.volume.dialog.domain.interactor.VolumeDialogVisibilityInteractor
import com.android.systemui.volume.dialog.ringer.domain.VolumeDialogRingerInteractor
import com.android.systemui.volume.dialog.ringer.shared.model.VolumeDialogRingerModel
import com.android.systemui.volume.dialog.shared.VolumeDialogLogger
import com.android.systemui.volume.dialog.ui.VolumeDialogUiEvent
import javax.inject.Inject
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

private const val DRAWER_STATE_ANIMATION_DURATION = 400L
private const val SHOW_RINGER_TOAST_COUNT = 12

@VolumeDialogScope
class VolumeDialogRingerDrawerViewModel
@Inject
constructor(
    @Application private val applicationContext: Context,
    @VolumeDialog private val coroutineScope: CoroutineScope,
    @Background private val backgroundDispatcher: CoroutineDispatcher,
    soundPolicyInteractor: NotificationsSoundPolicyInteractor,
    private val ringerInteractor: VolumeDialogRingerInteractor,
    private val vibrator: VibratorHelper,
    private val volumeDialogLogger: VolumeDialogLogger,
    private val visibilityInteractor: VolumeDialogVisibilityInteractor,
    configurationController: ConfigurationController,
    private val uiEventLogger: UiEventLogger,
    private val systemClock: SystemClock,
) {

    private val drawerState = MutableStateFlow<RingerDrawerState>(RingerDrawerState.Initial)
    private val orientation: StateFlow<Int> =
        configurationController.onConfigChanged
            .map { it.orientation }
            .stateIn(
                coroutineScope,
                SharingStarted.Eagerly,
                applicationContext.resources.configuration.orientation,
            )

    val ringerViewModel: StateFlow<RingerViewModelState> =
        combine(
                soundPolicyInteractor.isZenMuted(AudioStream(STREAM_RING)),
                ringerInteractor.ringerModel,
                drawerState,
                orientation,
            ) { isZenMuted, ringerModel, state, orientation ->
                level = ringerModel.level
                levelMax = ringerModel.levelMax
                ringerModel.toViewModel(state, isZenMuted, orientation)
            }
            .flowOn(backgroundDispatcher)
            .stateIn(coroutineScope, SharingStarted.Eagerly, RingerViewModelState.Unavailable)

    // Level and Maximum level of Ring Stream.
    private var level = -1
    private var levelMax = -1

    // Vibration attributes.
    private val sonificiationVibrationAttributes =
        AudioAttributes.Builder()
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .setUsage(AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
            .build()

    private var lastClickTime = 0L

    init {
        ringerViewModel
            .onEach { viewModelState ->
                when (viewModelState) {
                    is RingerViewModelState.Available ->
                        volumeDialogLogger.onRingerDrawerAvailable(
                            viewModelState.uiModel.availableButtons.map { it.ringerMode }
                        )
                    is RingerViewModelState.Unavailable ->
                        volumeDialogLogger.onRingerDrawerUnavailable()
                }
            }
            .launchIn(coroutineScope)
    }

    fun onRingerButtonClicked(ringerMode: RingerMode, isSelectedButton: Boolean = false) {
        val currentTime = systemClock.currentTimeMillis()
        if (currentTime - lastClickTime < DRAWER_STATE_ANIMATION_DURATION) return
        lastClickTime = currentTime
        if (drawerState.value is RingerDrawerState.Open && !isSelectedButton) {
            Events.writeEvent(Events.EVENT_RINGER_TOGGLE, ringerMode.value)
            volumeDialogLogger.onRingerModeChanged(ringerMode)
            provideTouchFeedback(ringerMode)
            maybeShowToast(ringerMode)
            ringerInteractor.setRingerMode(ringerMode)
            ringerMode.toVolumeDialogUiEvent()?.let(uiEventLogger::log)
        }
        visibilityInteractor.resetDismissTimeout()
        drawerState.value =
            when (drawerState.value) {
                is RingerDrawerState.Initial -> {
                    RingerDrawerState.Open(ringerMode)
                }
                is RingerDrawerState.Open -> {
                    RingerDrawerState.Closed(
                        ringerMode,
                        (drawerState.value as RingerDrawerState.Open).mode,
                    )
                }
                is RingerDrawerState.Closed -> {
                    RingerDrawerState.Open(ringerMode)
                }
            }
    }

    private fun provideTouchFeedback(ringerMode: RingerMode) {
        when (ringerMode.value) {
            RINGER_MODE_NORMAL -> {
                ringerInteractor.scheduleTouchFeedback()
                null
            }
            RINGER_MODE_SILENT -> VibrationEffect.get(VibrationEffect.EFFECT_CLICK)
            RINGER_MODE_VIBRATE -> VibrationEffect.get(VibrationEffect.EFFECT_DOUBLE_CLICK)
            else -> VibrationEffect.get(VibrationEffect.EFFECT_DOUBLE_CLICK)
        }?.let { vibrator.vibrate(it, sonificiationVibrationAttributes) }
    }

    private fun VolumeDialogRingerModel.toViewModel(
        drawerState: RingerDrawerState,
        isZenMuted: Boolean,
        orientation: Int,
    ): RingerViewModelState {
        val currentIndex = availableModes.indexOf(currentRingerMode)
        if (currentIndex == -1) {
            volumeDialogLogger.onCurrentRingerModeIsUnsupported(currentRingerMode)
        }
        return if (currentIndex == -1 || isSingleVolume) {
            RingerViewModelState.Unavailable
        } else {
            toButtonViewModel(currentRingerMode, isZenMuted, isSelectedButton = true)?.let {
                RingerViewModelState.Available(
                    RingerViewModel(
                        availableButtons =
                            availableModes.mapNotNull { mode ->
                                toButtonViewModel(mode, isZenMuted)
                            },
                        currentButtonIndex = currentIndex,
                        selectedButton = it,
                        drawerState = drawerState,
                    ),
                    orientation,
                )
            } ?: RingerViewModelState.Unavailable
        }
    }

    private fun VolumeDialogRingerModel.toButtonViewModel(
        ringerMode: RingerMode,
        isZenMuted: Boolean,
        isSelectedButton: Boolean = false,
    ): RingerButtonViewModel? {
        return when (ringerMode.value) {
            RINGER_MODE_SILENT ->
                RingerButtonViewModel(
                    imageResId = R.drawable.ic_speaker_mute,
                    contentDescriptionResId =
                        if (isSelectedButton) {
                            R.string.volume_ringer_status_silent
                        } else {
                            R.string.volume_ringer_hint_mute
                        },
                    hintLabelResId = R.string.volume_ringer_hint_unmute,
                    ringerMode = ringerMode,
                )
            RINGER_MODE_VIBRATE ->
                RingerButtonViewModel(
                    imageResId = R.drawable.ic_volume_ringer_vibrate,
                    contentDescriptionResId =
                        if (isSelectedButton) {
                            R.string.volume_ringer_status_vibrate
                        } else {
                            R.string.volume_ringer_hint_vibrate
                        },
                    hintLabelResId = R.string.volume_ringer_hint_vibrate,
                    ringerMode = ringerMode,
                )
            RINGER_MODE_NORMAL ->
                when {
                    isMuted && !isZenMuted ->
                        RingerButtonViewModel(
                            imageResId =
                                if (isSelectedButton) {
                                    R.drawable.ic_speaker_mute
                                } else {
                                    R.drawable.ic_speaker_on
                                },
                            contentDescriptionResId =
                                if (isSelectedButton) {
                                    R.string.volume_ringer_status_normal
                                } else {
                                    R.string.volume_ringer_hint_unmute
                                },
                            hintLabelResId = R.string.volume_ringer_hint_unmute,
                            ringerMode = ringerMode,
                        )
                    availableModes.contains(RingerMode(RINGER_MODE_VIBRATE)) ->
                        RingerButtonViewModel(
                            imageResId = R.drawable.ic_speaker_on,
                            contentDescriptionResId =
                                if (isSelectedButton) {
                                    R.string.volume_ringer_status_normal
                                } else {
                                    R.string.volume_ringer_hint_unmute
                                },
                            hintLabelResId = R.string.volume_ringer_hint_vibrate,
                            ringerMode = ringerMode,
                        )
                    else ->
                        RingerButtonViewModel(
                            imageResId = R.drawable.ic_speaker_on,
                            contentDescriptionResId =
                                if (isSelectedButton) {
                                    R.string.volume_ringer_status_normal
                                } else {
                                    R.string.volume_ringer_hint_unmute
                                },
                            hintLabelResId = R.string.volume_ringer_hint_mute,
                            ringerMode = ringerMode,
                        )
                }
            else -> null
        }
    }

    private fun maybeShowToast(ringerMode: RingerMode) {
        coroutineScope.launch {
            val seenToastCount = ringerInteractor.getToastCount()
            if (seenToastCount > SHOW_RINGER_TOAST_COUNT) {
                return@launch
            }

            val toastText =
                when (ringerMode.value) {
                    RINGER_MODE_NORMAL -> {
                        if (level != -1 && levelMax != -1) {
                            applicationContext.getString(
                                R.string.volume_dialog_ringer_guidance_ring,
                                Utils.formatPercentage(level.toLong(), levelMax.toLong()),
                            )
                        } else {
                            null
                        }
                    }
                    RINGER_MODE_SILENT ->
                        applicationContext.getString(
                            internalR.string.volume_dialog_ringer_guidance_silent
                        )
                    RINGER_MODE_VIBRATE ->
                        applicationContext.getString(
                            internalR.string.volume_dialog_ringer_guidance_vibrate
                        )
                    else ->
                        applicationContext.getString(
                            internalR.string.volume_dialog_ringer_guidance_vibrate
                        )
                }
            toastText?.let { Toast.makeText(applicationContext, it, Toast.LENGTH_SHORT).show() }
            ringerInteractor.updateToastCount(seenToastCount)
        }
    }
}

private fun RingerMode.toVolumeDialogUiEvent(): VolumeDialogUiEvent? {
    return when (value) {
        RINGER_MODE_NORMAL -> VolumeDialogUiEvent.RINGER_MODE_NORMAL
        RINGER_MODE_VIBRATE -> VolumeDialogUiEvent.RINGER_MODE_VIBRATE
        RINGER_MODE_SILENT -> VolumeDialogUiEvent.RINGER_MODE_SILENT
        else -> null
    }
}
