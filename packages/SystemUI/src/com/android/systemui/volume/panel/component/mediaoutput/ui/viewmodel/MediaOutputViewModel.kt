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

package com.android.systemui.volume.panel.component.mediaoutput.ui.viewmodel

import android.content.Context
import android.graphics.Color as GraphicsColor
import com.android.internal.logging.UiEventLogger
import com.android.systemui.Flags
import com.android.systemui.animation.Expandable
import com.android.systemui.common.shared.model.Color
import com.android.systemui.common.shared.model.Icon
import com.android.systemui.res.R
import com.android.systemui.volume.domain.model.AudioOutputDevice
import com.android.systemui.volume.panel.component.mediaoutput.domain.interactor.MediaOutputActionsInteractor
import com.android.systemui.volume.panel.component.mediaoutput.domain.interactor.MediaOutputComponentInteractor
import com.android.systemui.volume.panel.component.mediaoutput.domain.model.MediaOutputComponentModel
import com.android.systemui.volume.panel.dagger.scope.VolumePanelScope
import com.android.systemui.volume.panel.shared.model.Result
import com.android.systemui.volume.panel.shared.model.filterData
import com.android.systemui.volume.panel.ui.VolumePanelUiEvent
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

/** Models the UI of the Media Output Volume Panel component. */
@VolumePanelScope
class MediaOutputViewModel
@Inject
constructor(
    private val context: Context,
    @VolumePanelScope private val coroutineScope: CoroutineScope,
    private val actionsInteractor: MediaOutputActionsInteractor,
    private val mediaOutputComponentInteractor: MediaOutputComponentInteractor,
    private val uiEventLogger: UiEventLogger,
) {

    val connectedDeviceViewModel: StateFlow<ConnectedDeviceViewModel?> =
        mediaOutputComponentInteractor.mediaOutputModel
            .filterData()
            .map { mediaOutputModel ->
                val label =
                    when (mediaOutputModel) {
                        is MediaOutputComponentModel.Idle -> {
                            context.getString(R.string.media_output_title_without_playing)
                        }
                        is MediaOutputComponentModel.MediaSession -> {
                            if (mediaOutputModel.isPlaybackActive) {
                                context.getString(
                                    R.string.media_output_label_title,
                                    mediaOutputModel.session.appLabel,
                                )
                            } else {
                                context.getString(R.string.media_output_title_without_playing)
                            }
                        }
                        is MediaOutputComponentModel.Calling -> {
                            context.getString(R.string.media_output_title_ongoing_call)
                        }
                    }
                ConnectedDeviceViewModel(
                    label = label,
                    labelColor =
                        if (Flags.volumeRedesign()) {
                            Color.Resource(com.android.internal.R.color.materialColorOnSurface)
                        } else {
                            Color.Resource(
                                com.android.internal.R.color.materialColorOnSurfaceVariant
                            )
                        },
                    deviceName =
                        if (mediaOutputModel.isInAudioSharing) {
                            context.getString(R.string.audio_sharing_description)
                        } else {
                            mediaOutputModel.device
                                .takeIf { it !is AudioOutputDevice.Unknown }
                                ?.name ?: context.getString(R.string.media_seamless_other_device)
                        },
                    deviceNameColor =
                        if (mediaOutputModel.canOpenAudioSwitcher) {
                            Color.Resource(com.android.internal.R.color.materialColorOnSurface)
                        } else {
                            Color.Resource(
                                com.android.internal.R.color.materialColorOnSurfaceVariant
                            )
                        },
                )
            }
            .stateIn(coroutineScope, SharingStarted.Eagerly, null)

    val deviceIconViewModel: StateFlow<DeviceIconViewModel?> =
        mediaOutputComponentInteractor.mediaOutputModel
            .filterData()
            .map { mediaOutputModel ->
                val icon: Icon =
                    mediaOutputModel.device
                        .takeIf { it !is AudioOutputDevice.Unknown }
                        ?.icon
                        ?.let { Icon.Loaded(it, null) }
                        ?: Icon.Resource(R.drawable.ic_media_home_devices, null)
                val isPlaybackActive =
                    (mediaOutputModel as? MediaOutputComponentModel.MediaSession)
                        ?.isPlaybackActive == true
                val isCalling = mediaOutputModel is MediaOutputComponentModel.Calling
                if (isPlaybackActive || isCalling) {
                    DeviceIconViewModel.IsPlaying(
                        icon = icon,
                        iconColor =
                            if (mediaOutputModel.canOpenAudioSwitcher) {
                                if (Flags.volumeRedesign()) {
                                    Color.Resource(
                                        com.android.internal.R.color.materialColorOnPrimary
                                    )
                                } else {
                                    Color.Resource(
                                        com.android.internal.R.color.materialColorSurface
                                    )
                                }
                            } else {
                                Color.Resource(
                                    com.android.internal.R.color.materialColorSurfaceContainerHighest
                                )
                            },
                        backgroundColor =
                            if (mediaOutputModel.canOpenAudioSwitcher) {
                                if (Flags.volumeRedesign()) {
                                    Color.Resource(
                                        com.android.internal.R.color.materialColorPrimary
                                    )
                                } else {
                                    Color.Resource(
                                        com.android.internal.R.color.materialColorSecondary
                                    )
                                }
                            } else {
                                Color.Resource(com.android.internal.R.color.materialColorOutline)
                            },
                    )
                } else {
                    DeviceIconViewModel.IsNotPlaying(
                        icon = icon,
                        iconColor =
                            if (mediaOutputModel.canOpenAudioSwitcher) {
                                if (Flags.volumeRedesign()) {
                                    Color.Resource(
                                        com.android.internal.R.color.materialColorPrimary
                                    )
                                } else {
                                    Color.Resource(
                                        com.android.internal.R.color.materialColorOnSurfaceVariant
                                    )
                                }
                            } else {
                                Color.Resource(com.android.internal.R.color.materialColorOutline)
                            },
                        backgroundColor = Color.Loaded(GraphicsColor.TRANSPARENT),
                    )
                }
            }
            .stateIn(coroutineScope, SharingStarted.Eagerly, null)

    val enabled: StateFlow<Boolean> =
        mediaOutputComponentInteractor.mediaOutputModel
            .filterData()
            .map { it.canOpenAudioSwitcher }
            .stateIn(coroutineScope, SharingStarted.Eagerly, true)

    fun onBarClick(expandable: Expandable?) {
        uiEventLogger.log(VolumePanelUiEvent.VOLUME_PANEL_MEDIA_OUTPUT_CLICKED)
        val result: Result<MediaOutputComponentModel> =
            mediaOutputComponentInteractor.mediaOutputModel.value
        actionsInteractor.onBarClick(
            (result as? Result.Data<MediaOutputComponentModel>)?.data,
            expandable,
        )
    }
}
