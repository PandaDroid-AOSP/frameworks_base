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

package com.android.systemui.volume.panel.component.volume.domain.interactor

import android.media.AudioManager
import com.android.settingslib.volume.data.repository.AudioSystemRepository
import com.android.settingslib.volume.domain.interactor.AudioModeInteractor
import com.android.settingslib.volume.shared.model.AudioStream
import com.android.systemui.Flags
import com.android.systemui.volume.domain.interactor.AudioSharingInteractor
import com.android.systemui.volume.panel.component.mediaoutput.domain.interactor.MediaOutputInteractor
import com.android.systemui.volume.panel.component.mediaoutput.shared.model.MediaDeviceSession
import com.android.systemui.volume.panel.component.mediaoutput.shared.model.isTheSameSession
import com.android.systemui.volume.panel.component.volume.domain.model.SliderType
import com.android.systemui.volume.panel.dagger.scope.VolumePanelScope
import com.android.systemui.volume.panel.shared.model.filterData
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combineTransform
import kotlinx.coroutines.flow.stateIn

/** Provides volume sliders to show in the Volume Panel. */
@VolumePanelScope
class AudioSlidersInteractor
@Inject
constructor(
    @VolumePanelScope scope: CoroutineScope,
    mediaOutputInteractor: MediaOutputInteractor,
    audioModeInteractor: AudioModeInteractor,
    private val audioSystemRepository: AudioSystemRepository,
    audioSharingInteractor: AudioSharingInteractor,
) {

    val volumePanelSliders: StateFlow<List<SliderType>> =
        combineTransform(
                mediaOutputInteractor.activeMediaDeviceSessions,
                mediaOutputInteractor.defaultActiveMediaSession.filterData(),
                audioModeInteractor.isOngoingCall,
                audioSharingInteractor.volume,
            ) { activeSessions, defaultSession, isOngoingCall, audioSharingVolume ->
                coroutineScope {
                    val viewModels = buildList {
                        if (isOngoingCall) {
                            addStream(AudioManager.STREAM_VOICE_CALL)
                        }

                        if (defaultSession?.isTheSameSession(activeSessions.remote) == true) {
                            addSession(activeSessions.remote)
                            addStream(AudioManager.STREAM_MUSIC)
                            if (Flags.showAudioSharingSliderInVolumePanel()) {
                                audioSharingVolume?.let { addAudioSharingStream() }
                            }
                        } else {
                            addStream(AudioManager.STREAM_MUSIC)
                            if (Flags.showAudioSharingSliderInVolumePanel()) {
                                audioSharingVolume?.let { addAudioSharingStream() }
                            }
                            addSession(activeSessions.remote)
                        }

                        if (!isOngoingCall) {
                            addStream(AudioManager.STREAM_VOICE_CALL)
                        }

                        addStream(AudioManager.STREAM_RING)
                        addStream(AudioManager.STREAM_NOTIFICATION)
                        addStream(AudioManager.STREAM_ALARM)
                    }
                    emit(viewModels)
                }
            }
            .stateIn(scope, SharingStarted.Eagerly, emptyList())

    private fun MutableList<SliderType>.addSession(remoteMediaDeviceSession: MediaDeviceSession?) {
        if (remoteMediaDeviceSession?.canAdjustVolume == true) {
            add(SliderType.MediaDeviceCast(remoteMediaDeviceSession))
        }
    }

    private fun MutableList<SliderType>.addStream(stream: Int) {
        // Hide other streams except STREAM_MUSIC if the isSingleVolume mode is on. This makes sure
        // the volume slider in volume panel is consistent with the volume slider inside system
        // settings app.
        if (
            Flags.onlyShowMediaStreamSliderInSingleVolumeMode() &&
                audioSystemRepository.isSingleVolume &&
                stream != AudioManager.STREAM_MUSIC
        ) {
            return
        }

        add(SliderType.Stream(AudioStream(stream)))
    }

    private fun MutableList<SliderType>.addAudioSharingStream() {
        add(SliderType.AudioSharingStream)
    }
}
