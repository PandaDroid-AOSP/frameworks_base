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

package com.android.systemui.statusbar.chips.screenrecord.domain.interactor

import android.media.projection.StopReason
import com.android.systemui.Flags
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Application
import com.android.systemui.log.LogBuffer
import com.android.systemui.log.core.LogLevel
import com.android.systemui.mediaprojection.data.model.MediaProjectionState
import com.android.systemui.mediaprojection.data.repository.MediaProjectionRepository
import com.android.systemui.screenrecord.data.model.ScreenRecordModel
import com.android.systemui.screenrecord.data.repository.ScreenRecordRepository
import com.android.systemui.statusbar.chips.StatusBarChipLogTags.pad
import com.android.systemui.statusbar.chips.StatusBarChipsLog
import com.android.systemui.statusbar.chips.screenrecord.domain.model.ScreenRecordChipModel
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.transformLatest
import kotlinx.coroutines.launch

/** Interactor for the screen recording chip shown in the status bar. */
@SysUISingleton
class ScreenRecordChipInteractor
@Inject
constructor(
    @Application private val scope: CoroutineScope,
    private val screenRecordRepository: ScreenRecordRepository,
    private val mediaProjectionRepository: MediaProjectionRepository,
    @StatusBarChipsLog private val logger: LogBuffer,
) {
    /**
     * Emits true if we should assume that we're currently screen recording, even if
     * [ScreenRecordRepository.screenRecordState] hasn't emitted [ScreenRecordModel.Recording] yet.
     */
    private val shouldAssumeIsRecording: Flow<Boolean> =
        screenRecordRepository.screenRecordState
            .transformLatest {
                when (it) {
                    is ScreenRecordModel.DoingNothing -> {
                        emit(false)
                    }
                    is ScreenRecordModel.Starting -> {
                        // If we're told that the recording will start in [it.millisUntilStarted],
                        // optimistically assume the recording did indeed start after that time even
                        // if [ScreenRecordRepository.screenRecordState] hasn't emitted
                        // [ScreenRecordModel.Recording] yet. Start 50ms early so that the chip
                        // timer will definitely be showing by the time the recording actually
                        // starts - see b/366448907.
                        delay(it.millisUntilStarted - 50)
                        emit(true)
                    }
                    is ScreenRecordModel.Recording -> {}
                }
            }
            .stateIn(scope, SharingStarted.WhileSubscribed(), false)

    val screenRecordState: StateFlow<ScreenRecordChipModel> =
        // ScreenRecordRepository has the main "is the screen being recorded?" state, and
        // MediaProjectionRepository has information about what specifically is being recorded (a
        // single app or the entire screen)
        combine(
                screenRecordRepository.screenRecordState,
                mediaProjectionRepository.mediaProjectionState,
                shouldAssumeIsRecording,
            ) { screenRecordState, mediaProjectionState, shouldAssumeIsRecording ->
                if (
                    Flags.statusBarAutoStartScreenRecordChip() &&
                        shouldAssumeIsRecording &&
                        screenRecordState is ScreenRecordModel.Starting
                ) {
                    logger.log(
                        TAG,
                        LogLevel.INFO,
                        {},
                        {
                            "State: Recording(hostPackage=null, taskPackage=null) due to force-start"
                        },
                    )
                    ScreenRecordChipModel.Recording(hostPackage = null, recordedTask = null)
                } else {
                    when (screenRecordState) {
                        is ScreenRecordModel.DoingNothing -> {
                            logger.log(TAG, LogLevel.INFO, {}, { "State: DoingNothing" })
                            ScreenRecordChipModel.DoingNothing
                        }

                        is ScreenRecordModel.Starting -> {
                            logger.log(
                                TAG,
                                LogLevel.INFO,
                                { long1 = screenRecordState.millisUntilStarted },
                                { "State: Starting($long1)" },
                            )
                            ScreenRecordChipModel.Starting(screenRecordState.millisUntilStarted)
                        }

                        is ScreenRecordModel.Recording -> {
                            val recordedTask =
                                if (
                                    mediaProjectionState
                                        is MediaProjectionState.Projecting.SingleTask
                                ) {
                                    mediaProjectionState.task
                                } else {
                                    null
                                }
                            val hostPackage =
                                if (mediaProjectionState is MediaProjectionState.Projecting) {
                                    mediaProjectionState.hostPackage
                                } else {
                                    null
                                }
                            logger.log(
                                TAG,
                                LogLevel.INFO,
                                {
                                    str1 = hostPackage
                                    str2 = recordedTask?.baseIntent?.component?.packageName
                                },
                                { "State: Recording(hostPackage=$str1, taskPackage=$str2)" },
                            )
                            ScreenRecordChipModel.Recording(
                                hostPackage = hostPackage,
                                recordedTask = recordedTask,
                            )
                        }
                    }
                }
            }
            .stateIn(scope, SharingStarted.WhileSubscribed(), ScreenRecordChipModel.DoingNothing)

    /** Stops the recording. */
    fun stopRecording() {
        scope.launch { screenRecordRepository.stopRecording(StopReason.STOP_PRIVACY_CHIP) }
    }

    companion object {
        private val TAG = "ScreenRecord".pad()
    }
}
