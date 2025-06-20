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

package com.android.systemui.mediaprojection.data.repository

import android.app.ActivityManager
import android.media.projection.StopReason
import com.android.systemui.mediaprojection.data.model.MediaProjectionState
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow

class FakeMediaProjectionRepository : MediaProjectionRepository {
    override suspend fun switchProjectedTask(task: ActivityManager.RunningTaskInfo) {}

    override val mediaProjectionState: MutableStateFlow<MediaProjectionState> =
        MutableStateFlow(MediaProjectionState.NotProjecting)

    private val _projectionStartedDuringCallAndActivePostCallEvent = MutableSharedFlow<Unit>()

    override val projectionStartedDuringCallAndActivePostCallEvent: Flow<Unit> =
        _projectionStartedDuringCallAndActivePostCallEvent

    var stopProjectingInvoked = false

    override suspend fun stopProjecting(@StopReason stopReason: Int) {
        stopProjectingInvoked = true
    }

    suspend fun emitProjectionStartedDuringCallAndActivePostCallEvent() {
        _projectionStartedDuringCallAndActivePostCallEvent.emit(Unit)
    }
}
