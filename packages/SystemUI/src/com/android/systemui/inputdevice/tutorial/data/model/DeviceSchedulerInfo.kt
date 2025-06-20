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

package com.android.systemui.inputdevice.tutorial.data.model

import java.time.Instant

data class DeviceSchedulerInfo(
    var launchedTime: Instant? = null,
    var firstConnectionTime: Instant? = null,
    var notifiedTime: Instant? = null,
) {
    constructor(
        launchTimeSec: Long?,
        firstConnectionTimeSec: Long?,
        notifyTimeSec: Long?,
    ) : this(
        launchTimeSec?.let { Instant.ofEpochSecond(it) },
        firstConnectionTimeSec?.let { Instant.ofEpochSecond(it) },
        notifyTimeSec?.let { Instant.ofEpochSecond(it) },
    )

    val wasEverConnected: Boolean
        get() = firstConnectionTime != null

    val isLaunched: Boolean
        get() = launchedTime != null

    val isNotified: Boolean
        get() = notifiedTime != null
}
