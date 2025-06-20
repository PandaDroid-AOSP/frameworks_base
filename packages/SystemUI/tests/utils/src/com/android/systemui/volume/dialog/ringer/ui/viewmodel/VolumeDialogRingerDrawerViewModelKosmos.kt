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

import android.content.applicationContext
import com.android.internal.logging.uiEventLogger
import com.android.systemui.haptics.vibratorHelper
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.applicationCoroutineScope
import com.android.systemui.kosmos.testDispatcher
import com.android.systemui.statusbar.notification.domain.interactor.notificationsSoundPolicyInteractor
import com.android.systemui.statusbar.policy.configurationController
import com.android.systemui.util.time.fakeSystemClock
import com.android.systemui.util.time.systemClock
import com.android.systemui.volume.dialog.domain.interactor.volumeDialogVisibilityInteractor
import com.android.systemui.volume.dialog.ringer.domain.volumeDialogRingerInteractor
import com.android.systemui.volume.dialog.shared.volumeDialogLogger

val Kosmos.volumeDialogRingerDrawerViewModel by
    Kosmos.Fixture {
        VolumeDialogRingerDrawerViewModel(
            applicationContext = applicationContext,
            backgroundDispatcher = testDispatcher,
            coroutineScope = applicationCoroutineScope,
            soundPolicyInteractor = notificationsSoundPolicyInteractor,
            ringerInteractor = volumeDialogRingerInteractor,
            vibrator = vibratorHelper,
            volumeDialogLogger = volumeDialogLogger,
            visibilityInteractor = volumeDialogVisibilityInteractor,
            configurationController = configurationController,
            uiEventLogger = uiEventLogger,
            systemClock = fakeSystemClock,
        )
    }
