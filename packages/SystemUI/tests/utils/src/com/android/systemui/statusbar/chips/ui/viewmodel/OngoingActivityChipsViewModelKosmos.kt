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

package com.android.systemui.statusbar.chips.ui.viewmodel

import com.android.systemui.biometrics.domain.interactor.displayStateInteractor
import com.android.systemui.common.ui.domain.interactor.configurationInteractor
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.testScope
import com.android.systemui.statusbar.chips.call.ui.viewmodel.callChipViewModel
import com.android.systemui.statusbar.chips.casttootherdevice.ui.viewmodel.castToOtherDeviceChipViewModel
import com.android.systemui.statusbar.chips.notification.ui.viewmodel.notifChipsViewModel
import com.android.systemui.statusbar.chips.screenrecord.ui.viewmodel.screenRecordChipViewModel
import com.android.systemui.statusbar.chips.sharetoapp.ui.viewmodel.shareToAppChipViewModel
import com.android.systemui.statusbar.chips.statusBarChipsLogger

val Kosmos.ongoingActivityChipsViewModel: OngoingActivityChipsViewModel by
    Kosmos.Fixture {
        OngoingActivityChipsViewModel(
            testScope.backgroundScope,
            screenRecordChipViewModel = screenRecordChipViewModel,
            shareToAppChipViewModel = shareToAppChipViewModel,
            castToOtherDeviceChipViewModel = castToOtherDeviceChipViewModel,
            callChipViewModel = callChipViewModel,
            notifChipsViewModel = notifChipsViewModel,
            displayStateInteractor = displayStateInteractor,
            configurationInteractor = configurationInteractor,
            logger = statusBarChipsLogger,
        )
    }
