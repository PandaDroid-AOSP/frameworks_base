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

package com.android.systemui.bluetooth.qsdialog

import com.android.systemui.plugins.qs.TileDetailsViewModel

class BluetoothDetailsViewModel(
    private val onSettingsClick: () -> Unit,
    val detailsContentViewModel: BluetoothDetailsContentViewModel,
) : TileDetailsViewModel {
    override fun clickOnSettingsButton() {
        onSettingsClick()
    }

    // TODO: b/378513956 Update the placeholder text
    override val title = "Bluetooth"

    // TODO: b/378513956 Update the placeholder text
    override val subTitle = "Tap to connect or disconnect a device"
}
