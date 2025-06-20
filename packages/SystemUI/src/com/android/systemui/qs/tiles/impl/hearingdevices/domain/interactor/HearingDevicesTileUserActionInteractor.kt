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

package com.android.systemui.qs.tiles.impl.hearingdevices.domain.interactor

import android.content.Intent
import android.provider.Settings
import com.android.systemui.accessibility.hearingaid.HearingDevicesDialogManager
import com.android.systemui.accessibility.hearingaid.HearingDevicesUiEventLogger.Companion.LAUNCH_SOURCE_QS_TILE
import com.android.systemui.dagger.qualifiers.Main
import com.android.systemui.qs.shared.QSSettingsPackageRepository
import com.android.systemui.qs.tiles.base.domain.actions.QSTileIntentUserInputHandler
import com.android.systemui.qs.tiles.base.domain.interactor.QSTileUserActionInteractor
import com.android.systemui.qs.tiles.base.domain.model.QSTileInput
import com.android.systemui.qs.tiles.base.shared.model.QSTileUserAction
import com.android.systemui.qs.tiles.impl.hearingdevices.domain.model.HearingDevicesTileModel
import javax.inject.Inject
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.withContext

/** Handles hearing devices tile clicks. */
class HearingDevicesTileUserActionInteractor
@Inject
constructor(
    @Main private val mainContext: CoroutineContext,
    private val qsTileIntentUserActionHandler: QSTileIntentUserInputHandler,
    private val hearingDevicesDialogManager: HearingDevicesDialogManager,
    private val settingsPackageRepository: QSSettingsPackageRepository,
) : QSTileUserActionInteractor<HearingDevicesTileModel> {

    override suspend fun handleInput(input: QSTileInput<HearingDevicesTileModel>) =
        with(input) {
            when (action) {
                is QSTileUserAction.Click -> {
                    withContext(mainContext) {
                        hearingDevicesDialogManager.showDialog(
                            action.expandable,
                            LAUNCH_SOURCE_QS_TILE,
                        )
                    }
                }
                is QSTileUserAction.LongClick -> {
                    qsTileIntentUserActionHandler.handle(
                        action.expandable,
                        Intent(Settings.ACTION_HEARING_DEVICES_SETTINGS)
                            .setPackage(settingsPackageRepository.getSettingsPackageName()),
                    )
                }
                is QSTileUserAction.ToggleClick -> {}
            }
        }
}
