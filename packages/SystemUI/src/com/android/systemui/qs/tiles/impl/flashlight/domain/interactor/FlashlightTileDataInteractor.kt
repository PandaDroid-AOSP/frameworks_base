/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.systemui.qs.tiles.impl.flashlight.domain.interactor

import android.os.UserHandle
import com.android.systemui.qs.tiles.base.domain.interactor.QSTileDataInteractor
import com.android.systemui.qs.tiles.base.domain.model.DataUpdateTrigger
import com.android.systemui.qs.tiles.impl.flashlight.domain.model.FlashlightTileModel
import com.android.systemui.statusbar.policy.FlashlightController
import com.android.systemui.utils.coroutines.flow.conflatedCallbackFlow
import javax.inject.Inject
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf

/** Observes flashlight state changes providing the [FlashlightTileModel]. */
class FlashlightTileDataInteractor
@Inject
constructor(private val flashlightController: FlashlightController) :
    QSTileDataInteractor<FlashlightTileModel> {

    override fun tileData(
        user: UserHandle,
        triggers: Flow<DataUpdateTrigger>,
    ): Flow<FlashlightTileModel> = conflatedCallbackFlow {
        val callback =
            object : FlashlightController.FlashlightListener {
                override fun onFlashlightChanged(enabled: Boolean) {
                    trySend(FlashlightTileModel.FlashlightAvailable(enabled))
                }

                override fun onFlashlightError() {
                    trySend(FlashlightTileModel.FlashlightAvailable(false))
                }

                override fun onFlashlightAvailabilityChanged(available: Boolean) {
                    trySend(
                        if (available)
                            FlashlightTileModel.FlashlightAvailable(flashlightController.isEnabled)
                        else FlashlightTileModel.FlashlightTemporarilyUnavailable
                    )
                }
            }
        flashlightController.addCallback(callback)
        awaitClose { flashlightController.removeCallback(callback) }
    }

    /**
     * Used to determine if the tile should be displayed. Not to be confused with the availability
     * in the data model above. This flow signals whether the tile should be shown or hidden.
     */
    override fun availability(user: UserHandle): Flow<Boolean> =
        flowOf(flashlightController.hasFlashlight())
}
