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

package com.android.systemui.qs.tiles.impl.location.domain.interactor

import android.os.UserHandle
import com.android.systemui.qs.tiles.base.domain.interactor.QSTileDataInteractor
import com.android.systemui.qs.tiles.base.domain.model.DataUpdateTrigger
import com.android.systemui.qs.tiles.impl.location.domain.model.LocationTileModel
import com.android.systemui.statusbar.policy.LocationController
import com.android.systemui.util.kotlin.isLocationEnabledFlow
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map

/** Observes location state changes providing the [LocationTileModel]. */
class LocationTileDataInteractor
@Inject
constructor(private val locationController: LocationController) :
    QSTileDataInteractor<LocationTileModel> {

    override fun tileData(
        user: UserHandle,
        triggers: Flow<DataUpdateTrigger>,
    ): Flow<LocationTileModel> =
        locationController.isLocationEnabledFlow().map { LocationTileModel(it) }

    override fun availability(user: UserHandle): Flow<Boolean> = flowOf(true)
}
