/*
 * Copyright (C) 2025 The Android Open Source Project
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

package com.android.systemui.qs.tiles.base.domain.interactor

import android.os.UserHandle
import com.android.systemui.qs.tiles.base.domain.model.DataUpdateTrigger
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf

/**
 * Provides data and availability for the tile. In most cases it would delegate data retrieval to
 * repository, manager, controller or a combination of those. Avoid doing long running operations in
 * these methods because there is no background thread guarantee. Use [Flow.flowOn] (typically
 * with @Background [CoroutineDispatcher]) instead to move the calculations to another thread.
 */
interface QSTileDataInteractor<DATA_TYPE> : QSTileAvailabilityInteractor {

    /**
     * Returns a data flow scoped to the user. This means the subscription will live when the tile
     * is listened for the [user]. It's cancelled when the tile is not listened or the user changes.
     *
     * You can use [Flow.onStart] on the returned to update the tile with the current state as soon
     * as possible.
     */
    fun tileData(user: UserHandle, triggers: Flow<DataUpdateTrigger>): Flow<DATA_TYPE>
}

interface QSTileAvailabilityInteractor {
    /**
     * Returns tile availability - whether this device currently supports this tile.
     *
     * You can use [Flow.onStart] on the returned to update the tile with the current state as soon
     * as possible.
     */
    fun availability(user: UserHandle): Flow<Boolean>

    companion object {
        val AlwaysAvailableInteractor =
            object : QSTileAvailabilityInteractor {
                override fun availability(user: UserHandle): Flow<Boolean> {
                    return flowOf(true)
                }
            }
    }
}
