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

package com.android.systemui.qs.panels.ui.viewmodel

import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.plugins.qs.TileDetailsViewModel
import com.android.systemui.qs.pipeline.domain.interactor.CurrentTilesInteractor
import com.android.systemui.qs.pipeline.shared.TileSpec
import com.android.systemui.shade.domain.interactor.ShadeModeInteractor
import javax.inject.Inject

@SysUISingleton
@Stable
class DetailsViewModel @Inject constructor(
    val currentTilesInteractor: CurrentTilesInteractor,
    val shadeModeInteractor: ShadeModeInteractor
) {

    /**
     * The current active [TileDetailsViewModel]. If it's `null`, it means the qs overlay is not
     * showing any details view. It changes when [onTileClicked] and [closeDetailedView].
     */
    private val _activeTileDetails = mutableStateOf<TileDetailsViewModel?>(null)
    val activeTileDetails by _activeTileDetails

    /**
     * Update the active [TileDetailsViewModel] to `null`.
     *
     * @see activeTileDetails
     */
    fun closeDetailedView() {
        _activeTileDetails.value = null
    }

    /**
     * Update the active [TileDetailsViewModel] to the `spec`'s corresponding view model. Return if
     * the [TileDetailsViewModel] is successfully handled.
     *
     * @see activeTileDetails
     */
    fun onTileClicked(spec: TileSpec?): Boolean {
        if (!shadeModeInteractor.isDualShade){
            return false
        }

        if (spec == null) {
            _activeTileDetails.value = null
            return false
        }

        val currentTile =
            currentTilesInteractor.currentQSTiles.firstOrNull { it.tileSpec == spec.spec }

        return currentTile?.getDetailsViewModel { detailsViewModel ->
            _activeTileDetails.value = detailsViewModel
        } ?: false
    }
}
