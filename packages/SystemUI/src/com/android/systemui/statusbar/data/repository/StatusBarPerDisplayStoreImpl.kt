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

package com.android.systemui.statusbar.data.repository

import com.android.app.tracing.coroutines.launchTraced as launch
import com.android.systemui.dagger.qualifiers.Background
import com.android.systemui.display.data.repository.DisplayRepository
import com.android.systemui.display.data.repository.PerDisplayStoreImpl
import com.android.systemui.util.kotlin.pairwiseBy
import kotlinx.coroutines.CoroutineScope

/** [PerDisplayStoreImpl] for Status Bar related classes. */
abstract class StatusBarPerDisplayStoreImpl<T>(
    @Background private val backgroundApplicationScope: CoroutineScope,
    private val displayRepository: DisplayRepository,
) : PerDisplayStoreImpl<T>(backgroundApplicationScope, displayRepository) {

    override fun start() {
        val instanceType = instanceClass.simpleName
        backgroundApplicationScope.launch("StatusBarPerDisplayStore#<$instanceType>start") {
            displayRepository.displayIdsWithSystemDecorations
                .pairwiseBy { previousDisplays, currentDisplays ->
                    previousDisplays - currentDisplays
                }
                .collect { removedDisplayIds ->
                    removedDisplayIds.forEach { removedDisplayId ->
                        val removedInstance = perDisplayInstances.remove(removedDisplayId)
                        removedInstance?.let { onDisplayRemovalAction(it) }
                    }
                }
        }
    }
}
