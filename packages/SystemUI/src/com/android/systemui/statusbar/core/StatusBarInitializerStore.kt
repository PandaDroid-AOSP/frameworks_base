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

package com.android.systemui.statusbar.core

import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Background
import com.android.systemui.display.data.repository.DisplayRepository
import com.android.systemui.display.data.repository.PerDisplayStore
import com.android.systemui.display.data.repository.SingleDisplayStore
import com.android.systemui.statusbar.data.repository.DarkIconDispatcherStore
import com.android.systemui.statusbar.data.repository.StatusBarConfigurationControllerStore
import com.android.systemui.statusbar.data.repository.StatusBarModeRepositoryStore
import com.android.systemui.statusbar.data.repository.StatusBarPerDisplayStoreImpl
import com.android.systemui.statusbar.window.StatusBarWindowControllerStore
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope

/** Provides per display instances of [StatusBarInitializer]. */
interface StatusBarInitializerStore : PerDisplayStore<StatusBarInitializer>

@SysUISingleton
class MultiDisplayStatusBarInitializerStore
@Inject
constructor(
    @Background backgroundApplicationScope: CoroutineScope,
    displayRepository: DisplayRepository,
    private val factory: StatusBarInitializer.Factory,
    private val statusBarWindowControllerStore: StatusBarWindowControllerStore,
    private val statusBarModeRepositoryStore: StatusBarModeRepositoryStore,
    private val statusBarConfigurationControllerStore: StatusBarConfigurationControllerStore,
    private val darkIconDispatcherStore: DarkIconDispatcherStore,
) :
    StatusBarInitializerStore,
    StatusBarPerDisplayStoreImpl<StatusBarInitializer>(
        backgroundApplicationScope,
        displayRepository,
    ) {

    init {
        StatusBarConnectedDisplays.unsafeAssertInNewMode()
    }

    override fun createInstanceForDisplay(displayId: Int): StatusBarInitializer? {
        val statusBarWindowController =
            statusBarWindowControllerStore.forDisplay(displayId) ?: return null
        val statusBarModePerDisplayRepository =
            statusBarModeRepositoryStore.forDisplay(displayId) ?: return null
        val statusBarConfigurationController =
            statusBarConfigurationControllerStore.forDisplay(displayId) ?: return null
        val darkIconDispatcher = darkIconDispatcherStore.forDisplay(displayId) ?: return null
        return factory.create(
            statusBarWindowController,
            statusBarModePerDisplayRepository,
            statusBarConfigurationController,
            darkIconDispatcher,
        )
    }

    override val instanceClass = StatusBarInitializer::class.java
}

@SysUISingleton
class SingleDisplayStatusBarInitializerStore
@Inject
constructor(defaultInitializer: StatusBarInitializer) :
    StatusBarInitializerStore,
    PerDisplayStore<StatusBarInitializer> by SingleDisplayStore(defaultInitializer) {

    init {
        StatusBarConnectedDisplays.assertInLegacyMode()
    }
}
