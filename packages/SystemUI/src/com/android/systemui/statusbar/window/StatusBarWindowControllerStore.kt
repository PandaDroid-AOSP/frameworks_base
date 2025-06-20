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

package com.android.systemui.statusbar.window

import android.content.Context
import android.view.WindowManager
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Background
import com.android.systemui.display.data.repository.DisplayRepository
import com.android.systemui.display.data.repository.DisplayWindowPropertiesRepository
import com.android.systemui.display.data.repository.PerDisplayStore
import com.android.systemui.display.data.repository.SingleDisplayStore
import com.android.systemui.statusbar.core.StatusBarConnectedDisplays
import com.android.systemui.statusbar.data.repository.StatusBarConfigurationControllerStore
import com.android.systemui.statusbar.data.repository.StatusBarContentInsetsProviderStore
import com.android.systemui.statusbar.data.repository.StatusBarPerDisplayStoreImpl
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope

/** Store that allows to retrieve per display instances of [StatusBarWindowController]. */
interface StatusBarWindowControllerStore : PerDisplayStore<StatusBarWindowController>

@SysUISingleton
class MultiDisplayStatusBarWindowControllerStore
@Inject
constructor(
    @Background backgroundApplicationScope: CoroutineScope,
    private val controllerFactory: StatusBarWindowController.Factory,
    private val displayWindowPropertiesRepository: DisplayWindowPropertiesRepository,
    private val statusBarConfigurationControllerStore: StatusBarConfigurationControllerStore,
    private val statusBarContentInsetsProviderStore: StatusBarContentInsetsProviderStore,
    displayRepository: DisplayRepository,
) :
    StatusBarWindowControllerStore,
    StatusBarPerDisplayStoreImpl<StatusBarWindowController>(
        backgroundApplicationScope,
        displayRepository,
    ) {

    init {
        StatusBarConnectedDisplays.unsafeAssertInNewMode()
    }

    override fun createInstanceForDisplay(displayId: Int): StatusBarWindowController? {
        val statusBarDisplayContext =
            displayWindowPropertiesRepository.get(
                displayId = displayId,
                windowType = WindowManager.LayoutParams.TYPE_STATUS_BAR,
            ) ?: return null
        val statusBarConfigurationController =
            statusBarConfigurationControllerStore.forDisplay(displayId) ?: return null
        val contentInsetsProvider =
            statusBarContentInsetsProviderStore.forDisplay(displayId) ?: return null
        return controllerFactory.create(
            statusBarDisplayContext.context,
            statusBarDisplayContext.windowManager,
            statusBarConfigurationController,
            contentInsetsProvider,
        )
    }

    override suspend fun onDisplayRemovalAction(instance: StatusBarWindowController) {
        instance.stop()
    }

    override val instanceClass = StatusBarWindowController::class.java
}

@SysUISingleton
class SingleDisplayStatusBarWindowControllerStore
@Inject
constructor(
    context: Context,
    windowManager: WindowManager,
    factory: StatusBarWindowControllerImpl.Factory,
    statusBarConfigurationControllerStore: StatusBarConfigurationControllerStore,
    statusBarContentInsetsProviderStore: StatusBarContentInsetsProviderStore,
) :
    StatusBarWindowControllerStore,
    PerDisplayStore<StatusBarWindowController> by SingleDisplayStore(
        factory.create(
            context,
            windowManager,
            statusBarConfigurationControllerStore.defaultDisplay,
            statusBarContentInsetsProviderStore.defaultDisplay,
        )
    ) {

    init {
        StatusBarConnectedDisplays.assertInLegacyMode()
    }
}
