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

import android.view.WindowManager.LayoutParams.TYPE_STATUS_BAR
import com.android.app.displaylib.PerDisplayInstanceProvider
import com.android.app.displaylib.PerDisplayInstanceRepositoryImpl
import com.android.app.displaylib.PerDisplayRepository
import com.android.app.displaylib.SingleInstanceRepositoryImpl
import com.android.systemui.common.ui.ConfigurationState
import com.android.systemui.common.ui.ConfigurationStateImpl
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.display.data.repository.DisplayWindowPropertiesRepository
import com.android.systemui.statusbar.core.StatusBarConnectedDisplays
import dagger.Lazy
import dagger.Module
import dagger.Provides
import javax.inject.Inject

@SysUISingleton
class StatusBarPerDisplayConfigurationStateProvider
@Inject
constructor(
    private val displayWindowPropertiesRepository: DisplayWindowPropertiesRepository,
    private val statusBarConfigurationControllerStore: StatusBarConfigurationControllerStore,
    private val factory: ConfigurationStateImpl.Factory,
) : PerDisplayInstanceProvider<ConfigurationState> {
    override fun createInstance(displayId: Int): ConfigurationState? {
        val displayWindowProperties =
            displayWindowPropertiesRepository.get(displayId, TYPE_STATUS_BAR) ?: return null
        val configController =
            statusBarConfigurationControllerStore.forDisplay(displayId) ?: return null
        return factory.create(displayWindowProperties.context, configController)
    }
}

@Module
object StatusBarPerDisplayConfigurationStateModule {

    @Provides
    @SysUISingleton
    fun store(
        instanceProvider: Lazy<StatusBarPerDisplayConfigurationStateProvider>,
        factory: PerDisplayInstanceRepositoryImpl.Factory<ConfigurationState>,
        defaultInstance: ConfigurationState,
    ): PerDisplayRepository<ConfigurationState> {
        val name = "ConfigurationState"
        return if (StatusBarConnectedDisplays.isEnabled) {
            factory.create(name, instanceProvider.get())
        } else {
            SingleInstanceRepositoryImpl(name, defaultInstance)
        }
    }
}
