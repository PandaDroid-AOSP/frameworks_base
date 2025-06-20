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

package com.android.systemui.statusbar.pipeline.shared.domain.interactor

import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.statusbar.disableflags.domain.interactor.DisableFlagsInteractor
import com.android.systemui.statusbar.pipeline.airplane.domain.interactor.AirplaneModeInteractor
import com.android.systemui.statusbar.pipeline.mobile.domain.interactor.CarrierConfigInteractor
import com.android.systemui.statusbar.pipeline.shared.domain.model.StatusBarDisableFlagsVisibilityModel
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map

/**
 * Interactor for the home screen status bar (aka
 * [com.android.systemui.statusbar.phone.fragment.CollapsedStatusBarFragment]).
 */
@SysUISingleton
class HomeStatusBarInteractor
@Inject
constructor(
    airplaneModeInteractor: AirplaneModeInteractor,
    carrierConfigInteractor: CarrierConfigInteractor,
    disableFlagsInteractor: DisableFlagsInteractor,
) {
    /**
     * The visibilities of various status bar child views, based only on the information we received
     * from disable flags.
     */
    val visibilityViaDisableFlags: Flow<StatusBarDisableFlagsVisibilityModel> =
        disableFlagsInteractor.disableFlags.map {
            StatusBarDisableFlagsVisibilityModel(
                isClockAllowed = it.isClockEnabled,
                areNotificationIconsAllowed = it.areNotificationIconsEnabled,
                isSystemInfoAllowed = it.isSystemInfoEnabled,
                animate = it.animate,
            )
        }

    private val defaultDataSubConfigShowOperatorView =
        carrierConfigInteractor.defaultDataSubscriptionCarrierConfig.flatMapLatest {
            it?.showOperatorNameInStatusBar ?: flowOf(false)
        }

    /**
     * True if the carrier config for the default data subscription has
     * [SystemUiCarrierConfig.showOperatorNameInStatusBar] set and the device is not in airplane
     * mode
     */
    val shouldShowOperatorName: Flow<Boolean> =
        combine(defaultDataSubConfigShowOperatorView, airplaneModeInteractor.isAirplaneMode) {
            showOperatorName,
            isAirplaneMode ->
            showOperatorName && !isAirplaneMode
        }
}
