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

package com.android.systemui.flags

import com.android.server.notification.Flags.FLAG_CROSS_APP_POLITE_NOTIFICATIONS
import com.android.server.notification.Flags.FLAG_POLITE_NOTIFICATIONS
import com.android.server.notification.Flags.FLAG_VIBRATE_WHILE_UNLOCKED
import com.android.server.notification.Flags.crossAppPoliteNotifications
import com.android.server.notification.Flags.politeNotifications
import com.android.server.notification.Flags.vibrateWhileUnlocked
import com.android.systemui.Flags.FLAG_COMMUNAL_HUB
import com.android.systemui.Flags.communalHub
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.scene.shared.flag.SceneContainerFlag
import com.android.systemui.statusbar.notification.collection.SortBySectionTimeFlag
import com.android.systemui.statusbar.notification.emptyshade.shared.ModesEmptyShadeFix
import com.android.systemui.statusbar.notification.interruption.VisualInterruptionRefactor
import com.android.systemui.statusbar.notification.shared.NotificationAvalancheSuppression
import com.android.systemui.statusbar.notification.shared.NotificationMinimalism
import com.android.systemui.statusbar.notification.shared.NotificationThrottleHun
import com.android.systemui.statusbar.notification.shared.PriorityPeopleSection
import javax.inject.Inject

/** A class in which engineers can define flag dependencies */
@SysUISingleton
class FlagDependencies @Inject constructor(featureFlags: FeatureFlagsClassic, handler: Handler) :
    FlagDependenciesBase(featureFlags, handler) {
    override fun defineDependencies() {
        // Internal notification backend dependencies
        crossAppPoliteNotifications dependsOn politeNotifications
        vibrateWhileUnlockedToken dependsOn politeNotifications

        // Internal notification frontend dependencies
        NotificationAvalancheSuppression.token dependsOn VisualInterruptionRefactor.token
        PriorityPeopleSection.token dependsOn SortBySectionTimeFlag.token
        NotificationMinimalism.token dependsOn NotificationThrottleHun.token
        ModesEmptyShadeFix.token dependsOn modesUi

        // SceneContainer dependencies
        SceneContainerFlag.getFlagDependencies().forEach { (alpha, beta) -> alpha dependsOn beta }
    }

    private inline val politeNotifications
        get() = FlagToken(FLAG_POLITE_NOTIFICATIONS, politeNotifications())

    private inline val crossAppPoliteNotifications
        get() = FlagToken(FLAG_CROSS_APP_POLITE_NOTIFICATIONS, crossAppPoliteNotifications())

    private inline val vibrateWhileUnlockedToken: FlagToken
        get() = FlagToken(FLAG_VIBRATE_WHILE_UNLOCKED, vibrateWhileUnlocked())

    private inline val modesUi
        get() = FlagToken(android.app.Flags.FLAG_MODES_UI, android.app.Flags.modesUi())

    private inline val communalHub
        get() = FlagToken(FLAG_COMMUNAL_HUB, communalHub())
}
