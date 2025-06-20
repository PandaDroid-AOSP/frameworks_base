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

package com.android.systemui.communal.data.repository

import android.app.admin.DevicePolicyManager
import android.app.admin.DevicePolicyManager.KEYGUARD_DISABLE_WIDGETS_ALL
import android.content.IntentFilter
import android.content.pm.UserInfo
import android.content.res.Resources
import android.os.UserHandle
import android.provider.Settings
import com.android.systemui.Flags.communalHub
import com.android.systemui.Flags.glanceableHubV2
import com.android.systemui.broadcast.BroadcastDispatcher
import com.android.systemui.communal.data.model.CommunalFeature
import com.android.systemui.communal.data.model.FEATURE_ALL
import com.android.systemui.communal.data.model.SuppressionReason
import com.android.systemui.communal.data.repository.CommunalSettingsRepositoryModule.Companion.DEFAULT_BACKGROUND_TYPE
import com.android.systemui.communal.shared.model.CommunalBackgroundType
import com.android.systemui.communal.shared.model.WhenToDream
import com.android.systemui.communal.shared.model.WhenToStartHub
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Background
import com.android.systemui.dagger.qualifiers.Main
import com.android.systemui.flags.FeatureFlagsClassic
import com.android.systemui.flags.Flags
import com.android.systemui.util.kotlin.emitOnStart
import com.android.systemui.util.settings.SecureSettings
import com.android.systemui.util.settings.SettingsProxyExt.observerFlow
import javax.inject.Inject
import javax.inject.Named
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map

interface CommunalSettingsRepository {
    /** Whether a particular feature is enabled */
    fun isEnabled(@CommunalFeature feature: Int): Flow<Boolean>

    /**
     * Suppresses the hub with the given reasons. If there are no reasons, the hub will not be
     * suppressed.
     */
    fun setSuppressionReasons(reasons: List<SuppressionReason>)

    /**
     * Returns a [WhenToDream] for the specified user, indicating what state the device should be in
     * to trigger dreams.
     */
    fun getWhenToDreamState(user: UserInfo): Flow<WhenToDream>

    /**
     * Returns a[WhenToStartHub] for the specified user, indicating what state the device should be
     * in to automatically display the hub.
     */
    fun getWhenToStartHubState(user: UserInfo): Flow<WhenToStartHub>

    /** Returns whether glanceable hub is enabled by the current user. */
    fun getSettingEnabledByUser(user: UserInfo): Flow<Boolean>

    /**
     * Returns true if any glanceable hub functionality should be enabled via configs and flags.
     *
     * This should be used for preventing basic glanceable hub functionality from running on devices
     * that don't need it.
     *
     * If the glanceable_hub_v2 flag is enabled, checks the config_glanceableHubEnabled Android
     * config boolean. Otherwise, checks the old config_communalServiceEnabled config and
     * communal_hub flag.
     */
    fun getFlagEnabled(): Boolean

    /**
     * Returns true if the Android config config_glanceableHubEnabled and the glanceable_hub_v2 flag
     * are enabled.
     *
     * This should be used to flag off new glanceable hub or dream behavior that should launch
     * together with the new hub experience that brings the hub to mobile.
     *
     * The trunk-stable flag is controlled by server rollout and is on all devices. The Android
     * config flag is enabled via resource overlay only on products we want the hub to be present
     * on.
     */
    fun getV2FlagEnabled(): Boolean

    /** Keyguard widgets enabled state by Device Policy Manager for the specified user. */
    fun getAllowedByDevicePolicy(user: UserInfo): Flow<Boolean>

    /** The type of background to use for the hub. Used to experiment with different backgrounds. */
    fun getBackground(user: UserInfo): Flow<CommunalBackgroundType>
}

@SysUISingleton
class CommunalSettingsRepositoryImpl
@Inject
constructor(
    @Background private val bgDispatcher: CoroutineDispatcher,
    @Main private val resources: Resources,
    private val featureFlagsClassic: FeatureFlagsClassic,
    private val secureSettings: SecureSettings,
    private val broadcastDispatcher: BroadcastDispatcher,
    private val devicePolicyManager: DevicePolicyManager,
    @Named(DEFAULT_BACKGROUND_TYPE) private val defaultBackgroundType: CommunalBackgroundType,
) : CommunalSettingsRepository {

    private val dreamsActivatedOnSleepByDefault by lazy {
        resources.getBoolean(com.android.internal.R.bool.config_dreamsActivatedOnSleepByDefault)
    }

    private val dreamsActivatedOnDockByDefault by lazy {
        resources.getBoolean(com.android.internal.R.bool.config_dreamsActivatedOnDockByDefault)
    }

    private val dreamsActivatedOnPosturedByDefault by lazy {
        resources.getBoolean(com.android.internal.R.bool.config_dreamsActivatedOnPosturedByDefault)
    }

    private val whenToStartHubByDefault by lazy {
        resources.getInteger(com.android.internal.R.integer.config_whenToStartHubModeDefault)
    }

    private val _suppressionReasons =
        MutableStateFlow<List<SuppressionReason>>(
            // Suppress hub by default until we get an initial update.
            listOf(SuppressionReason.ReasonUnknown(FEATURE_ALL))
        )

    override fun isEnabled(@CommunalFeature feature: Int): Flow<Boolean> =
        _suppressionReasons.map { reasons -> reasons.none { it.isSuppressed(feature) } }

    override fun setSuppressionReasons(reasons: List<SuppressionReason>) {
        _suppressionReasons.value = reasons
    }

    override fun getFlagEnabled(): Boolean {
        return if (getV2FlagEnabled()) {
            true
        } else {
            // This config (exposed as a classic feature flag) is targeted only to tablet.
            // TODO(b/379181581): clean up usages of communal_hub flag
            featureFlagsClassic.isEnabled(Flags.COMMUNAL_SERVICE_ENABLED) && communalHub()
        }
    }

    override fun getV2FlagEnabled(): Boolean {
        return resources.getBoolean(com.android.internal.R.bool.config_glanceableHubEnabled) &&
            glanceableHubV2()
    }

    override fun getWhenToDreamState(user: UserInfo): Flow<WhenToDream> =
        secureSettings
            .observerFlow(
                userId = user.id,
                names =
                    arrayOf(
                        Settings.Secure.SCREENSAVER_ACTIVATE_ON_SLEEP,
                        Settings.Secure.SCREENSAVER_ACTIVATE_ON_DOCK,
                        Settings.Secure.SCREENSAVER_ACTIVATE_ON_POSTURED,
                    ),
            )
            .emitOnStart()
            .map {
                if (
                    secureSettings.getBoolForUser(
                        Settings.Secure.SCREENSAVER_ACTIVATE_ON_SLEEP,
                        dreamsActivatedOnSleepByDefault,
                        user.id,
                    )
                ) {
                    WhenToDream.WHILE_CHARGING
                } else if (
                    secureSettings.getBoolForUser(
                        Settings.Secure.SCREENSAVER_ACTIVATE_ON_DOCK,
                        dreamsActivatedOnDockByDefault,
                        user.id,
                    )
                ) {
                    WhenToDream.WHILE_DOCKED
                } else if (
                    secureSettings.getBoolForUser(
                        Settings.Secure.SCREENSAVER_ACTIVATE_ON_POSTURED,
                        dreamsActivatedOnPosturedByDefault,
                        user.id,
                    )
                ) {
                    WhenToDream.WHILE_POSTURED
                } else {
                    WhenToDream.NEVER
                }
            }
            .flowOn(bgDispatcher)

    override fun getWhenToStartHubState(user: UserInfo): Flow<WhenToStartHub> {
        if (!getV2FlagEnabled()) {
            return MutableStateFlow(WhenToStartHub.NEVER)
        }
        return secureSettings
            .observerFlow(
                userId = user.id,
                names = arrayOf(Settings.Secure.WHEN_TO_START_GLANCEABLE_HUB),
            )
            .emitOnStart()
            .map {
                when (
                    secureSettings.getIntForUser(
                        Settings.Secure.WHEN_TO_START_GLANCEABLE_HUB,
                        whenToStartHubByDefault,
                        user.id,
                    )
                ) {
                    Settings.Secure.GLANCEABLE_HUB_START_NEVER -> WhenToStartHub.NEVER
                    Settings.Secure.GLANCEABLE_HUB_START_CHARGING -> WhenToStartHub.WHILE_CHARGING
                    Settings.Secure.GLANCEABLE_HUB_START_CHARGING_UPRIGHT ->
                        WhenToStartHub.WHILE_CHARGING_AND_POSTURED

                    Settings.Secure.GLANCEABLE_HUB_START_DOCKED -> WhenToStartHub.WHILE_DOCKED
                    else -> WhenToStartHub.NEVER
                }
            }
            .flowOn(bgDispatcher)
    }

    override fun getAllowedByDevicePolicy(user: UserInfo): Flow<Boolean> =
        broadcastDispatcher
            .broadcastFlow(
                filter =
                    IntentFilter(DevicePolicyManager.ACTION_DEVICE_POLICY_MANAGER_STATE_CHANGED),
                // In COPE management mode, the restriction from the managed profile may
                // propagate to the main profile. Therefore listen to this broadcast across
                // all users and update the state each time it changes.
                user = UserHandle.ALL,
            )
            .emitOnStart()
            .map { devicePolicyManager.areKeyguardWidgetsAllowed(user.id) }

    override fun getBackground(user: UserInfo): Flow<CommunalBackgroundType> =
        secureSettings
            .observerFlow(userId = user.id, names = arrayOf(GLANCEABLE_HUB_BACKGROUND_SETTING))
            .emitOnStart()
            .map {
                val intType =
                    secureSettings.getIntForUser(
                        GLANCEABLE_HUB_BACKGROUND_SETTING,
                        defaultBackgroundType.value,
                        user.id,
                    )
                CommunalBackgroundType.entries.find { type -> type.value == intType }
                    ?: defaultBackgroundType
            }

    override fun getSettingEnabledByUser(user: UserInfo): Flow<Boolean> =
        secureSettings
            .observerFlow(userId = user.id, names = arrayOf(Settings.Secure.GLANCEABLE_HUB_ENABLED))
            // Force an update
            .emitOnStart()
            .map {
                secureSettings.getIntForUser(
                    Settings.Secure.GLANCEABLE_HUB_ENABLED,
                    ENABLED_SETTING_DEFAULT,
                    user.id,
                ) == 1
            }
            .flowOn(bgDispatcher)

    companion object {
        const val GLANCEABLE_HUB_BACKGROUND_SETTING = "glanceable_hub_background"
        private const val ENABLED_SETTING_DEFAULT = 1
    }
}

private fun DevicePolicyManager.areKeyguardWidgetsAllowed(userId: Int): Boolean =
    (getKeyguardDisabledFeatures(null, userId) and KEYGUARD_DISABLE_WIDGETS_ALL) == 0
