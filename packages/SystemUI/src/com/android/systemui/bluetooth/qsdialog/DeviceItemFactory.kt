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

package com.android.systemui.bluetooth.qsdialog

import android.bluetooth.BluetoothDevice
import android.content.Context
import com.android.settingslib.bluetooth.BluetoothUtils
import com.android.settingslib.bluetooth.CachedBluetoothDevice
import com.android.settingslib.bluetooth.LocalBluetoothManager
import com.android.systemui.res.R

private val backgroundOn = R.drawable.settingslib_switch_bar_bg_on
private val backgroundOff = R.drawable.bluetooth_tile_dialog_bg_off
private val backgroundOffBusy = R.drawable.bluetooth_tile_dialog_bg_off_busy
private val connected = R.string.quick_settings_bluetooth_device_connected
private val audioSharing = R.string.quick_settings_bluetooth_device_audio_sharing
private val audioSharingAddIcon = R.drawable.ic_add
private val audioSharingOnGoingIcon = R.drawable.ic_check
private val saved = R.string.quick_settings_bluetooth_device_saved
private val actionAccessibilityLabelActivate =
    R.string.accessibility_quick_settings_bluetooth_device_tap_to_activate
private val actionAccessibilityLabelDisconnect =
    R.string.accessibility_quick_settings_bluetooth_device_tap_to_disconnect

/** Factories to create different types of Bluetooth device items from CachedBluetoothDevice. */
abstract class DeviceItemFactory {
    abstract fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean

    // Overloaded that defaults audioSharingAvailable to false
    fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
    ): Boolean = isFilterMatched(context, cachedDevice, isOngoingCall, false)

    abstract fun create(context: Context, cachedDevice: CachedBluetoothDevice): DeviceItem

    companion object {
        @JvmStatic
        fun createDeviceItem(
            cachedDevice: CachedBluetoothDevice,
            type: DeviceItemType,
            connectionSummary: String,
            background: Int,
            actionAccessibilityLabel: String,
            isActive: Boolean,
            actionIconRes: Int = R.drawable.ic_settings_24dp,
        ): DeviceItem {
            return DeviceItem(
                type = type,
                cachedBluetoothDevice = cachedDevice,
                deviceName = cachedDevice.name,
                connectionSummary = connectionSummary,
                iconWithDescription =
                    cachedDevice.drawableWithDescription.let { Pair(it.first, it.second) },
                background = background,
                isEnabled = !cachedDevice.isBusy,
                actionAccessibilityLabel = actionAccessibilityLabel,
                isActive = isActive,
                actionIconRes = actionIconRes,
            )
        }
    }
}

internal open class ActiveMediaDeviceItemFactory : DeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return BluetoothUtils.isActiveMediaDevice(cachedDevice) &&
            BluetoothUtils.isAvailableMediaBluetoothDevice(cachedDevice, isOngoingCall)
    }

    override fun create(context: Context, cachedDevice: CachedBluetoothDevice): DeviceItem {
        return createDeviceItem(
            cachedDevice,
            DeviceItemType.ACTIVE_MEDIA_BLUETOOTH_DEVICE,
            cachedDevice.connectionSummary ?: "",
            backgroundOn,
            context.getString(actionAccessibilityLabelDisconnect),
            isActive = true,
        )
    }
}

internal class AudioSharingMediaDeviceItemFactory(
    private val localBluetoothManager: LocalBluetoothManager
) : DeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return audioSharingAvailable &&
            !isOngoingCall &&
            BluetoothUtils.hasConnectedBroadcastSource(cachedDevice, localBluetoothManager)
    }

    override fun create(context: Context, cachedDevice: CachedBluetoothDevice): DeviceItem {
        return createDeviceItem(
            cachedDevice,
            DeviceItemType.AUDIO_SHARING_MEDIA_BLUETOOTH_DEVICE,
            cachedDevice.connectionSummary.takeUnless { it.isNullOrEmpty() }
                ?: context.getString(audioSharing),
            if (cachedDevice.isBusy) backgroundOffBusy else backgroundOn,
            "",
            isActive = !cachedDevice.isBusy,
            actionIconRes = audioSharingOnGoingIcon,
        )
    }
}

internal class AvailableAudioSharingMediaDeviceItemFactory(
    private val localBluetoothManager: LocalBluetoothManager
) : AvailableMediaDeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return audioSharingAvailable &&
            !isOngoingCall &&
            super.isFilterMatched(context, cachedDevice, false, true) &&
            BluetoothUtils.isAvailableAudioSharingMediaBluetoothDevice(
                cachedDevice,
                localBluetoothManager,
            )
    }

    override fun create(context: Context, cachedDevice: CachedBluetoothDevice): DeviceItem {
        return createDeviceItem(
            cachedDevice,
            DeviceItemType.AVAILABLE_AUDIO_SHARING_MEDIA_BLUETOOTH_DEVICE,
            context.getString(
                R.string.quick_settings_bluetooth_device_audio_sharing_or_switch_active
            ),
            if (cachedDevice.isBusy) backgroundOffBusy else backgroundOff,
            "",
            isActive = false,
            actionIconRes = audioSharingAddIcon,
        )
    }
}

internal class ActiveHearingDeviceItemFactory : ActiveMediaDeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return BluetoothUtils.isActiveMediaDevice(cachedDevice) &&
            BluetoothUtils.isAvailableHearingDevice(cachedDevice)
    }
}

open class AvailableMediaDeviceItemFactory : DeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return !BluetoothUtils.isActiveMediaDevice(cachedDevice) &&
            BluetoothUtils.isAvailableMediaBluetoothDevice(cachedDevice, isOngoingCall)
    }

    override fun create(context: Context, cachedDevice: CachedBluetoothDevice): DeviceItem {
        return createDeviceItem(
            cachedDevice,
            DeviceItemType.AVAILABLE_MEDIA_BLUETOOTH_DEVICE,
            cachedDevice.connectionSummary.takeUnless { it.isNullOrEmpty() }
                ?: context.getString(connected),
            if (cachedDevice.isBusy) backgroundOffBusy else backgroundOff,
            context.getString(actionAccessibilityLabelActivate),
            isActive = false,
        )
    }
}

internal class AvailableHearingDeviceItemFactory : AvailableMediaDeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return !BluetoothUtils.isActiveMediaDevice(cachedDevice) &&
            BluetoothUtils.isAvailableHearingDevice(cachedDevice)
    }
}

internal open class ConnectedDeviceItemFactory : DeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return !BluetoothUtils.isExclusivelyManagedBluetoothDevice(context, cachedDevice.device) &&
            BluetoothUtils.isConnectedBluetoothDevice(cachedDevice, isOngoingCall)
    }

    override fun create(context: Context, cachedDevice: CachedBluetoothDevice): DeviceItem {
        return createDeviceItem(
            cachedDevice,
            DeviceItemType.CONNECTED_BLUETOOTH_DEVICE,
            cachedDevice.connectionSummary.takeUnless { it.isNullOrEmpty() }
                ?: context.getString(connected),
            if (cachedDevice.isBusy) backgroundOffBusy else backgroundOff,
            context.getString(actionAccessibilityLabelDisconnect),
            isActive = false,
        )
    }
}

internal class ConnectedHearingDeviceItemFactory : ConnectedDeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return cachedDevice.isHearingDevice &&
            cachedDevice.bondState == BluetoothDevice.BOND_BONDED &&
            cachedDevice.device.isConnected
    }
}

internal open class SavedDeviceItemFactory : DeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return !BluetoothUtils.isExclusivelyManagedBluetoothDevice(context, cachedDevice.device) &&
            cachedDevice.bondState == BluetoothDevice.BOND_BONDED &&
            !cachedDevice.isConnected
    }

    override fun create(context: Context, cachedDevice: CachedBluetoothDevice): DeviceItem {
        return createDeviceItem(
            cachedDevice,
            DeviceItemType.SAVED_BLUETOOTH_DEVICE,
            cachedDevice.connectionSummary.takeUnless { it.isNullOrEmpty() }
                ?: context.getString(saved),
            if (cachedDevice.isBusy) backgroundOffBusy else backgroundOff,
            context.getString(actionAccessibilityLabelActivate),
            isActive = false,
        )
    }
}

internal class SavedHearingDeviceItemFactory : SavedDeviceItemFactory() {
    override fun isFilterMatched(
        context: Context,
        cachedDevice: CachedBluetoothDevice,
        isOngoingCall: Boolean,
        audioSharingAvailable: Boolean,
    ): Boolean {
        return !BluetoothUtils.isExclusivelyManagedBluetoothDevice(
            context,
            cachedDevice.getDevice(),
        ) &&
            cachedDevice.isHearingDevice &&
            cachedDevice.bondState == BluetoothDevice.BOND_BONDED &&
            !cachedDevice.isConnected
    }
}
