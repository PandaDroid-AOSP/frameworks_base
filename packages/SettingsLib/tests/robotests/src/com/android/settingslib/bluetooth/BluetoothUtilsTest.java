/*
 * Copyright (C) 2017 The Android Open Source Project
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
package com.android.settingslib.bluetooth;

import static com.android.settingslib.bluetooth.BluetoothUtils.getInputDevice;
import static com.android.settingslib.bluetooth.BluetoothUtils.isAvailableAudioSharingMediaBluetoothDevice;
import static com.android.settingslib.bluetooth.BluetoothUtils.isDeviceStylus;
import static com.android.settingslib.bluetooth.LocalBluetoothLeBroadcast.UNKNOWN_VALUE_PLACEHOLDER;
import static com.android.settingslib.flags.Flags.FLAG_ENABLE_DETERMINING_ADVANCED_DETAILS_HEADER_WITH_METADATA;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothCsipSetCoordinator;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothLeBroadcastReceiveState;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothStatusCodes;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.hardware.input.InputManager;
import android.media.AudioDeviceAttributes;
import android.media.AudioDeviceInfo;
import android.media.AudioManager;
import android.net.Uri;
import android.platform.test.annotations.DisableFlags;
import android.platform.test.annotations.EnableFlags;
import android.platform.test.flag.junit.SetFlagsRule;
import android.provider.Settings;
import android.util.Pair;
import android.view.InputDevice;

import com.android.internal.R;
import com.android.settingslib.flags.Flags;
import com.android.settingslib.testutils.shadow.ShadowBluetoothAdapter;
import com.android.settingslib.widget.AdaptiveIcon;

import com.google.common.collect.ImmutableList;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.shadow.api.Shadow;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RunWith(RobolectricTestRunner.class)
@Config(shadows = {ShadowBluetoothAdapter.class})
public class BluetoothUtilsTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private CachedBluetoothDevice mCachedBluetoothDevice;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private BluetoothDevice mBluetoothDevice;

    @Mock private PackageManager mPackageManager;
    @Mock private LeAudioProfile mA2dpProfile;
    @Mock private LeAudioProfile mLeAudioProfile;
    @Mock private LeAudioProfile mHearingAid;
    @Mock private LocalBluetoothLeBroadcast mBroadcast;
    @Mock private LocalBluetoothProfileManager mProfileManager;
    @Mock private LocalBluetoothManager mLocalBluetoothManager;
    @Mock private LocalBluetoothLeBroadcastAssistant mAssistant;
    @Mock private CachedBluetoothDeviceManager mDeviceManager;
    @Mock private BluetoothLeBroadcastReceiveState mLeBroadcastReceiveState;
    @Mock
    private InputManager mInputManager;

    private Context mContext;
    private ShadowBluetoothAdapter mShadowBluetoothAdapter;
    private final InputDevice mInputDevice = mock(InputDevice.class);
    private static final String STRING_METADATA = "string_metadata";
    private static final String LE_AUDIO_SHARING_METADATA = "le_audio_sharing";
    private static final String BOOL_METADATA = "true";
    private static final String INT_METADATA = "25";
    private static final int METADATA_FAST_PAIR_CUSTOMIZED_FIELDS = 25;
    private static final int TEST_DEVICE_ID = 123;
    private static final String KEY_HEARABLE_CONTROL_SLICE = "HEARABLE_CONTROL_SLICE_WITH_WIDTH";
    private static final String CONTROL_METADATA =
            "<HEARABLE_CONTROL_SLICE_WITH_WIDTH>"
                    + STRING_METADATA
                    + "</HEARABLE_CONTROL_SLICE_WITH_WIDTH>";
    private static final String TEMP_BOND_METADATA =
            "<TEMP_BOND_TYPE>" + LE_AUDIO_SHARING_METADATA + "</TEMP_BOND_TYPE>";
    private static final String FAKE_TEMP_BOND_METADATA = "<TEMP_BOND_TYPE>fake</TEMP_BOND_TYPE>";
    private static final String TEST_EXCLUSIVE_MANAGER_PACKAGE = "com.test.manager";
    private static final String TEST_EXCLUSIVE_MANAGER_COMPONENT = "com.test.manager/.component";
    private static final String TEST_ADDRESS = "11:22:33:44:55:66";
    private static final int TEST_BROADCAST_ID = 25;

    @Rule public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        mContext = spy(RuntimeEnvironment.application);
        mSetFlagsRule.disableFlags(FLAG_ENABLE_DETERMINING_ADVANCED_DETAILS_HEADER_WITH_METADATA);
        mShadowBluetoothAdapter = Shadow.extract(BluetoothAdapter.getDefaultAdapter());
        when(mLocalBluetoothManager.getProfileManager()).thenReturn(mProfileManager);
        when(mLocalBluetoothManager.getCachedDeviceManager()).thenReturn(mDeviceManager);
        when(mProfileManager.getLeAudioBroadcastProfile()).thenReturn(mBroadcast);
        when(mProfileManager.getLeAudioBroadcastAssistantProfile()).thenReturn(mAssistant);
        when(mProfileManager.getLeAudioProfile()).thenReturn(mLeAudioProfile);
        when(mA2dpProfile.getProfileId()).thenReturn(BluetoothProfile.A2DP);
        when(mLeAudioProfile.getProfileId()).thenReturn(BluetoothProfile.LE_AUDIO);
        when(mHearingAid.getProfileId()).thenReturn(BluetoothProfile.HEARING_AID);
        when(mContext.getSystemService(InputManager.class)).thenReturn(mInputManager);
        when(mInputManager.getInputDeviceIds()).thenReturn(new int[]{TEST_DEVICE_ID});
        when(mInputManager.getInputDeviceBluetoothAddress(TEST_DEVICE_ID)).thenReturn(TEST_ADDRESS);
        when(mInputManager.getInputDevice(TEST_DEVICE_ID)).thenReturn(mInputDevice);
    }

    @Test
    public void
            getDerivedBtClassDrawableWithDescription_isAdvancedUntetheredDevice_returnHeadset() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .thenReturn(BOOL_METADATA.getBytes());
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        Pair<Drawable, String> pair =
                BluetoothUtils.getDerivedBtClassDrawableWithDescription(
                        mContext, mCachedBluetoothDevice);

        verify(mContext).getDrawable(R.drawable.ic_bt_headphones_a2dp);
    }

    @Test
    public void
            getDerivedBtClassDrawableWithDescription_notAdvancedUntetheredDevice_returnPhone() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .thenReturn("false".getBytes());
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getBtClass().getMajorDeviceClass())
                .thenReturn(BluetoothClass.Device.Major.PHONE);
        Pair<Drawable, String> pair =
                BluetoothUtils.getDerivedBtClassDrawableWithDescription(
                        mContext, mCachedBluetoothDevice);

        verify(mContext).getDrawable(R.drawable.ic_phone);
    }

    @Test
    public void getBtClassDrawableWithDescription_typePhone_returnPhoneDrawable() {
        when(mCachedBluetoothDevice.getBtClass().getMajorDeviceClass())
                .thenReturn(BluetoothClass.Device.Major.PHONE);
        final Pair<Drawable, String> pair =
                BluetoothUtils.getBtClassDrawableWithDescription(mContext, mCachedBluetoothDevice);

        verify(mContext).getDrawable(com.android.internal.R.drawable.ic_phone);
    }

    @Test
    public void getBtClassDrawableWithDescription_typeComputer_returnComputerDrawable() {
        when(mCachedBluetoothDevice.getBtClass().getMajorDeviceClass())
                .thenReturn(BluetoothClass.Device.Major.COMPUTER);
        final Pair<Drawable, String> pair =
                BluetoothUtils.getBtClassDrawableWithDescription(mContext, mCachedBluetoothDevice);

        verify(mContext).getDrawable(com.android.internal.R.drawable.ic_bt_laptop);
    }

    @Test
    public void getBtClassDrawableWithDescription_typeHearingAid_returnHearingAidDrawable() {
        when(mCachedBluetoothDevice.isHearingAidDevice()).thenReturn(true);
        BluetoothUtils.getBtClassDrawableWithDescription(mContext, mCachedBluetoothDevice);

        verify(mContext).getDrawable(com.android.internal.R.drawable.ic_bt_hearing_aid);
    }

    @Test
    public void getBtRainbowDrawableWithDescription_normalHeadset_returnAdaptiveIcon() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .thenReturn("false".getBytes());
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getAddress()).thenReturn("1f:aa:bb");

        assertThat(
                        BluetoothUtils.getBtRainbowDrawableWithDescription(
                                        RuntimeEnvironment.application, mCachedBluetoothDevice)
                                .first)
                .isInstanceOf(AdaptiveIcon.class);
    }

    @Test
    public void getStringMetaData_hasMetaData_getCorrectMetaData() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_UNTETHERED_LEFT_ICON))
                .thenReturn(STRING_METADATA.getBytes());

        assertThat(
                        BluetoothUtils.getStringMetaData(
                                mBluetoothDevice, BluetoothDevice.METADATA_UNTETHERED_LEFT_ICON))
                .isEqualTo(STRING_METADATA);
    }

    @Test
    public void getIntMetaData_hasMetaData_getCorrectMetaData() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_UNTETHERED_LEFT_BATTERY))
                .thenReturn(INT_METADATA.getBytes());

        assertThat(
                        BluetoothUtils.getIntMetaData(
                                mBluetoothDevice, BluetoothDevice.METADATA_UNTETHERED_LEFT_BATTERY))
                .isEqualTo(Integer.parseInt(INT_METADATA));
    }

    @Test
    public void getIntMetaData_invalidMetaData_getErrorCode() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_UNTETHERED_LEFT_BATTERY))
                .thenReturn(null);

        assertThat(
                        BluetoothUtils.getIntMetaData(
                                mBluetoothDevice, BluetoothDevice.METADATA_UNTETHERED_LEFT_ICON))
                .isEqualTo(BluetoothUtils.META_INT_ERROR);
    }

    @Test
    public void getBooleanMetaData_hasMetaData_getCorrectMetaData() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .thenReturn(BOOL_METADATA.getBytes());

        assertThat(
                        BluetoothUtils.getBooleanMetaData(
                                mBluetoothDevice, BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .isTrue();
    }

    @Test
    public void getUriMetaData_hasMetaData_getCorrectMetaData() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_MAIN_ICON))
                .thenReturn(STRING_METADATA.getBytes());

        assertThat(
                        BluetoothUtils.getUriMetaData(
                                mBluetoothDevice, BluetoothDevice.METADATA_MAIN_ICON))
                .isEqualTo(Uri.parse(STRING_METADATA));
    }

    @Test
    public void getUriMetaData_nullMetaData_getNullUri() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_MAIN_ICON)).thenReturn(null);

        assertThat(
                        BluetoothUtils.getUriMetaData(
                                mBluetoothDevice, BluetoothDevice.METADATA_MAIN_ICON))
                .isNull();
    }

    @Test
    public void getControlUriMetaData_hasMetaData_returnsCorrectMetaData() {
        when(mBluetoothDevice.getMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS))
                .thenReturn(CONTROL_METADATA.getBytes());

        assertThat(BluetoothUtils.getControlUriMetaData(mBluetoothDevice))
                .isEqualTo(STRING_METADATA);
    }

    @Test
    public void getFastPairCustomizedField_hasMetaData_returnsCorrectMetaData() {
        when(mBluetoothDevice.getMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS))
                .thenReturn(CONTROL_METADATA.getBytes());

        assertThat(
                        BluetoothUtils.getFastPairCustomizedField(
                                mBluetoothDevice, KEY_HEARABLE_CONTROL_SLICE))
                .isEqualTo(STRING_METADATA);
    }

    @Test
    public void isAdvancedDetailsHeader_untetheredHeadset_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .thenReturn(BOOL_METADATA.getBytes());

        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedDetailsHeader_deviceTypeUntetheredHeadset_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_UNTETHERED_HEADSET.getBytes());

        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedDetailsHeader_deviceTypeWatch_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_WATCH.getBytes());

        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedDetailsHeader_deviceTypeStylus_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_STYLUS.getBytes());

        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedDetailsHeader_deviceTypeDefault_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_DEFAULT.getBytes());

        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedDetailsHeader_noMetadata_returnFalse() {
        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isAdvancedDetailsHeader_noMainIcon_returnFalse() {
        mSetFlagsRule.enableFlags(FLAG_ENABLE_DETERMINING_ADVANCED_DETAILS_HEADER_WITH_METADATA);

        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_MAIN_ICON)).thenReturn(null);

        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isAdvancedDetailsHeader_hasMainIcon_returnTrue() {
        mSetFlagsRule.enableFlags(FLAG_ENABLE_DETERMINING_ADVANCED_DETAILS_HEADER_WITH_METADATA);

        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_MAIN_ICON))
                .thenReturn(STRING_METADATA.getBytes());

        assertThat(BluetoothUtils.isAdvancedDetailsHeader(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedUntetheredDevice_untetheredHeadset_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .thenReturn(BOOL_METADATA.getBytes());

        assertThat(BluetoothUtils.isAdvancedUntetheredDevice(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedUntetheredDevice_deviceTypeUntetheredHeadset_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_UNTETHERED_HEADSET.getBytes());

        assertThat(BluetoothUtils.isAdvancedUntetheredDevice(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isAdvancedUntetheredDevice_deviceTypeWatch_returnFalse() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_WATCH.getBytes());

        assertThat(BluetoothUtils.isAdvancedUntetheredDevice(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isAdvancedUntetheredDevice_deviceTypeDefault_returnFalse() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_DEFAULT.getBytes());

        assertThat(BluetoothUtils.isAdvancedUntetheredDevice(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isAdvancedUntetheredDevice_noMetadata_returnFalse() {
        assertThat(BluetoothUtils.isAdvancedUntetheredDevice(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isAdvancedUntetheredDevice_untetheredHeadsetMetadataIsFalse_returnFalse() {
        mSetFlagsRule.enableFlags(FLAG_ENABLE_DETERMINING_ADVANCED_DETAILS_HEADER_WITH_METADATA);

        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET))
                .thenReturn("false".getBytes());
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_UNTETHERED_HEADSET.getBytes());

        assertThat(BluetoothUtils.isAdvancedUntetheredDevice(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isHeadset_metadataMatched_returnTrue() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_UNTETHERED_HEADSET.getBytes());

        assertThat(BluetoothUtils.isHeadset(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isHeadset_metadataNotMatched_returnFalse() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE))
                .thenReturn(BluetoothDevice.DEVICE_TYPE_CARKIT.getBytes());

        assertThat(BluetoothUtils.isHeadset(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isHeadset_btClassMatched_returnTrue() {
        when(mBluetoothDevice.getBluetoothClass().getDeviceClass())
                .thenReturn(BluetoothClass.Device.AUDIO_VIDEO_HEADPHONES);

        assertThat(BluetoothUtils.isHeadset(mBluetoothDevice)).isTrue();
    }

    @Test
    public void isHeadset_btClassNotMatched_returnFalse() {
        when(mBluetoothDevice.getBluetoothClass().getDeviceClass())
                .thenReturn(BluetoothClass.Device.AUDIO_VIDEO_LOUDSPEAKER);

        assertThat(BluetoothUtils.isHeadset(mBluetoothDevice)).isFalse();
    }

    @Test
    public void isAvailableMediaBluetoothDevice_isConnectedLeAudioDevice_returnTrue() {
        when(mCachedBluetoothDevice.isConnectedLeAudioDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(
                        BluetoothUtils.isAvailableMediaBluetoothDevice(
                                mCachedBluetoothDevice, /* isOngoingCall= */ false))
                .isTrue();
    }

    @Test
    public void isAvailableMediaBluetoothDevice_isHeadset_isConnectedA2dpDevice_returnFalse() {
        when(mCachedBluetoothDevice.isConnectedA2dpDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(
                        BluetoothUtils.isAvailableMediaBluetoothDevice(
                                mCachedBluetoothDevice,  /* isOngoingCall= */ true))
                .isFalse();
    }

    @Test
    public void isAvailableMediaBluetoothDevice_isA2dp_isConnectedA2dpDevice_returnTrue() {
        when(mCachedBluetoothDevice.isConnectedA2dpDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(
                        BluetoothUtils.isAvailableMediaBluetoothDevice(
                                mCachedBluetoothDevice,  /* isOngoingCall= */ false))
                .isTrue();
    }

    @Test
    public void isAvailableMediaBluetoothDevice_isHeadset_isConnectedHfpDevice_returnTrue() {
        when(mCachedBluetoothDevice.isConnectedHfpDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(
                        BluetoothUtils.isAvailableMediaBluetoothDevice(
                                mCachedBluetoothDevice, /* isOngoingCall= */ true))
                .isTrue();
    }

    @Test
    public void isConnectedBluetoothDevice_isConnectedLeAudioDevice_returnFalse() {
        when(mCachedBluetoothDevice.isConnectedLeAudioDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(BluetoothUtils.isConnectedBluetoothDevice(
                mCachedBluetoothDevice, /* isOngoingCall= */ false)).isFalse();
    }

    @Test
    public void isConnectedBluetoothDevice_isHeadset_isConnectedA2dpDevice_returnTrue() {
        when(mCachedBluetoothDevice.isConnectedA2dpDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(BluetoothUtils.isConnectedBluetoothDevice(
                mCachedBluetoothDevice,  /* isOngoingCall= */ true)).isTrue();
    }

    @Test
    public void isConnectedBluetoothDevice_isA2dp_isConnectedA2dpDevice_returnFalse() {
        when(mCachedBluetoothDevice.isConnectedA2dpDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(BluetoothUtils.isConnectedBluetoothDevice(
                mCachedBluetoothDevice, /* isOngoingCall= */ false)).isFalse();
    }

    @Test
    public void isConnectedBluetoothDevice_isHeadset_isConnectedHfpDevice_returnFalse() {
        when(mCachedBluetoothDevice.isConnectedHfpDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(BluetoothUtils.isConnectedBluetoothDevice(
                mCachedBluetoothDevice,  /* isOngoingCall= */ true)).isFalse();
    }

    @Test
    public void isConnectedBluetoothDevice_isNotConnected_returnFalse() {
        when(mCachedBluetoothDevice.isConnectedA2dpDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(false);

        assertThat(BluetoothUtils.isConnectedBluetoothDevice(
                mCachedBluetoothDevice,  /* isOngoingCall= */ true)).isFalse();
    }

    @Test
    public void isExclusivelyManaged_hasNoManager_returnFalse() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_EXCLUSIVE_MANAGER))
                .thenReturn(null);

        assertThat(BluetoothUtils.isExclusivelyManagedBluetoothDevice(mContext, mBluetoothDevice))
                .isFalse();
    }

    @Test
    public void isExclusivelyManaged_hasPackageName_packageNotInstalled_returnFalse()
            throws Exception {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_EXCLUSIVE_MANAGER))
                .thenReturn(TEST_EXCLUSIVE_MANAGER_PACKAGE.getBytes());
        when(mContext.getPackageManager()).thenReturn(mPackageManager);
        doThrow(new PackageManager.NameNotFoundException())
                .when(mPackageManager)
                .getApplicationInfo(TEST_EXCLUSIVE_MANAGER_PACKAGE, 0);

        assertThat(BluetoothUtils.isExclusivelyManagedBluetoothDevice(mContext, mBluetoothDevice))
                .isFalse();
    }

    @Test
    public void isExclusivelyManaged_hasComponentName_packageNotInstalled_returnFalse()
            throws Exception {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_EXCLUSIVE_MANAGER))
                .thenReturn(TEST_EXCLUSIVE_MANAGER_COMPONENT.getBytes());
        when(mContext.getPackageManager()).thenReturn(mPackageManager);
        doThrow(new PackageManager.NameNotFoundException())
                .when(mPackageManager)
                .getApplicationInfo(TEST_EXCLUSIVE_MANAGER_PACKAGE, 0);

        assertThat(BluetoothUtils.isExclusivelyManagedBluetoothDevice(mContext, mBluetoothDevice))
                .isFalse();
    }

    @Test
    public void isExclusivelyManaged_hasPackageName_packageNotEnabled_returnFalse()
            throws Exception {
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.enabled = false;
        when(mContext.getPackageManager()).thenReturn(mPackageManager);
        doReturn(appInfo)
                .when(mPackageManager)
                .getApplicationInfo(TEST_EXCLUSIVE_MANAGER_PACKAGE, 0);
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_EXCLUSIVE_MANAGER))
                .thenReturn(TEST_EXCLUSIVE_MANAGER_PACKAGE.getBytes());

        assertThat(BluetoothUtils.isExclusivelyManagedBluetoothDevice(mContext, mBluetoothDevice))
                .isFalse();
    }

    @Test
    public void isExclusivelyManaged_hasComponentName_packageNotEnabled_returnFalse()
            throws Exception {
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.enabled = false;
        when(mContext.getPackageManager()).thenReturn(mPackageManager);
        doReturn(appInfo)
                .when(mPackageManager)
                .getApplicationInfo(TEST_EXCLUSIVE_MANAGER_PACKAGE, 0);
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_EXCLUSIVE_MANAGER))
                .thenReturn(TEST_EXCLUSIVE_MANAGER_COMPONENT.getBytes());

        assertThat(BluetoothUtils.isExclusivelyManagedBluetoothDevice(mContext, mBluetoothDevice))
                .isFalse();
    }

    @Test
    public void isExclusivelyManaged_hasPackageName_packageInstalledAndEnabled_returnTrue()
            throws Exception {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_EXCLUSIVE_MANAGER))
                .thenReturn(TEST_EXCLUSIVE_MANAGER_PACKAGE.getBytes());
        when(mContext.getPackageManager()).thenReturn(mPackageManager);
        doReturn(new ApplicationInfo())
                .when(mPackageManager)
                .getApplicationInfo(TEST_EXCLUSIVE_MANAGER_PACKAGE, 0);

        assertThat(BluetoothUtils.isExclusivelyManagedBluetoothDevice(mContext, mBluetoothDevice))
                .isTrue();
    }

    @Test
    public void isExclusivelyManaged_hasComponentName_packageInstalledAndEnabled_returnTrue()
            throws Exception {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_EXCLUSIVE_MANAGER))
                .thenReturn(TEST_EXCLUSIVE_MANAGER_COMPONENT.getBytes());
        when(mContext.getPackageManager()).thenReturn(mPackageManager);
        doReturn(new ApplicationInfo())
                .when(mPackageManager)
                .getApplicationInfo(TEST_EXCLUSIVE_MANAGER_PACKAGE, 0);

        assertThat(BluetoothUtils.isExclusivelyManagedBluetoothDevice(mContext, mBluetoothDevice))
                .isTrue();
    }

    @Test
    public void testIsBroadcasting_broadcastEnabled_returnTrue() {
        when(mBroadcast.isEnabled(any())).thenReturn(true);
        assertThat(BluetoothUtils.isBroadcasting(mLocalBluetoothManager)).isTrue();
    }

    @Test
    public void testHasConnectedBroadcastSource_leadDeviceConnectedToBroadcastSource() {
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        CachedBluetoothDevice memberCachedDevice = mock(CachedBluetoothDevice.class);
        BluetoothDevice memberDevice = mock(BluetoothDevice.class);
        when(memberCachedDevice.getDevice()).thenReturn(memberDevice);
        Set<CachedBluetoothDevice> memberCachedDevices = new HashSet<>();
        memberCachedDevices.add(memberCachedDevice);
        when(mCachedBluetoothDevice.getMemberDevice()).thenReturn(memberCachedDevices);

        List<Long> bisSyncState = new ArrayList<>();
        bisSyncState.add(1L);
        when(mLeBroadcastReceiveState.getBisSyncState()).thenReturn(bisSyncState);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);
        when(mAssistant.getAllSources(memberDevice)).thenReturn(Collections.emptyList());

        assertThat(
                        BluetoothUtils.hasConnectedBroadcastSource(
                                mCachedBluetoothDevice, mLocalBluetoothManager))
                .isTrue();
    }

    @Test
    public void testHasConnectedBroadcastSource_memberDeviceConnectedToBroadcastSource() {
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        CachedBluetoothDevice memberCachedDevice = mock(CachedBluetoothDevice.class);
        BluetoothDevice memberDevice = mock(BluetoothDevice.class);
        when(memberCachedDevice.getDevice()).thenReturn(memberDevice);
        Set<CachedBluetoothDevice> memberCachedDevices = new HashSet<>();
        memberCachedDevices.add(memberCachedDevice);
        when(mCachedBluetoothDevice.getMemberDevice()).thenReturn(memberCachedDevices);

        List<Long> bisSyncState = new ArrayList<>();
        bisSyncState.add(1L);
        when(mLeBroadcastReceiveState.getBisSyncState()).thenReturn(bisSyncState);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(memberDevice)).thenReturn(sourceList);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(Collections.emptyList());

        assertThat(
                        BluetoothUtils.hasConnectedBroadcastSource(
                                mCachedBluetoothDevice, mLocalBluetoothManager))
                .isTrue();
    }

    @Test
    public void testHasConnectedBroadcastSource_deviceNotConnectedToBroadcastSource() {
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);

        List<Long> bisSyncState = new ArrayList<>();
        when(mLeBroadcastReceiveState.getBisSyncState()).thenReturn(bisSyncState);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                        BluetoothUtils.hasConnectedBroadcastSource(
                                mCachedBluetoothDevice, mLocalBluetoothManager))
                .isFalse();
    }

    @Test
    public void testHasConnectedBroadcastSourceForBtDevice_deviceConnectedToBroadcastSource() {
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        List<Long> bisSyncState = new ArrayList<>();
        bisSyncState.add(1L);
        when(mLeBroadcastReceiveState.getBisSyncState()).thenReturn(bisSyncState);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                        BluetoothUtils.hasConnectedBroadcastSourceForBtDevice(
                                mBluetoothDevice, mLocalBluetoothManager))
                .isTrue();
    }

    @Test
    public void testHasConnectedBroadcastSourceForBtDevice_deviceNotConnectedToBroadcastSource() {
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        List<Long> bisSyncState = new ArrayList<>();
        when(mLeBroadcastReceiveState.getBisSyncState()).thenReturn(bisSyncState);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                        BluetoothUtils.hasConnectedBroadcastSourceForBtDevice(
                                mBluetoothDevice, mLocalBluetoothManager))
                .isFalse();
    }

    @Test
    public void hasConnectedBroadcastSource_hysteresisFix_leadDeviceHasActiveLocalSource() {
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        CachedBluetoothDevice memberCachedDevice = mock(CachedBluetoothDevice.class);
        BluetoothDevice memberDevice = mock(BluetoothDevice.class);
        when(memberCachedDevice.getDevice()).thenReturn(memberDevice);
        Set<CachedBluetoothDevice> memberCachedDevices = new HashSet<>();
        memberCachedDevices.add(memberCachedDevice);
        when(mCachedBluetoothDevice.getMemberDevice()).thenReturn(memberCachedDevices);


        when(mBroadcast.getLatestBroadcastId()).thenReturn(TEST_BROADCAST_ID);
        when(mLeBroadcastReceiveState.getBroadcastId()).thenReturn(TEST_BROADCAST_ID);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);
        when(mAssistant.getAllSources(memberDevice)).thenReturn(Collections.emptyList());

        assertThat(
                BluetoothUtils.hasConnectedBroadcastSource(
                        mCachedBluetoothDevice, mLocalBluetoothManager))
                .isTrue();
    }

    @Test
    public void hasConnectedBroadcastSource_hysteresisFix_memberDeviceHasActiveLocalSource() {
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        CachedBluetoothDevice memberCachedDevice = mock(CachedBluetoothDevice.class);
        BluetoothDevice memberDevice = mock(BluetoothDevice.class);
        when(memberCachedDevice.getDevice()).thenReturn(memberDevice);
        Set<CachedBluetoothDevice> memberCachedDevices = new HashSet<>();
        memberCachedDevices.add(memberCachedDevice);
        when(mCachedBluetoothDevice.getMemberDevice()).thenReturn(memberCachedDevices);

        when(mBroadcast.getLatestBroadcastId()).thenReturn(TEST_BROADCAST_ID);
        when(mLeBroadcastReceiveState.getBroadcastId()).thenReturn(TEST_BROADCAST_ID);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(memberDevice)).thenReturn(sourceList);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(Collections.emptyList());

        assertThat(
                BluetoothUtils.hasConnectedBroadcastSource(
                        mCachedBluetoothDevice, mLocalBluetoothManager))
                .isTrue();
    }

    @Test
    public void hasConnectedBroadcastSource_hysteresisFix_deviceNoActiveLocalSource() {
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);

        when(mBroadcast.getLatestBroadcastId()).thenReturn(UNKNOWN_VALUE_PLACEHOLDER);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                BluetoothUtils.hasConnectedBroadcastSource(
                        mCachedBluetoothDevice, mLocalBluetoothManager))
                .isFalse();
    }

    @Test
    public void hasConnectedBroadcastSourceForBtDevice_hysteresisFix_deviceHasActiveLocalSource() {
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mBroadcast.getLatestBroadcastId()).thenReturn(TEST_BROADCAST_ID);
        when(mLeBroadcastReceiveState.getBroadcastId()).thenReturn(TEST_BROADCAST_ID);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                BluetoothUtils.hasConnectedBroadcastSourceForBtDevice(
                        mBluetoothDevice, mLocalBluetoothManager))
                .isTrue();
    }

    @Test
    public void hasConnectedBroadcastSourceForBtDevice_hysteresisFix_deviceNoActiveLocalSource() {
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        when(mBroadcast.getLatestBroadcastId()).thenReturn(TEST_BROADCAST_ID);
        when(mLeBroadcastReceiveState.getBroadcastId()).thenReturn(UNKNOWN_VALUE_PLACEHOLDER);

        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                BluetoothUtils.hasConnectedBroadcastSourceForBtDevice(
                        mBluetoothDevice, mLocalBluetoothManager))
                .isFalse();
    }

    @Test
    public void testHasActiveLocalBroadcastSourceForBtDevice_hasActiveLocalSource() {
        when(mBroadcast.getLatestBroadcastId()).thenReturn(TEST_BROADCAST_ID);
        when(mLeBroadcastReceiveState.getBroadcastId()).thenReturn(TEST_BROADCAST_ID);
        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                        BluetoothUtils.hasActiveLocalBroadcastSourceForBtDevice(
                                mBluetoothDevice, mLocalBluetoothManager))
                .isTrue();
    }

    @Test
    public void testHasActiveLocalBroadcastSourceForBtDevice_noActiveLocalSource() {
        when(mLeBroadcastReceiveState.getBroadcastId()).thenReturn(UNKNOWN_VALUE_PLACEHOLDER);
        List<BluetoothLeBroadcastReceiveState> sourceList = new ArrayList<>();
        sourceList.add(mLeBroadcastReceiveState);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(sourceList);

        assertThat(
                        BluetoothUtils.hasActiveLocalBroadcastSourceForBtDevice(
                                mBluetoothDevice, mLocalBluetoothManager))
                .isFalse();
    }

    @Test
    public void isAvailableHearingDevice_isConnectedHearingAid_returnTure() {
        when(mCachedBluetoothDevice.isConnectedHearingAidDevice()).thenReturn(true);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mBluetoothDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);
        when(mBluetoothDevice.isConnected()).thenReturn(true);

        assertThat(BluetoothUtils.isAvailableHearingDevice(mCachedBluetoothDevice)).isTrue();
    }

    @Test
    public void getGroupId_getCsipProfileId() {
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(1);

        assertThat(BluetoothUtils.getGroupId(mCachedBluetoothDevice)).isEqualTo(1);
    }

    @Test
    public void getGroupId_getLeAudioProfileId() {
        when(mCachedBluetoothDevice.getGroupId())
                .thenReturn(BluetoothCsipSetCoordinator.GROUP_ID_INVALID);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        LeAudioProfile leAudio = mock(LeAudioProfile.class);
        when(leAudio.getGroupId(mBluetoothDevice)).thenReturn(1);
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(ImmutableList.of(leAudio));

        assertThat(BluetoothUtils.getGroupId(mCachedBluetoothDevice)).isEqualTo(1);
    }

    @Test
    public void getSecondaryDeviceForBroadcast_noBroadcast_returnNull() {
        assertThat(
                        BluetoothUtils.getSecondaryDeviceForBroadcast(
                                mContext.getContentResolver(), mLocalBluetoothManager))
                .isNull();
    }

    @Test
    public void getSecondaryDeviceForBroadcast_nullProfile_returnNull() {
        when(mProfileManager.getLeAudioBroadcastProfile()).thenReturn(null);
        assertThat(
                        BluetoothUtils.getSecondaryDeviceForBroadcast(
                                mContext.getContentResolver(), mLocalBluetoothManager))
                .isNull();
    }

    @Test
    @EnableFlags(Flags.FLAG_ADOPT_PRIMARY_GROUP_MANAGEMENT_API_V2)
    public void getSecondaryDeviceForBroadcast_adoptAPI_noSecondary_returnNull() {
        when(mBroadcast.isEnabled(any())).thenReturn(true);
        when(mLeAudioProfile.getBroadcastToUnicastFallbackGroup()).thenReturn(1);
        when(mDeviceManager.findDevice(mBluetoothDevice)).thenReturn(mCachedBluetoothDevice);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(1);
        BluetoothLeBroadcastReceiveState state = mock(BluetoothLeBroadcastReceiveState.class);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(ImmutableList.of(state));
        when(mAssistant.getAllConnectedDevices()).thenReturn(ImmutableList.of(mBluetoothDevice));

        assertThat(
                BluetoothUtils.getSecondaryDeviceForBroadcast(
                        mContext.getContentResolver(), mLocalBluetoothManager))
                .isNull();
    }

    @Test
    @EnableFlags(Flags.FLAG_ADOPT_PRIMARY_GROUP_MANAGEMENT_API_V2)
    public void getSecondaryDeviceForBroadcast_adoptAPI_returnCorrectDevice() {
        when(mBroadcast.isEnabled(any())).thenReturn(true);
        when(mLeAudioProfile.getBroadcastToUnicastFallbackGroup()).thenReturn(1);
        CachedBluetoothDevice cachedBluetoothDevice = mock(CachedBluetoothDevice.class);
        BluetoothDevice bluetoothDevice = mock(BluetoothDevice.class);
        when(cachedBluetoothDevice.getDevice()).thenReturn(bluetoothDevice);
        when(cachedBluetoothDevice.getGroupId()).thenReturn(1);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(2);
        when(mDeviceManager.findDevice(bluetoothDevice)).thenReturn(cachedBluetoothDevice);
        when(mDeviceManager.findDevice(mBluetoothDevice)).thenReturn(mCachedBluetoothDevice);
        BluetoothLeBroadcastReceiveState state = mock(BluetoothLeBroadcastReceiveState.class);
        List<Long> bisSyncState = new ArrayList<>();
        bisSyncState.add(1L);
        when(state.getBisSyncState()).thenReturn(bisSyncState);
        when(mAssistant.getAllSources(any(BluetoothDevice.class)))
                .thenReturn(ImmutableList.of(state));
        when(mAssistant.getAllConnectedDevices())
                .thenReturn(ImmutableList.of(mBluetoothDevice, bluetoothDevice));

        assertThat(
                BluetoothUtils.getSecondaryDeviceForBroadcast(
                        mContext.getContentResolver(), mLocalBluetoothManager))
                .isEqualTo(mCachedBluetoothDevice);
    }

    @Test
    @DisableFlags(Flags.FLAG_ADOPT_PRIMARY_GROUP_MANAGEMENT_API_V2)
    public void getSecondaryDeviceForBroadcast_noSecondary_returnNull() {
        Settings.Secure.putInt(
                mContext.getContentResolver(),
                BluetoothUtils.getPrimaryGroupIdUriForBroadcast(),
                1);
        when(mBroadcast.isEnabled(any())).thenReturn(true);
        when(mDeviceManager.findDevice(mBluetoothDevice)).thenReturn(mCachedBluetoothDevice);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(1);
        BluetoothLeBroadcastReceiveState state = mock(BluetoothLeBroadcastReceiveState.class);
        when(mAssistant.getAllSources(mBluetoothDevice)).thenReturn(ImmutableList.of(state));
        when(mAssistant.getAllConnectedDevices()).thenReturn(ImmutableList.of(mBluetoothDevice));

        assertThat(
                        BluetoothUtils.getSecondaryDeviceForBroadcast(
                                mContext.getContentResolver(), mLocalBluetoothManager))
                .isNull();
    }

    @Test
    @DisableFlags(Flags.FLAG_ADOPT_PRIMARY_GROUP_MANAGEMENT_API_V2)
    public void getSecondaryDeviceForBroadcast_returnCorrectDevice() {
        Settings.Secure.putInt(
                mContext.getContentResolver(),
                BluetoothUtils.getPrimaryGroupIdUriForBroadcast(),
                1);
        when(mBroadcast.isEnabled(any())).thenReturn(true);
        CachedBluetoothDeviceManager deviceManager = mock(CachedBluetoothDeviceManager.class);
        when(mLocalBluetoothManager.getCachedDeviceManager()).thenReturn(deviceManager);
        CachedBluetoothDevice cachedBluetoothDevice = mock(CachedBluetoothDevice.class);
        BluetoothDevice bluetoothDevice = mock(BluetoothDevice.class);
        when(cachedBluetoothDevice.getDevice()).thenReturn(bluetoothDevice);
        when(cachedBluetoothDevice.getGroupId()).thenReturn(1);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(2);
        when(deviceManager.findDevice(bluetoothDevice)).thenReturn(cachedBluetoothDevice);
        when(deviceManager.findDevice(mBluetoothDevice)).thenReturn(mCachedBluetoothDevice);
        BluetoothLeBroadcastReceiveState state = mock(BluetoothLeBroadcastReceiveState.class);
        List<Long> bisSyncState = new ArrayList<>();
        bisSyncState.add(1L);
        when(state.getBisSyncState()).thenReturn(bisSyncState);
        when(mAssistant.getAllSources(any(BluetoothDevice.class)))
                .thenReturn(ImmutableList.of(state));
        when(mAssistant.getAllConnectedDevices())
                .thenReturn(ImmutableList.of(mBluetoothDevice, bluetoothDevice));

        assertThat(
                        BluetoothUtils.getSecondaryDeviceForBroadcast(
                                mContext.getContentResolver(), mLocalBluetoothManager))
                .isEqualTo(mCachedBluetoothDevice);
    }

    @Test
    public void testIsAvailableAudioSharingMediaBluetoothDevice_nullProfiles() {
        when(mProfileManager.getLeAudioBroadcastAssistantProfile()).thenReturn(null);
        boolean result =
                isAvailableAudioSharingMediaBluetoothDevice(
                        mCachedBluetoothDevice, mLocalBluetoothManager);

        assertThat(result).isFalse();
    }

    @Test
    public void testIsAvailableAudioSharingMediaBluetoothDevice_alreadyBroadcasting() {
        when(mBroadcast.isEnabled(any())).thenReturn(true);

        boolean result =
                isAvailableAudioSharingMediaBluetoothDevice(
                        mCachedBluetoothDevice, mLocalBluetoothManager);

        assertThat(result).isFalse();
    }

    @Test
    public void testIsAvailableAudioSharingMediaBluetoothDevice_availableDevice() {
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(1);
        CachedBluetoothDevice cachedBluetoothDevice2 = mock(CachedBluetoothDevice.class);
        when(cachedBluetoothDevice2.getGroupId()).thenReturn(2);

        BluetoothDevice device1 = mock(BluetoothDevice.class);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(device1);
        when(mDeviceManager.findDevice(device1)).thenReturn(mCachedBluetoothDevice);
        BluetoothDevice device2 = mock(BluetoothDevice.class);
        when(cachedBluetoothDevice2.getDevice()).thenReturn(device2);
        when(mDeviceManager.findDevice(device2)).thenReturn(cachedBluetoothDevice2);

        when(mAssistant.getAllConnectedDevices()).thenReturn(ImmutableList.of(device1, device2));
        when(mLeAudioProfile.getActiveDevices()).thenReturn(ImmutableList.of(device1));

        boolean result =
                isAvailableAudioSharingMediaBluetoothDevice(
                        cachedBluetoothDevice2, mLocalBluetoothManager);

        assertThat(result).isTrue();
    }

    @Test
    public void testIsAvailableAudioSharingMediaBluetoothDevice_alreadyActive() {
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(1);
        CachedBluetoothDevice cachedBluetoothDevice2 = mock(CachedBluetoothDevice.class);
        when(cachedBluetoothDevice2.getGroupId()).thenReturn(2);

        BluetoothDevice device1 = mock(BluetoothDevice.class);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(device1);
        when(mDeviceManager.findDevice(device1)).thenReturn(mCachedBluetoothDevice);
        BluetoothDevice device2 = mock(BluetoothDevice.class);
        when(cachedBluetoothDevice2.getDevice()).thenReturn(device2);
        when(mDeviceManager.findDevice(device2)).thenReturn(cachedBluetoothDevice2);

        when(mAssistant.getAllConnectedDevices()).thenReturn(ImmutableList.of(device1, device2));
        when(mLeAudioProfile.getActiveDevices()).thenReturn(ImmutableList.of(device1));

        boolean result =
                isAvailableAudioSharingMediaBluetoothDevice(
                        mCachedBluetoothDevice, mLocalBluetoothManager);

        assertThat(result).isFalse();
    }

    @Test
    public void testIsAvailableAudioSharingMediaBluetoothDevice_notConnected() {
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(1);
        CachedBluetoothDevice cachedBluetoothDevice2 = mock(CachedBluetoothDevice.class);
        when(cachedBluetoothDevice2.getGroupId()).thenReturn(2);

        BluetoothDevice device1 = mock(BluetoothDevice.class);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(device1);
        when(mDeviceManager.findDevice(device1)).thenReturn(mCachedBluetoothDevice);
        BluetoothDevice device2 = mock(BluetoothDevice.class);
        when(cachedBluetoothDevice2.getDevice()).thenReturn(device2);
        when(mDeviceManager.findDevice(device2)).thenReturn(cachedBluetoothDevice2);

        when(mAssistant.getAllConnectedDevices()).thenReturn(ImmutableList.of(device2));
        when(mLeAudioProfile.getActiveDevices()).thenReturn(ImmutableList.of(device1));

        boolean result =
                isAvailableAudioSharingMediaBluetoothDevice(
                        mCachedBluetoothDevice, mLocalBluetoothManager);

        assertThat(result).isFalse();
    }

    @Test
    public void testIsAvailableAudioSharingMediaBluetoothDevice_moreThanTwoConnected() {
        when(mCachedBluetoothDevice.getGroupId()).thenReturn(1);
        CachedBluetoothDevice cachedBluetoothDevice2 = mock(CachedBluetoothDevice.class);
        when(cachedBluetoothDevice2.getGroupId()).thenReturn(2);
        CachedBluetoothDevice cachedBluetoothDevice3 = mock(CachedBluetoothDevice.class);
        when(cachedBluetoothDevice3.getGroupId()).thenReturn(3);

        BluetoothDevice device1 = mock(BluetoothDevice.class);
        when(mCachedBluetoothDevice.getDevice()).thenReturn(device1);
        when(mDeviceManager.findDevice(device1)).thenReturn(mCachedBluetoothDevice);
        BluetoothDevice device2 = mock(BluetoothDevice.class);
        when(cachedBluetoothDevice2.getDevice()).thenReturn(device2);
        when(mDeviceManager.findDevice(device2)).thenReturn(cachedBluetoothDevice2);
        BluetoothDevice device3 = mock(BluetoothDevice.class);
        when(cachedBluetoothDevice3.getDevice()).thenReturn(device3);
        when(mDeviceManager.findDevice(device3)).thenReturn(cachedBluetoothDevice3);

        when(mAssistant.getAllConnectedDevices())
                .thenReturn(ImmutableList.of(device1, device2, device3));
        when(mLeAudioProfile.getActiveDevices()).thenReturn(ImmutableList.of(device1));

        boolean result =
                isAvailableAudioSharingMediaBluetoothDevice(
                        cachedBluetoothDevice2, mLocalBluetoothManager);

        assertThat(result).isFalse();
    }

    @Test
    public void getAudioDeviceAttributesForSpatialAudio_bleHeadset() {
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getAddress()).thenReturn(TEST_ADDRESS);
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(List.of(mLeAudioProfile));
        when(mLeAudioProfile.isEnabled(mBluetoothDevice)).thenReturn(true);

        AudioDeviceAttributes attr =
                BluetoothUtils.getAudioDeviceAttributesForSpatialAudio(
                        mCachedBluetoothDevice, AudioManager.AUDIO_DEVICE_CATEGORY_HEADPHONES);

        assertThat(attr)
                .isEqualTo(
                        new AudioDeviceAttributes(
                                AudioDeviceAttributes.ROLE_OUTPUT,
                                AudioDeviceInfo.TYPE_BLE_HEADSET,
                                TEST_ADDRESS));
    }

    @Test
    public void getAudioDeviceAttributesForSpatialAudio_bleSpeaker() {
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getAddress()).thenReturn(TEST_ADDRESS);
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(List.of(mLeAudioProfile));
        when(mLeAudioProfile.isEnabled(mBluetoothDevice)).thenReturn(true);

        AudioDeviceAttributes attr =
                BluetoothUtils.getAudioDeviceAttributesForSpatialAudio(
                        mCachedBluetoothDevice, AudioManager.AUDIO_DEVICE_CATEGORY_SPEAKER);

        assertThat(attr)
                .isEqualTo(
                        new AudioDeviceAttributes(
                                AudioDeviceAttributes.ROLE_OUTPUT,
                                AudioDeviceInfo.TYPE_BLE_SPEAKER,
                                TEST_ADDRESS));
    }

    @Test
    public void getAudioDeviceAttributesForSpatialAudio_a2dp() {

        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getAddress()).thenReturn(TEST_ADDRESS);
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(List.of(mA2dpProfile));
        when(mA2dpProfile.isEnabled(mBluetoothDevice)).thenReturn(true);

        AudioDeviceAttributes attr =
                BluetoothUtils.getAudioDeviceAttributesForSpatialAudio(
                        mCachedBluetoothDevice, AudioManager.AUDIO_DEVICE_CATEGORY_HEADPHONES);

        assertThat(attr)
                .isEqualTo(
                        new AudioDeviceAttributes(
                                AudioDeviceAttributes.ROLE_OUTPUT,
                                AudioDeviceInfo.TYPE_BLUETOOTH_A2DP,
                                TEST_ADDRESS));
    }

    @Test
    public void getAudioDeviceAttributesForSpatialAudio_hearingAid() {
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mCachedBluetoothDevice.getAddress()).thenReturn(TEST_ADDRESS);
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(List.of(mHearingAid));
        when(mHearingAid.isEnabled(mBluetoothDevice)).thenReturn(true);

        AudioDeviceAttributes attr =
                BluetoothUtils.getAudioDeviceAttributesForSpatialAudio(
                        mCachedBluetoothDevice, AudioManager.AUDIO_DEVICE_CATEGORY_HEARING_AID);

        assertThat(attr)
                .isEqualTo(
                        new AudioDeviceAttributes(
                                AudioDeviceAttributes.ROLE_OUTPUT,
                                AudioDeviceInfo.TYPE_HEARING_AID,
                                TEST_ADDRESS));
    }

    @Test
    public void isAudioSharingEnabled_flagOff_returnsFalse() {
        mSetFlagsRule.disableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);

        assertThat(BluetoothUtils.isAudioSharingEnabled()).isFalse();
    }

    @Test
    public void isAudioSharingEnabled_featureNotSupported_returnsFalse() {
        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_NOT_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);

        assertThat(BluetoothUtils.isAudioSharingEnabled()).isFalse();
    }

    @Test
    public void isAudioSharingEnabled_featureSupported_returnsTrue() {
        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);

        assertThat(BluetoothUtils.isAudioSharingEnabled()).isTrue();
    }

    @Test
    public void isAudioSharingPreviewEnabled_flagOff_returnsFalse() {
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);

        assertThat(BluetoothUtils.isAudioSharingPreviewEnabled(
                mContext.getContentResolver())).isFalse();
    }

    @Test
    public void isAudioSharingPreviewEnabled_featureNotSupported_returnsFalse() {
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_NOT_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);

        assertThat(BluetoothUtils.isAudioSharingPreviewEnabled(
                mContext.getContentResolver())).isFalse();
    }

    @Test
    public void isAudioSharingPreviewEnabled_developerOptionOff_returnsFalse() {
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        Settings.Global.putInt(mContext.getContentResolver(),
                BluetoothUtils.DEVELOPER_OPTION_PREVIEW_KEY, 0);

        assertThat(BluetoothUtils.isAudioSharingPreviewEnabled(
                mContext.getContentResolver())).isFalse();
    }

    @Test
    public void isAudioSharingPreviewEnabled_developerOptionOn_returnsTrue() {
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        Settings.Global.putInt(mContext.getContentResolver(),
                BluetoothUtils.DEVELOPER_OPTION_PREVIEW_KEY, 1);

        assertThat(BluetoothUtils.isAudioSharingPreviewEnabled(
                mContext.getContentResolver())).isTrue();
    }

    @Test
    public void isAudioSharingUIAvailable_audioSharingAndPreviewFlagOff_returnsFalse() {
        mSetFlagsRule.disableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);

        assertThat(BluetoothUtils.isAudioSharingUIAvailable(mContext)).isFalse();
    }

    @Test
    public void isAudioSharingUIAvailable_audioSharingAndPreviewDisabled_returnsFalse() {
        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_NOT_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);

        assertThat(BluetoothUtils.isAudioSharingUIAvailable(mContext)).isFalse();
    }

    @Test
    public void isAudioSharingUIAvailable_audioSharingEnabled_returnsTrue() {
        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);
        Settings.Global.putInt(mContext.getContentResolver(),
                BluetoothUtils.DEVELOPER_OPTION_PREVIEW_KEY, 0);

        assertThat(BluetoothUtils.isAudioSharingUIAvailable(mContext)).isTrue();
    }

    @Test
    public void isAudioSharingUIAvailable_audioSharingPreviewEnabled_returnsTrue() {
        mSetFlagsRule.disableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastSourceSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        mShadowBluetoothAdapter.setIsLeAudioBroadcastAssistantSupported(
                BluetoothStatusCodes.FEATURE_SUPPORTED);
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);
        Settings.Global.putInt(mContext.getContentResolver(),
                BluetoothUtils.DEVELOPER_OPTION_PREVIEW_KEY, 1);

        assertThat(BluetoothUtils.isAudioSharingUIAvailable(mContext)).isTrue();
    }

    @Test
    public void isAudioSharingHysteresisModeFixAvailable_mainAndPreviewFlagOff_returnsFalse() {
        mSetFlagsRule.disableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);

        assertThat(BluetoothUtils.isAudioSharingHysteresisModeFixAvailable(mContext)).isFalse();
    }

    @Test
    public void isAudioSharingHysteresisModeFixAvailable_hysteresisFixFlagOff_returnsFalse() {
        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);

        assertThat(BluetoothUtils.isAudioSharingHysteresisModeFixAvailable(mContext)).isFalse();
    }

    @Test
    public void isAudioSharingHysteresisModeFixAvailable_previewFlagOn_returnsTrue() {
        mSetFlagsRule.disableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);
        Settings.Global.putInt(mContext.getContentResolver(),
                BluetoothUtils.DEVELOPER_OPTION_PREVIEW_KEY, 1);

        assertThat(BluetoothUtils.isAudioSharingHysteresisModeFixAvailable(mContext)).isTrue();
    }

    @Test
    public void isAudioSharingHysteresisModeFixAvailable_mainAndPreviewFlagOn_returnsTrue() {
        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_LE_AUDIO_SHARING);
        mSetFlagsRule.enableFlags(Flags.FLAG_AUDIO_SHARING_HYSTERESIS_MODE_FIX);
        mSetFlagsRule.disableFlags(Flags.FLAG_AUDIO_SHARING_DEVELOPER_OPTION);

        assertThat(BluetoothUtils.isAudioSharingHysteresisModeFixAvailable(mContext)).isTrue();
    }

    @Test
    public void isMediaDevice_returnsFalse() {
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(ImmutableList.of(mAssistant));
        assertThat(BluetoothUtils.isMediaDevice(mCachedBluetoothDevice)).isFalse();
    }

    @Test
    public void isMediaDevice_returnsTrue() {
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(ImmutableList.of(mLeAudioProfile));
        assertThat(BluetoothUtils.isMediaDevice(mCachedBluetoothDevice)).isTrue();
    }

    @Test
    public void isLeAudioSupported_returnsFalse() {
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(ImmutableList.of(mLeAudioProfile));
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mLeAudioProfile.isEnabled(mBluetoothDevice)).thenReturn(false);

        assertThat(BluetoothUtils.isLeAudioSupported(mCachedBluetoothDevice)).isFalse();
    }

    @Test
    public void isLeAudioSupported_returnsTrue() {
        when(mCachedBluetoothDevice.getProfiles()).thenReturn(ImmutableList.of(mLeAudioProfile));
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);
        when(mLeAudioProfile.isEnabled(mBluetoothDevice)).thenReturn(true);

        assertThat(BluetoothUtils.isLeAudioSupported(mCachedBluetoothDevice)).isTrue();
    }

    @Test
    public void isTemporaryBondDevice_hasMetadata_returnsTrue() {
        when(mBluetoothDevice.getMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS))
                .thenReturn(TEMP_BOND_METADATA.getBytes());

        assertThat(BluetoothUtils.isTemporaryBondDevice(mBluetoothDevice)).isTrue();
    }

    @Test
    @DisableFlags(Flags.FLAG_ENABLE_TEMPORARY_BOND_DEVICES_UI)
    public void setTemporaryBondDevice_flagOff_doNothing() {
        when(mBluetoothDevice.getMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS))
                .thenReturn(new byte[]{});
        BluetoothUtils.setTemporaryBondMetadata(mBluetoothDevice);
        verify(mBluetoothDevice, never()).setMetadata(eq(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS),
                any());
    }

    @Test
    @EnableFlags(Flags.FLAG_ENABLE_TEMPORARY_BOND_DEVICES_UI)
    public void setTemporaryBondDevice_flagOn_setCorrectValue() {
        when(mBluetoothDevice.getMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS))
                .thenReturn(new byte[]{});
        BluetoothUtils.setTemporaryBondMetadata(mBluetoothDevice);
        verify(mBluetoothDevice).setMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS,
                TEMP_BOND_METADATA.getBytes());
    }

    @Test
    @EnableFlags(Flags.FLAG_ENABLE_TEMPORARY_BOND_DEVICES_UI)
    public void setTemporaryBondDevice_flagOff_replaceAndSetCorrectValue() {
        when(mBluetoothDevice.getMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS))
                .thenReturn(FAKE_TEMP_BOND_METADATA.getBytes());
        BluetoothUtils.setTemporaryBondMetadata(mBluetoothDevice);
        verify(mBluetoothDevice).setMetadata(METADATA_FAST_PAIR_CUSTOMIZED_FIELDS,
                TEMP_BOND_METADATA.getBytes());
    }

    @Test
    public void getInputDevice_addressNotMatched_returnsNull() {
        assertThat(getInputDevice(mContext, "123")).isNull();
    }

    @Test
    public void getInputDevice_isInputDevice_returnsInputDevice() {
        assertThat(getInputDevice(mContext, TEST_ADDRESS)).isEqualTo(mInputDevice);
    }

    @Test
    public void isDeviceStylus_noDevices_false() {
        assertThat(isDeviceStylus(null, null)).isFalse();
    }

    @Test
    public void isDeviceStylus_nonStylusInputDevice_false() {
        InputDevice inputDevice = new InputDevice.Builder()
                .setSources(InputDevice.SOURCE_DPAD)
                .build();

        assertThat(isDeviceStylus(inputDevice, null)).isFalse();
    }

    @Test
    public void isDeviceStylus_stylusInputDevice_true() {
        InputDevice inputDevice = new InputDevice.Builder()
                .setSources(InputDevice.SOURCE_STYLUS)
                .build();

        assertThat(isDeviceStylus(inputDevice, null)).isTrue();
    }

    @Test
    public void isDeviceStylus_nonStylusBluetoothDevice_false() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE)).thenReturn(
                BluetoothDevice.DEVICE_TYPE_WATCH.getBytes());

        assertThat(isDeviceStylus(null, mCachedBluetoothDevice)).isFalse();
    }

    @Test
    public void isDeviceStylus_stylusBluetoothDevice_true() {
        when(mBluetoothDevice.getMetadata(BluetoothDevice.METADATA_DEVICE_TYPE)).thenReturn(
                BluetoothDevice.DEVICE_TYPE_STYLUS.getBytes());
        when(mCachedBluetoothDevice.getDevice()).thenReturn(mBluetoothDevice);

        assertThat(isDeviceStylus(null, mCachedBluetoothDevice)).isTrue();
    }
}
