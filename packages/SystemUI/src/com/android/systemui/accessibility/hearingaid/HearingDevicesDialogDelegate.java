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

package com.android.systemui.accessibility.hearingaid;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;

import static com.android.internal.accessibility.AccessibilityShortcutController.ACCESSIBILITY_HEARING_AIDS_COMPONENT_NAME;

import static java.util.Collections.emptyList;

import android.bluetooth.BluetoothHapClient;
import android.bluetooth.BluetoothHapPresetInfo;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.Resources;
import android.media.AudioManager;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Space;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.annotation.WorkerThread;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.android.settingslib.bluetooth.AmbientVolumeUiController;
import com.android.settingslib.bluetooth.BluetoothCallback;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import com.android.systemui.accessibility.hearingaid.HearingDevicesListAdapter.HearingDeviceItemCallback;
import com.android.systemui.animation.DialogTransitionAnimator;
import com.android.systemui.bluetooth.qsdialog.ActiveHearingDeviceItemFactory;
import com.android.systemui.bluetooth.qsdialog.AvailableHearingDeviceItemFactory;
import com.android.systemui.bluetooth.qsdialog.ConnectedHearingDeviceItemFactory;
import com.android.systemui.bluetooth.qsdialog.DeviceItem;
import com.android.systemui.bluetooth.qsdialog.DeviceItemFactory;
import com.android.systemui.bluetooth.qsdialog.DeviceItemType;
import com.android.systemui.bluetooth.qsdialog.SavedHearingDeviceItemFactory;
import com.android.systemui.dagger.qualifiers.Background;
import com.android.systemui.dagger.qualifiers.Main;
import com.android.systemui.plugins.ActivityStarter;
import com.android.systemui.qs.shared.QSSettingsPackageRepository;
import com.android.systemui.res.R;
import com.android.systemui.statusbar.phone.SystemUIDialog;

import dagger.assisted.Assisted;
import dagger.assisted.AssistedFactory;
import dagger.assisted.AssistedInject;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

/**
 * Dialog for showing hearing devices controls.
 */
public class HearingDevicesDialogDelegate implements SystemUIDialog.Delegate,
        HearingDeviceItemCallback, BluetoothCallback {

    private static final String TAG = "HearingDevicesDialogDelegate";
    @VisibleForTesting
    static final String ACTION_BLUETOOTH_DEVICE_DETAILS =
            "com.android.settings.BLUETOOTH_DEVICE_DETAIL_SETTINGS";
    private static final String EXTRA_SHOW_FRAGMENT_ARGUMENTS = ":settings:show_fragment_args";
    private static final String KEY_BLUETOOTH_ADDRESS = "device_address";
    @VisibleForTesting
    static final Intent LIVE_CAPTION_INTENT = new Intent(
            "com.android.settings.action.live_caption");

    private final SystemUIDialog.Factory mSystemUIDialogFactory;
    private final DialogTransitionAnimator mDialogTransitionAnimator;
    private final ActivityStarter mActivityStarter;
    private final LocalBluetoothManager mLocalBluetoothManager;
    private final Executor mMainExecutor;
    private final Executor mBgExecutor;
    private final AudioManager mAudioManager;
    private final LocalBluetoothProfileManager mProfileManager;
    private final HearingDevicesUiEventLogger mUiEventLogger;
    private final boolean mShowPairNewDevice;
    private final int mLaunchSourceId;
    private final QSSettingsPackageRepository mQSSettingsPackageRepository;

    private SystemUIDialog mDialog;
    private HearingDevicesListAdapter mDeviceListAdapter;

    private View mPresetLayout;
    private Spinner mPresetSpinner;
    private HearingDevicesPresetsController mPresetController;
    private HearingDevicesSpinnerAdapter mPresetInfoAdapter;

    private View mInputRoutingLayout;
    private Spinner mInputRoutingSpinner;
    private HearingDevicesInputRoutingController.Factory mInputRoutingControllerFactory;
    private HearingDevicesInputRoutingController mInputRoutingController;
    private HearingDevicesSpinnerAdapter mInputRoutingAdapter;

    private final HearingDevicesPresetsController.PresetCallback mPresetCallback =
            new HearingDevicesPresetsController.PresetCallback() {
                @Override
                public void onPresetInfoUpdated(List<BluetoothHapPresetInfo> presetInfos,
                        int activePresetIndex) {
                    mMainExecutor.execute(
                            () -> refreshPresetUi(presetInfos, activePresetIndex));
                }

                @Override
                public void onPresetCommandFailed(int reason) {
                    mPresetController.refreshPresetInfo();
                    mMainExecutor.execute(() -> {
                        showErrorToast(R.string.hearing_devices_presets_error);
                    });
                }
            };

    private AmbientVolumeUiController mAmbientController;

    private final List<DeviceItemFactory> mHearingDeviceItemFactoryList = List.of(
            new ActiveHearingDeviceItemFactory(),
            new AvailableHearingDeviceItemFactory(),
            new ConnectedHearingDeviceItemFactory(),
            new SavedHearingDeviceItemFactory()
    );

    /** Factory to create a {@link HearingDevicesDialogDelegate} dialog instance. */
    @AssistedFactory
    public interface Factory {
        /** Create a {@link HearingDevicesDialogDelegate} instance */
        HearingDevicesDialogDelegate create(
                boolean showPairNewDevice,
                @HearingDevicesUiEventLogger.LaunchSourceId int launchSource);
    }

    @AssistedInject
    public HearingDevicesDialogDelegate(
            @Assisted boolean showPairNewDevice,
            @Assisted @HearingDevicesUiEventLogger.LaunchSourceId int launchSourceId,
            SystemUIDialog.Factory systemUIDialogFactory,
            ActivityStarter activityStarter,
            DialogTransitionAnimator dialogTransitionAnimator,
            @Nullable LocalBluetoothManager localBluetoothManager,
            @Main Executor mainExecutor,
            @Background Executor bgExecutor,
            AudioManager audioManager,
            HearingDevicesUiEventLogger uiEventLogger,
            QSSettingsPackageRepository qsSettingsPackageRepository,
            HearingDevicesInputRoutingController.Factory inputRoutingControllerFactory) {
        mShowPairNewDevice = showPairNewDevice;
        mSystemUIDialogFactory = systemUIDialogFactory;
        mActivityStarter = activityStarter;
        mDialogTransitionAnimator = dialogTransitionAnimator;
        mLocalBluetoothManager = localBluetoothManager;
        mMainExecutor = mainExecutor;
        mBgExecutor = bgExecutor;
        mAudioManager = audioManager;
        mProfileManager = localBluetoothManager.getProfileManager();
        mUiEventLogger = uiEventLogger;
        mLaunchSourceId = launchSourceId;
        mQSSettingsPackageRepository = qsSettingsPackageRepository;
        mInputRoutingControllerFactory = inputRoutingControllerFactory;
    }

    @Override
    public SystemUIDialog createDialog() {
        SystemUIDialog dialog = mSystemUIDialogFactory.create(this);
        dismissDialogIfExists();
        mDialog = dialog;

        return dialog;
    }

    @Override
    public void onDeviceItemGearClicked(@NonNull DeviceItem deviceItem, @NonNull View view) {
        mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_GEAR_CLICK, mLaunchSourceId);
        dismissDialogIfExists();
        Bundle bundle = new Bundle();
        bundle.putString(KEY_BLUETOOTH_ADDRESS, deviceItem.getCachedBluetoothDevice().getAddress());
        Intent intent = new Intent(ACTION_BLUETOOTH_DEVICE_DETAILS)
                .setPackage(mQSSettingsPackageRepository.getSettingsPackageName())
                .putExtra(EXTRA_SHOW_FRAGMENT_ARGUMENTS, bundle);
        mActivityStarter.postStartActivityDismissingKeyguard(intent, /* delay= */ 0,
                mDialogTransitionAnimator.createActivityTransitionController(view));
    }

    @Override
    public void onDeviceItemClicked(@NonNull DeviceItem deviceItem, @NonNull View view) {
        CachedBluetoothDevice cachedBluetoothDevice = deviceItem.getCachedBluetoothDevice();
        switch (deviceItem.getType()) {
            case ACTIVE_MEDIA_BLUETOOTH_DEVICE, CONNECTED_BLUETOOTH_DEVICE -> {
                mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_DISCONNECT,
                        mLaunchSourceId);
                cachedBluetoothDevice.disconnect();
            }
            case AVAILABLE_MEDIA_BLUETOOTH_DEVICE -> {
                mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_SET_ACTIVE,
                        mLaunchSourceId);
                cachedBluetoothDevice.setActive();
            }
            case SAVED_BLUETOOTH_DEVICE -> {
                mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_CONNECT, mLaunchSourceId);
                cachedBluetoothDevice.connect();
            }
        }
    }

    @Override
    public void onActiveDeviceChanged(@Nullable CachedBluetoothDevice activeDevice,
            int bluetoothProfile) {
        List<DeviceItem> hearingDeviceItemList = getHearingDeviceItemList();
        refreshDeviceUi(hearingDeviceItemList);
        mMainExecutor.execute(() -> {
            CachedBluetoothDevice device = getActiveHearingDevice(hearingDeviceItemList);
            if (mPresetController != null) {
                mPresetController.setDevice(device);
                mPresetLayout.setVisibility(
                        mPresetController.isPresetControlAvailable() ? VISIBLE : GONE);
            }
            if (mInputRoutingController != null) {
                mInputRoutingController.setDevice(device);
                mInputRoutingController.isInputRoutingControlAvailable(
                        available -> mMainExecutor.execute(() -> mInputRoutingLayout.setVisibility(
                                available ? VISIBLE : GONE)));
            }
            if (mAmbientController != null) {
                mAmbientController.loadDevice(device);
            }
        });
    }

    @Override
    public void onProfileConnectionStateChanged(@NonNull CachedBluetoothDevice cachedDevice,
            int state, int bluetoothProfile) {
        List<DeviceItem> hearingDeviceItemList = getHearingDeviceItemList();
        refreshDeviceUi(hearingDeviceItemList);
    }

    @Override
    public void onAclConnectionStateChanged(@NonNull CachedBluetoothDevice cachedDevice,
            int state) {
        List<DeviceItem> hearingDeviceItemList = getHearingDeviceItemList();
        refreshDeviceUi(hearingDeviceItemList);
    }

    @Override
    public void beforeCreate(@NonNull SystemUIDialog dialog, @Nullable Bundle savedInstanceState) {
        dialog.setTitle(R.string.quick_settings_hearing_devices_dialog_title);
        dialog.setView(LayoutInflater.from(dialog.getContext()).inflate(
                R.layout.hearing_devices_tile_dialog, null));
        dialog.setNegativeButton(
                R.string.hearing_devices_settings_button,
                (dialogInterface, which) -> {
                    mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_SETTINGS_CLICK,
                            mLaunchSourceId);
                    final Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_DETAILS_SETTINGS)
                            .putExtra(Intent.EXTRA_COMPONENT_NAME,
                                    ACCESSIBILITY_HEARING_AIDS_COMPONENT_NAME.flattenToString())
                            .setPackage(mQSSettingsPackageRepository.getSettingsPackageName());

                    mActivityStarter.postStartActivityDismissingKeyguard(intent, /* delay= */ 0,
                            mDialogTransitionAnimator.createActivityTransitionController(
                                    dialog));
                },
                /* dismissOnClick = */ true
        );
        dialog.setPositiveButton(
                R.string.quick_settings_done,
                /* onClick = */ null,
                /* dismissOnClick = */ true
        );
    }

    @Override
    public void onCreate(@NonNull SystemUIDialog dialog, @Nullable Bundle savedInstanceState) {
        if (mLocalBluetoothManager == null) {
            return;
        }

        // Remove the default padding of the system ui dialog
        View container = dialog.findViewById(android.R.id.custom);
        if (container != null && container.getParent() != null) {
            View containerParent = (View) container.getParent();
            containerParent.setPadding(0, 0, 0, 0);
        }

        mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_DIALOG_SHOW, mLaunchSourceId);

        mBgExecutor.execute(() -> {
            List<DeviceItem> hearingDeviceItemList = getHearingDeviceItemList();
            CachedBluetoothDevice activeHearingDevice = getActiveHearingDevice(
                    hearingDeviceItemList);
            mLocalBluetoothManager.getEventManager().registerCallback(this);

            mMainExecutor.execute(() -> {
                setupDeviceListView(dialog, hearingDeviceItemList);
                setupPairNewDeviceButton(dialog);
                setupPresetSpinner(dialog, activeHearingDevice);
                if (com.android.settingslib.flags.Flags.hearingDevicesInputRoutingControl()) {
                    setupInputRoutingSpinner(dialog, activeHearingDevice);
                }
                if (com.android.settingslib.flags.Flags.hearingDevicesAmbientVolumeControl()) {
                    setupAmbientControls(activeHearingDevice);
                }
                setupRelatedToolsView(dialog);
            });
        });
    }

    @Override
    public void onStop(@NonNull SystemUIDialog dialog) {
        mBgExecutor.execute(() -> {
            if (mLocalBluetoothManager != null) {
                mLocalBluetoothManager.getEventManager().unregisterCallback(this);
            }
            if (mPresetController != null) {
                mPresetController.unregisterHapCallback();
            }
            if (mAmbientController != null) {
                mAmbientController.stop();
            }
        });
    }

    private void setupDeviceListView(SystemUIDialog dialog,
            List<DeviceItem> hearingDeviceItemList) {
        final RecyclerView deviceList = dialog.requireViewById(R.id.device_list);
        deviceList.setLayoutManager(new LinearLayoutManager(dialog.getContext()));
        mDeviceListAdapter = new HearingDevicesListAdapter(hearingDeviceItemList, this);
        deviceList.setAdapter(mDeviceListAdapter);
    }

    private void setupPresetSpinner(SystemUIDialog dialog,
            CachedBluetoothDevice activeHearingDevice) {
        mPresetController = new HearingDevicesPresetsController(mProfileManager, mPresetCallback);
        mPresetController.setDevice(activeHearingDevice);

        mPresetSpinner = dialog.requireViewById(R.id.preset_spinner);
        mPresetInfoAdapter = new HearingDevicesSpinnerAdapter(dialog.getContext());
        mPresetSpinner.setAdapter(mPresetInfoAdapter);
        // Disable redundant Touch & Hold accessibility action for Switch Access
        mPresetSpinner.setAccessibilityDelegate(new View.AccessibilityDelegate() {
            @Override
            public void onInitializeAccessibilityNodeInfo(@NonNull View host,
                    @NonNull AccessibilityNodeInfo info) {
                info.removeAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_LONG_CLICK);
                super.onInitializeAccessibilityNodeInfo(host, info);
            }
        });
        // Should call setSelection(index, false) for the spinner before setOnItemSelectedListener()
        // to avoid extra onItemSelected() get called when first register the listener.
        refreshPresetUi(mPresetController.getAllPresetInfo(),
                mPresetController.getActivePresetIndex());
        mPresetSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                mPresetInfoAdapter.setSelected(position);
                mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_PRESET_SELECT,
                        mLaunchSourceId);
                mPresetController.selectPreset(
                        mPresetController.getAllPresetInfo().get(position).getIndex());
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                // Do nothing
            }
        });

        mPresetLayout = dialog.requireViewById(R.id.preset_layout);
        mPresetLayout.setVisibility(mPresetController.isPresetControlAvailable() ? VISIBLE : GONE);
        mBgExecutor.execute(() -> mPresetController.registerHapCallback());
    }

    private void setupInputRoutingSpinner(SystemUIDialog dialog,
            CachedBluetoothDevice activeHearingDevice) {
        mInputRoutingController = mInputRoutingControllerFactory.create(dialog.getContext());
        mInputRoutingController.setDevice(activeHearingDevice);

        mInputRoutingSpinner = dialog.requireViewById(R.id.input_routing_spinner);
        mInputRoutingAdapter = new HearingDevicesSpinnerAdapter(dialog.getContext());
        mInputRoutingAdapter.addAll(
                HearingDevicesInputRoutingController.getInputRoutingOptions(dialog.getContext()));
        mInputRoutingSpinner.setAdapter(mInputRoutingAdapter);
        // Disable redundant Touch & Hold accessibility action for Switch Access
        mInputRoutingSpinner.setAccessibilityDelegate(new View.AccessibilityDelegate() {
            @Override
            public void onInitializeAccessibilityNodeInfo(@NonNull View host,
                    @NonNull AccessibilityNodeInfo info) {
                info.removeAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_LONG_CLICK);
                super.onInitializeAccessibilityNodeInfo(host, info);
            }
        });
        // Should call setSelection(index, false) for the spinner before setOnItemSelectedListener()
        // to avoid extra onItemSelected() get called when first register the listener.
        final int initialPosition =
                mInputRoutingController.getUserPreferredInputRoutingValue();
        mInputRoutingSpinner.setSelection(initialPosition, false);
        mInputRoutingAdapter.setSelected(initialPosition);
        mInputRoutingSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                mInputRoutingAdapter.setSelected(position);
                mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_INPUT_ROUTING_SELECT,
                        mLaunchSourceId);
                mInputRoutingController.selectInputRouting(position);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                // Do nothing
            }
        });

        mInputRoutingLayout = dialog.requireViewById(R.id.input_routing_layout);
        mInputRoutingController.isInputRoutingControlAvailable(
                available -> mMainExecutor.execute(() -> mInputRoutingLayout.setVisibility(
                        available ? VISIBLE : GONE)));
    }

    private void setupAmbientControls(CachedBluetoothDevice activeHearingDevice) {
        final AmbientVolumeLayout ambientLayout = mDialog.requireViewById(R.id.ambient_layout);
        ambientLayout.setUiEventLogger(mUiEventLogger, mLaunchSourceId);
        mAmbientController = new AmbientVolumeUiController(
                mDialog.getContext(), mLocalBluetoothManager, ambientLayout);
        mAmbientController.setShowUiWhenLocalDataExist(false);
        mAmbientController.loadDevice(activeHearingDevice);
        mBgExecutor.execute(() -> mAmbientController.start());
    }

    private void setupPairNewDeviceButton(SystemUIDialog dialog) {
        final Button pairButton = dialog.requireViewById(R.id.pair_new_device_button);
        pairButton.setVisibility(mShowPairNewDevice ? VISIBLE : GONE);
        if (mShowPairNewDevice) {
            pairButton.setOnClickListener(v -> {
                mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_PAIR, mLaunchSourceId);
                dismissDialogIfExists();
                final Intent intent = new Intent(Settings.ACTION_HEARING_DEVICE_PAIRING_SETTINGS)
                        .setPackage(mQSSettingsPackageRepository.getSettingsPackageName());
                mActivityStarter.postStartActivityDismissingKeyguard(intent, /* delay= */ 0,
                        mDialogTransitionAnimator.createActivityTransitionController(dialog));
            });
        }
    }

    private void setupRelatedToolsView(SystemUIDialog dialog) {
        final Context context = dialog.getContext();
        final List<ToolItem> toolItemList = new ArrayList<>();
        final String[] toolNameArray;
        final String[] toolIconArray;

        ToolItem preInstalledItem = getLiveCaptionToolItem(context);
        if (preInstalledItem != null) {
            toolItemList.add(preInstalledItem);
        }
        try {
            toolNameArray = context.getResources().getStringArray(
                    R.array.config_quickSettingsHearingDevicesRelatedToolName);
            toolIconArray = context.getResources().getStringArray(
                    R.array.config_quickSettingsHearingDevicesRelatedToolIcon);
            toolItemList.addAll(
                    HearingDevicesToolItemParser.parseStringArray(context, toolNameArray,
                    toolIconArray));
        } catch (Resources.NotFoundException e) {
            Log.i(TAG, "No hearing devices related tool config resource");
        }

        final View toolsLayout = dialog.requireViewById(R.id.tools_layout);
        toolsLayout.setVisibility(toolItemList.isEmpty() ? GONE : VISIBLE);

        final LinearLayout toolsContainer = dialog.requireViewById(R.id.tools_container);
        for (int i = 0; i < toolItemList.size(); i++) {
            View view = createToolView(context, toolItemList.get(i), toolsContainer);
            toolsContainer.addView(view);
            if (i != toolItemList.size() - 1) {
                final int spaceSize = context.getResources().getDimensionPixelSize(
                        R.dimen.hearing_devices_layout_margin);
                Space space = new Space(context);
                space.setLayoutParams(new LinearLayout.LayoutParams(spaceSize, 0));
                toolsContainer.addView(space);
            }
        }
    }

    private void refreshDeviceUi(List<DeviceItem> hearingDeviceItemList) {
        mMainExecutor.execute(() -> {
            if (mDeviceListAdapter != null) {
                mDeviceListAdapter.refreshDeviceItemList(hearingDeviceItemList);
            }
        });
    }

    private void refreshPresetUi(List<BluetoothHapPresetInfo> presetInfos, int activePresetIndex) {
        mPresetInfoAdapter.clear();
        mPresetInfoAdapter.addAll(
                presetInfos.stream().map(BluetoothHapPresetInfo::getName).toList());
        if (activePresetIndex != BluetoothHapClient.PRESET_INDEX_UNAVAILABLE) {
            final int size = mPresetInfoAdapter.getCount();
            for (int position = 0; position < size; position++) {
                if (presetInfos.get(position).getIndex() == activePresetIndex) {
                    mPresetSpinner.setSelection(position, /* animate= */ false);
                    mPresetInfoAdapter.setSelected(position);
                }
            }
        }
    }

    private List<DeviceItem> getHearingDeviceItemList() {
        if (mLocalBluetoothManager == null
                || !mLocalBluetoothManager.getBluetoothAdapter().isEnabled()) {
            return emptyList();
        }
        return mLocalBluetoothManager.getCachedDeviceManager().getCachedDevicesCopy().stream()
                .map(this::createHearingDeviceItem)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Nullable
    private static CachedBluetoothDevice getActiveHearingDevice(
            List<DeviceItem> hearingDeviceItemList) {
        return hearingDeviceItemList.stream()
                .filter(item -> item.getType() == DeviceItemType.ACTIVE_MEDIA_BLUETOOTH_DEVICE)
                .map(DeviceItem::getCachedBluetoothDevice)
                .findFirst()
                .orElse(null);
    }

    @WorkerThread
    private DeviceItem createHearingDeviceItem(CachedBluetoothDevice cachedDevice) {
        final Context context = mDialog.getContext();
        if (cachedDevice == null) {
            return null;
        }
        int mode = mAudioManager.getMode();
        boolean isOngoingCall = mode == AudioManager.MODE_RINGTONE
                || mode == AudioManager.MODE_IN_CALL
                || mode == AudioManager.MODE_IN_COMMUNICATION;
        for (DeviceItemFactory itemFactory : mHearingDeviceItemFactoryList) {
            if (itemFactory.isFilterMatched(context, cachedDevice, isOngoingCall)) {
                return itemFactory.create(context, cachedDevice);
            }
        }
        return null;
    }

    @NonNull
    private View createToolView(Context context, ToolItem item, ViewGroup container) {
        View view = LayoutInflater.from(context).inflate(R.layout.hearing_tool_item, container,
                false);
        ImageView icon = view.requireViewById(R.id.tool_icon);
        TextView text = view.requireViewById(R.id.tool_name);
        view.setContentDescription(item.getToolName());
        icon.setImageDrawable(item.getToolIcon());
        if (item.isCustomIcon()) {
            icon.getDrawable().mutate().setTint(context.getColor(
                    com.android.internal.R.color.materialColorOnPrimaryContainer));
        }
        text.setText(item.getToolName());
        Intent intent = item.getToolIntent();
        view.setOnClickListener(v -> {
            final String name = intent.getComponent() != null
                    ? intent.getComponent().flattenToString()
                    : intent.getPackage() + "/" + intent.getAction();
            mUiEventLogger.log(HearingDevicesUiEvent.HEARING_DEVICES_RELATED_TOOL_CLICK,
                    mLaunchSourceId, name);
            dismissDialogIfExists();
            mActivityStarter.postStartActivityDismissingKeyguard(intent, /* delay= */ 0,
                    mDialogTransitionAnimator.createActivityTransitionController(view));
        });
        return view;
    }

    private ToolItem getLiveCaptionToolItem(Context context) {
        final PackageManager packageManager = context.getPackageManager();
        LIVE_CAPTION_INTENT.setPackage(packageManager.getSystemCaptionsServicePackageName());
        final List<ResolveInfo> resolved = packageManager.queryIntentActivities(LIVE_CAPTION_INTENT,
                /* flags= */ 0);
        if (!resolved.isEmpty()) {
            return new ToolItem(
                    context.getString(R.string.quick_settings_hearing_devices_live_caption_title),
                    context.getDrawable(R.drawable.ic_volume_odi_captions),
                    LIVE_CAPTION_INTENT,
                    /* isCustomIcon= */ true);
        }
        return null;
    }

    private void dismissDialogIfExists() {
        if (mDialog != null) {
            mDialog.dismiss();
        }
    }

    private void showErrorToast(int stringResId) {
        Toast.makeText(mDialog.getContext(), stringResId, Toast.LENGTH_SHORT).show();
    }
}
