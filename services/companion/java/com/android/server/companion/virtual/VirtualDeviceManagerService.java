/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.server.companion.virtual;

import static android.companion.virtual.VirtualDeviceParams.DEVICE_POLICY_DEFAULT;
import static android.companion.virtual.VirtualDeviceParams.POLICY_TYPE_DEFAULT_DEVICE_CAMERA_ACCESS;
import static android.media.AudioManager.AUDIO_SESSION_ID_GENERATE;

import static com.android.server.wm.ActivityInterceptorCallback.VIRTUAL_DEVICE_SERVICE_ORDERED_ID;

import android.annotation.EnforcePermission;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.SuppressLint;
import android.app.ActivityOptions;
import android.app.compat.CompatChanges;
import android.companion.AssociationInfo;
import android.companion.AssociationRequest;
import android.companion.CompanionDeviceManager;
import android.companion.virtual.IVirtualDevice;
import android.companion.virtual.IVirtualDeviceActivityListener;
import android.companion.virtual.IVirtualDeviceListener;
import android.companion.virtual.IVirtualDeviceManager;
import android.companion.virtual.IVirtualDeviceSoundEffectListener;
import android.companion.virtual.VirtualDevice;
import android.companion.virtual.VirtualDeviceManager;
import android.companion.virtual.VirtualDeviceParams;
import android.companion.virtual.sensor.VirtualSensor;
import android.companion.virtualnative.IVirtualDeviceManagerNative;
import android.compat.annotation.ChangeId;
import android.compat.annotation.EnabledAfter;
import android.content.AttributionSource;
import android.content.Context;
import android.content.Intent;
import android.hardware.display.DisplayManagerInternal;
import android.hardware.display.IVirtualDisplayCallback;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.LocaleList;
import android.os.Looper;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.UserHandle;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.ExceptionUtils;
import android.util.Slog;
import android.util.SparseArray;
import android.view.Display;
import android.widget.Toast;
import android.window.DisplayWindowPolicyController;

import com.android.internal.R;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.DumpUtils;
import com.android.internal.widget.LockPatternUtils;
import com.android.modules.expresslog.Counter;
import com.android.server.LocalServices;
import com.android.server.SystemService;
import com.android.server.companion.virtual.VirtualDeviceImpl.PendingTrampoline;
import com.android.server.wm.ActivityInterceptorCallback;
import com.android.server.wm.ActivityTaskManagerInternal;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@SuppressLint("LongLogTag")
public class VirtualDeviceManagerService extends SystemService {

    private static final String TAG = "VirtualDeviceManagerService";

    private static final String VIRTUAL_DEVICE_NATIVE_SERVICE = "virtualdevice_native";

    private static final List<String> VIRTUAL_DEVICE_COMPANION_DEVICE_PROFILES = Arrays.asList(
            AssociationRequest.DEVICE_PROFILE_AUTOMOTIVE_PROJECTION,
            AssociationRequest.DEVICE_PROFILE_APP_STREAMING,
            AssociationRequest.DEVICE_PROFILE_NEARBY_DEVICE_STREAMING,
            AssociationRequest.DEVICE_PROFILE_VIRTUAL_DEVICE);

    /** Enable default device camera access for apps running on virtual devices. */
    @ChangeId
    @EnabledAfter(targetSdkVersion = Build.VERSION_CODES.VANILLA_ICE_CREAM)
    public static final long ENABLE_DEFAULT_DEVICE_CAMERA_ACCESS = 371173368L;

    /**
     * A virtual device association id corresponding to no CDM association.
     */
    static final int CDM_ASSOCIATION_ID_NONE = 0;

    /**
     * Global VDM lock.
     *
     * Never call outside this class while holding this lock. A number of other system services like
     * WindowManager, DisplayManager, etc. call into VDM to get device-specific information, while
     * holding their own global locks.
     *
     * Making a call to another service while holding this lock creates lock order inversion and
     * will potentially cause a deadlock.
     */
    private final Object mVirtualDeviceManagerLock = new Object();

    private final VirtualDeviceManagerImpl mImpl;
    private final VirtualDeviceManagerNativeImpl mNativeImpl;
    private final VirtualDeviceManagerInternal mLocalService;
    private final VirtualDeviceLog mVirtualDeviceLog = new VirtualDeviceLog(getContext());
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final PendingTrampolineMap mPendingTrampolines = new PendingTrampolineMap(mHandler);

    private static AtomicInteger sNextUniqueIndex = new AtomicInteger(
            Context.DEVICE_ID_DEFAULT + 1);

    @GuardedBy("mVirtualDeviceManagerLock")
    private ArrayMap<String, AssociationInfo> mActiveAssociations = new ArrayMap<>();

    private class StrongAuthTracker extends LockPatternUtils.StrongAuthTracker {
        final Set<Integer> mUsersInLockdown = new ArraySet<>();

        StrongAuthTracker(Context context) {
            super(context);
        }

        @Override
        public synchronized void onStrongAuthRequiredChanged(int userId) {
            if ((getStrongAuthForUser(userId) & STRONG_AUTH_REQUIRED_AFTER_USER_LOCKDOWN) > 0) {
                if (mUsersInLockdown.add(userId) && mUsersInLockdown.size() == 1) {
                    onLockdownChanged(true);
                }
            } else if (mUsersInLockdown.remove(userId) && mUsersInLockdown.isEmpty()) {
                onLockdownChanged(false);
            }
        }
    }
    private StrongAuthTracker mStrongAuthTracker;

    private final RemoteCallbackList<IVirtualDeviceListener> mVirtualDeviceListeners =
            new RemoteCallbackList<>();

    /**
     * Mapping from device IDs to virtual devices.
     */
    @GuardedBy("mVirtualDeviceManagerLock")
    private final SparseArray<VirtualDeviceImpl> mVirtualDevices = new SparseArray<>();

    /**
     * Mapping from device IDs to app UIDs running on the corresponding virtual device.
     */
    @GuardedBy("mVirtualDeviceManagerLock")
    private final SparseArray<ArraySet<Integer>> mAppsOnVirtualDevices = new SparseArray<>();

    public VirtualDeviceManagerService(Context context) {
        super(context);
        mImpl = new VirtualDeviceManagerImpl();
        mNativeImpl = new VirtualDeviceManagerNativeImpl();
        mLocalService = new LocalService();
    }

    private final ActivityInterceptorCallback mActivityInterceptorCallback =
            new ActivityInterceptorCallback() {

                @Nullable
                @Override
                public ActivityInterceptResult onInterceptActivityLaunch(@NonNull
                        ActivityInterceptorInfo info) {
                    if (info.getCallingPackage() == null) {
                        return null;
                    }
                    PendingTrampoline pt = mPendingTrampolines.remove(info.getCallingPackage());
                    if (pt == null) {
                        return null;
                    }
                    pt.mResultReceiver.send(VirtualDeviceManager.LAUNCH_SUCCESS, null);
                    ActivityOptions options = info.getCheckedOptions();
                    if (options == null) {
                        options = ActivityOptions.makeBasic();
                    }
                    return new ActivityInterceptResult(
                            info.getIntent(), options.setLaunchDisplayId(pt.mDisplayId));
                }
            };

    @Override
    @RequiresPermission(android.Manifest.permission.MANAGE_COMPANION_DEVICES)
    public void onStart() {
        publishBinderService(Context.VIRTUAL_DEVICE_SERVICE, mImpl);
        publishBinderService(VIRTUAL_DEVICE_NATIVE_SERVICE, mNativeImpl);
        publishLocalService(VirtualDeviceManagerInternal.class, mLocalService);
        ActivityTaskManagerInternal activityTaskManagerInternal = getLocalService(
                ActivityTaskManagerInternal.class);
        activityTaskManagerInternal.registerActivityStartInterceptor(
                VIRTUAL_DEVICE_SERVICE_ORDERED_ID,
                mActivityInterceptorCallback);

        CompanionDeviceManager cdm = getContext().getSystemService(CompanionDeviceManager.class);
        if (cdm != null) {
            onCdmAssociationsChanged(cdm.getAllAssociations(UserHandle.USER_ALL));
            cdm.addOnAssociationsChangedListener(getContext().getMainExecutor(),
                    this::onCdmAssociationsChanged, UserHandle.USER_ALL);
        } else {
            Slog.e(TAG, "Failed to find CompanionDeviceManager. No CDM association info "
                    + " will be available.");
        }
        if (android.companion.virtualdevice.flags.Flags.deviceAwareDisplayPower()) {
            mStrongAuthTracker = new StrongAuthTracker(getContext());
            new LockPatternUtils(getContext()).registerStrongAuthTracker(mStrongAuthTracker);
        }
    }

    // Called when the global lockdown state changes, i.e. lockdown is considered active if any user
    // is in lockdown mode, and inactive if no users are in lockdown mode.
    void onLockdownChanged(boolean lockdownActive) {
        ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
        for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
            virtualDevicesSnapshot.get(i).onLockdownChanged(lockdownActive);
        }
    }

    private void onCameraAccessBlocked(int appUid) {
        ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
        for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
            VirtualDeviceImpl virtualDevice = virtualDevicesSnapshot.get(i);
            virtualDevice.showToastWhereUidIsRunning(appUid,
                    getContext().getString(
                            R.string.vdm_camera_access_denied,
                            virtualDevice.getDisplayName()),
                    Toast.LENGTH_LONG, Looper.myLooper());
        }
    }

    private CameraAccessController getCameraAccessController(UserHandle userHandle,
            VirtualDeviceParams params, String callingPackage) {
        if (CompatChanges.isChangeEnabled(ENABLE_DEFAULT_DEVICE_CAMERA_ACCESS, callingPackage,
                userHandle)
                && android.companion.virtualdevice.flags.Flags.defaultDeviceCameraAccessPolicy()
                && (params.getDevicePolicy(POLICY_TYPE_DEFAULT_DEVICE_CAMERA_ACCESS)
                    == DEVICE_POLICY_DEFAULT)) {
            return null;
        }
        int userId = userHandle.getIdentifier();
        ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
        for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
            final CameraAccessController cameraAccessController =
                    virtualDevicesSnapshot.get(i).getCameraAccessController();
            if (cameraAccessController.getUserId() == userId) {
                return cameraAccessController;
            }
        }        Context userContext = getContext().createContextAsUser(userHandle, 0);
        return new CameraAccessController(userContext, mLocalService, this::onCameraAccessBlocked);
    }

    @VisibleForTesting
    VirtualDeviceManagerInternal getLocalServiceInstance() {
        return mLocalService;
    }

    @VisibleForTesting
    void notifyRunningAppsChanged(int deviceId, ArraySet<Integer> uids) {
        synchronized (mVirtualDeviceManagerLock) {
            if (!mVirtualDevices.contains(deviceId)) {
                Slog.e(TAG, "notifyRunningAppsChanged called for unknown deviceId:" + deviceId
                        + " (maybe it was recently closed?)");
                return;
            }
            mAppsOnVirtualDevices.put(deviceId, uids);
        }
        mLocalService.onAppsOnVirtualDeviceChanged();
    }

    @VisibleForTesting
    void addVirtualDevice(VirtualDeviceImpl virtualDevice) {
        synchronized (mVirtualDeviceManagerLock) {
            mVirtualDevices.put(virtualDevice.getDeviceId(), virtualDevice);
        }
    }

    /**
     * Remove the virtual device. Sends the
     * {@link VirtualDeviceManager#ACTION_VIRTUAL_DEVICE_REMOVED} broadcast as a result.
     *
     * @param deviceId deviceId to be removed
     * @return {@code true} if the device was removed, {@code false} if the operation was a no-op
     */
    boolean removeVirtualDevice(int deviceId) {
        synchronized (mVirtualDeviceManagerLock) {
            if (!mVirtualDevices.contains(deviceId)) {
                return false;
            }

            mAppsOnVirtualDevices.remove(deviceId);
            mVirtualDevices.remove(deviceId);
        }

        mVirtualDeviceListeners.broadcast(listener -> {
            try {
                listener.onVirtualDeviceClosed(deviceId);
            } catch (RemoteException e) {
                Slog.i(TAG, "Failed to invoke onVirtualDeviceClosed listener: "
                        + e.getMessage());
            }
        });

        Intent i = new Intent(VirtualDeviceManager.ACTION_VIRTUAL_DEVICE_REMOVED);
        i.putExtra(VirtualDeviceManager.EXTRA_VIRTUAL_DEVICE_ID, deviceId);
        i.setFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY);
        final long identity = Binder.clearCallingIdentity();
        try {
            getContext().sendBroadcastAsUser(i, UserHandle.ALL);
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
        return true;
    }

    void onCdmAssociationsChanged(List<AssociationInfo> associations) {
        ArrayMap<String, AssociationInfo> vdmAssociations = new ArrayMap<>();
        for (int i = 0; i < associations.size(); ++i) {
            AssociationInfo association = associations.get(i);
            if (VIRTUAL_DEVICE_COMPANION_DEVICE_PROFILES.contains(association.getDeviceProfile())
                    && !association.isRevoked()) {
                String persistentId =
                        VirtualDeviceImpl.createPersistentDeviceId(association.getId());
                vdmAssociations.put(persistentId, association);
            }
        }
        Set<VirtualDeviceImpl> virtualDevicesToRemove = new HashSet<>();
        Set<String> removedPersistentDeviceIds;
        synchronized (mVirtualDeviceManagerLock) {
            removedPersistentDeviceIds = mActiveAssociations.keySet();
            removedPersistentDeviceIds.removeAll(vdmAssociations.keySet());
            mActiveAssociations = vdmAssociations;

            for (int i = 0; i < mVirtualDevices.size(); i++) {
                VirtualDeviceImpl virtualDevice = mVirtualDevices.valueAt(i);
                if (removedPersistentDeviceIds.contains(virtualDevice.getPersistentDeviceId())) {
                    virtualDevicesToRemove.add(virtualDevice);
                }
            }
        }

        for (VirtualDeviceImpl virtualDevice : virtualDevicesToRemove) {
            virtualDevice.close();
        }

        if (!removedPersistentDeviceIds.isEmpty()) {
            mLocalService.onPersistentDeviceIdsRemoved(removedPersistentDeviceIds);
        }
    }

    private ArrayList<VirtualDeviceImpl> getVirtualDevicesSnapshot() {
        synchronized (mVirtualDeviceManagerLock) {
            ArrayList<VirtualDeviceImpl> virtualDevices = new ArrayList<>(mVirtualDevices.size());
            for (int i = 0; i < mVirtualDevices.size(); i++) {
                virtualDevices.add(mVirtualDevices.valueAt(i));
            }
            return virtualDevices;
        }
    }

    private VirtualDeviceImpl getVirtualDeviceForId(int deviceId) {
        synchronized (mVirtualDeviceManagerLock) {
            return mVirtualDevices.get(deviceId);
        }
    }

    class VirtualDeviceManagerImpl extends IVirtualDeviceManager.Stub {

        private final VirtualDeviceImpl.PendingTrampolineCallback mPendingTrampolineCallback =
                new VirtualDeviceImpl.PendingTrampolineCallback() {
                    @Override
                    public void startWaitingForPendingTrampoline(
                            PendingTrampoline pendingTrampoline) {
                        PendingTrampoline existing = mPendingTrampolines.put(
                                pendingTrampoline.mPendingIntent.getCreatorPackage(),
                                pendingTrampoline);
                        if (existing != null) {
                            existing.mResultReceiver.send(
                                    VirtualDeviceManager.LAUNCH_FAILURE_NO_ACTIVITY, null);
                        }
                    }

                    @Override
                    public void stopWaitingForPendingTrampoline(
                            PendingTrampoline pendingTrampoline) {
                        mPendingTrampolines.remove(
                                pendingTrampoline.mPendingIntent.getCreatorPackage());
                    }
                };

        @EnforcePermission(android.Manifest.permission.CREATE_VIRTUAL_DEVICE)
        @Override // Binder call
        public IVirtualDevice createVirtualDevice(
                IBinder token,
                AttributionSource attributionSource,
                int associationId,
                @NonNull VirtualDeviceParams params,
                @NonNull IVirtualDeviceActivityListener activityListener,
                @NonNull IVirtualDeviceSoundEffectListener soundEffectListener) {
            createVirtualDevice_enforcePermission();
            Objects.requireNonNull(activityListener);
            Objects.requireNonNull(soundEffectListener);
            final String packageName = attributionSource.getPackageName();
            AssociationInfo associationInfo = getAssociationInfo(packageName, associationId);
            if (associationInfo == null) {
                throw new IllegalArgumentException("No association with ID " + associationId);
            } else if (!VIRTUAL_DEVICE_COMPANION_DEVICE_PROFILES.contains(
                    associationInfo.getDeviceProfile())) {
                throw new IllegalArgumentException("Unsupported CDM Association device profile "
                        + associationInfo.getDeviceProfile() + " for virtual device creation.");
            }
            return createVirtualDevice(token, attributionSource, associationInfo, params,
                    activityListener, soundEffectListener);
        }

        private IVirtualDevice createVirtualDevice(
                IBinder token,
                AttributionSource attributionSource,
                AssociationInfo associationInfo,
                @NonNull VirtualDeviceParams params,
                @Nullable IVirtualDeviceActivityListener activityListener,
                @Nullable IVirtualDeviceSoundEffectListener soundEffectListener) {
            createVirtualDevice_enforcePermission();
            attributionSource.enforceCallingUid();

            final String packageName = attributionSource.getPackageName();
            if (!PermissionUtils.validateCallingPackageName(getContext(), packageName)) {
                throw new SecurityException(
                        "Package name " + packageName + " does not belong to calling uid "
                                + getCallingUid());
            }
            Objects.requireNonNull(params);

            final UserHandle userHandle = getCallingUserHandle();
            final CameraAccessController cameraAccessController =
                    getCameraAccessController(userHandle, params,
                            attributionSource.getPackageName());
            final int deviceId = sNextUniqueIndex.getAndIncrement();
            final Consumer<ArraySet<Integer>> runningAppsChangedCallback =
                    runningUids -> notifyRunningAppsChanged(deviceId, runningUids);
            VirtualDeviceImpl virtualDevice = new VirtualDeviceImpl(getContext(), associationInfo,
                    VirtualDeviceManagerService.this, mVirtualDeviceLog, token, attributionSource,
                    deviceId,
                    cameraAccessController, mPendingTrampolineCallback, activityListener,
                    soundEffectListener, runningAppsChangedCallback, params);
            Counter.logIncrement("virtual_devices.value_virtual_devices_created_count");

            synchronized (mVirtualDeviceManagerLock) {
                mVirtualDevices.put(deviceId, virtualDevice);
            }

            mVirtualDeviceListeners.broadcast(listener -> {
                try {
                    listener.onVirtualDeviceCreated(deviceId);
                } catch (RemoteException e) {
                    Slog.i(TAG, "Failed to invoke onVirtualDeviceCreated listener: "
                            + e.getMessage());
                }
            });
            Counter.logIncrementWithUid(
                    "virtual_devices.value_virtual_devices_created_with_uid_count",
                    attributionSource.getUid());
            return virtualDevice;
        }

        @Override // Binder call
        public List<VirtualDevice> getVirtualDevices() {
            List<VirtualDevice> virtualDevices = new ArrayList<>();
            ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
            for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
                VirtualDeviceImpl device = virtualDevicesSnapshot.get(i);
                virtualDevices.add(device.getPublicVirtualDeviceObject());
            }
            return virtualDevices;
        }

        @Override // Binder call
        public VirtualDevice getVirtualDevice(int deviceId) {
            VirtualDeviceImpl device = getVirtualDeviceForId(deviceId);
            return device == null ? null : device.getPublicVirtualDeviceObject();
        }

        @Override // Binder call
        public void registerVirtualDeviceListener(IVirtualDeviceListener listener) {
            mVirtualDeviceListeners.register(listener);
        }

        @Override // Binder call
        public void unregisterVirtualDeviceListener(IVirtualDeviceListener listener) {
            mVirtualDeviceListeners.unregister(listener);
        }

        @Override // BinderCall
        @VirtualDeviceParams.DevicePolicy
        public int getDevicePolicy(int deviceId, @VirtualDeviceParams.PolicyType int policyType) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice != null
                    ? virtualDevice.getDevicePolicy(policyType) : DEVICE_POLICY_DEFAULT;
        }

        @Override // Binder call
        public int getDeviceIdForDisplayId(int displayId) {
            if (displayId == Display.INVALID_DISPLAY || displayId == Display.DEFAULT_DISPLAY) {
                return Context.DEVICE_ID_DEFAULT;
            }
            ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
            for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
                VirtualDeviceImpl virtualDevice = virtualDevicesSnapshot.get(i);
                if (virtualDevice.isDisplayOwnedByVirtualDevice(displayId)) {
                    return virtualDevice.getDeviceId();
                }
            }
            return Context.DEVICE_ID_DEFAULT;
        }

        @Override // Binder call
        public @Nullable CharSequence getDisplayNameForPersistentDeviceId(
                @NonNull String persistentDeviceId) {
            final AssociationInfo associationInfo;
            synchronized (mVirtualDeviceManagerLock) {
                associationInfo = mActiveAssociations.get(persistentDeviceId);
            }
            return associationInfo == null ? null : associationInfo.getDisplayName();
        }

        @Override // Binder call
        public @NonNull List<String> getAllPersistentDeviceIds() {
            return new ArrayList<>(mLocalService.getAllPersistentDeviceIds());
        }

        // Binder call
        @Override
        public boolean isValidVirtualDeviceId(int deviceId) {
            synchronized (mVirtualDeviceManagerLock) {
                return mVirtualDevices.contains(deviceId);
            }
        }

        @Override // Binder call
        public int getAudioPlaybackSessionId(int deviceId) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice != null
                    ? virtualDevice.getAudioPlaybackSessionId() : AUDIO_SESSION_ID_GENERATE;
        }

        @Override // Binder call
        public int getAudioRecordingSessionId(int deviceId) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice != null
                    ? virtualDevice.getAudioRecordingSessionId() : AUDIO_SESSION_ID_GENERATE;
        }

        @Override // Binder call
        public void playSoundEffect(int deviceId, int effectType) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);

            if (virtualDevice != null) {
                virtualDevice.playSoundEffect(effectType);
            }
        }

        @Override // Binder call
        public boolean isVirtualDeviceOwnedMirrorDisplay(int displayId) {
            if (getDeviceIdForDisplayId(displayId) == Context.DEVICE_ID_DEFAULT) {
                return false;
            }

            DisplayManagerInternal displayManager = LocalServices.getService(
                    DisplayManagerInternal.class);
            return displayManager.getDisplayIdToMirror(displayId) != Display.INVALID_DISPLAY;
        }

        @Nullable
        private AssociationInfo getAssociationInfo(String packageName, int associationId) {
            final UserHandle userHandle = getCallingUserHandle();
            final CompanionDeviceManager cdm =
                    getContext().createContextAsUser(userHandle, 0)
                            .getSystemService(CompanionDeviceManager.class);
            List<AssociationInfo> associations;
            final long identity = Binder.clearCallingIdentity();
            try {
                associations = cdm.getAllAssociations();
            } finally {
                Binder.restoreCallingIdentity(identity);
            }
            final int callingUserId = userHandle.getIdentifier();
            if (associations != null) {
                final int associationSize = associations.size();
                for (int i = 0; i < associationSize; i++) {
                    AssociationInfo associationInfo = associations.get(i);
                    if (associationInfo.belongsToPackage(callingUserId, packageName)
                            && associationId == associationInfo.getId()) {
                        return associationInfo;
                    }
                }
            } else {
                Slog.w(TAG, "No associations for user " + callingUserId);
            }
            return null;
        }

        @Override
        public boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            try {
                return super.onTransact(code, data, reply, flags);
            } catch (Throwable e) {
                Slog.e(TAG, "Error during IPC", e);
                throw ExceptionUtils.propagate(e, RemoteException.class);
            }
        }

        @Override
        public void dump(@NonNull FileDescriptor fd,
                @NonNull PrintWriter fout,
                @Nullable String[] args) {
            if (!DumpUtils.checkDumpAndUsageStatsPermission(getContext(), TAG, fout)) {
                return;
            }
            fout.println("Created virtual devices: ");
            ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
            for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
                virtualDevicesSnapshot.get(i).dump(fd, fout, args);
            }

            mVirtualDeviceLog.dump(fout);
        }
    }

    final class VirtualDeviceManagerNativeImpl extends IVirtualDeviceManagerNative.Stub {
        @Override // Binder call
        public int[] getDeviceIdsForUid(int uid) {
            return mLocalService
                    .getDeviceIdsForUid(uid).stream().mapToInt(Integer::intValue).toArray();
        }

        @Override // Binder call
        public int getDevicePolicy(int deviceId, int policyType) {
            return mImpl.getDevicePolicy(deviceId, policyType);
        }

        @Override // Binder call
        public int getDeviceIdForDisplayId(int displayId) {
            return mImpl.getDeviceIdForDisplayId(displayId);
        }
    }

    private final class LocalService extends VirtualDeviceManagerInternal {
        @GuardedBy("mVirtualDeviceManagerLock")
        private final ArrayList<AppsOnVirtualDeviceListener> mAppsOnVirtualDeviceListeners =
                new ArrayList<>();
        @GuardedBy("mVirtualDeviceManagerLock")
        private final ArrayList<Consumer<String>> mPersistentDeviceIdRemovedListeners =
                new ArrayList<>();

        @GuardedBy("mVirtualDeviceManagerLock")
        private final ArraySet<Integer> mAllUidsOnVirtualDevice = new ArraySet<>();

        @Override
        public @NonNull VirtualDeviceManager.VirtualDevice createVirtualDevice(
                @NonNull VirtualDeviceParams params) {
            Objects.requireNonNull(params, "params must not be null");
            Objects.requireNonNull(params.getName(), "virtual device name must not be null");
            IVirtualDevice virtualDevice = mImpl.createVirtualDevice(
                    new Binder(),
                    getContext().getAttributionSource(),
                    /* associationInfo= */ null,
                    params,
                    /* activityListener= */ null,
                    /* soundEffectListener= */ null);
            return new VirtualDeviceManager.VirtualDevice(getContext(), virtualDevice);
        }

        @Override
        public int getDeviceOwnerUid(int deviceId) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice != null ? virtualDevice.getOwnerUid() : Process.INVALID_UID;
        }

        @Override
        public @Nullable VirtualSensor getVirtualSensor(int deviceId, int handle) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice != null ? virtualDevice.getVirtualSensorByHandle(handle) : null;
        }

        @Override
        public @NonNull ArraySet<Integer> getDeviceIdsForUid(int uid) {
            ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
            ArraySet<Integer> result = new ArraySet<>();
            for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
                VirtualDeviceImpl device = virtualDevicesSnapshot.get(i);
                if (device.isAppRunningOnVirtualDevice(uid)) {
                    result.add(device.getDeviceId());
                }
            }
            return result;
        }

        @Override
        public void onVirtualDisplayCreated(IVirtualDevice virtualDevice, int displayId,
                IVirtualDisplayCallback callback, DisplayWindowPolicyController dwpc) {
            VirtualDeviceImpl virtualDeviceImpl = getVirtualDeviceForId(
                    ((VirtualDeviceImpl) virtualDevice).getDeviceId());
            if (virtualDeviceImpl != null) {
                virtualDeviceImpl.onVirtualDisplayCreated(displayId, callback, dwpc);
            }
        }

        @Override
        public void onVirtualDisplayRemoved(IVirtualDevice virtualDevice, int displayId) {
            VirtualDeviceImpl virtualDeviceImpl = getVirtualDeviceForId(
                    ((VirtualDeviceImpl) virtualDevice).getDeviceId());
            if (virtualDeviceImpl != null) {
                virtualDeviceImpl.onVirtualDisplayRemoved(displayId);
            }
        }

        @Override
        public void onAppsOnVirtualDeviceChanged() {
            ArraySet<Integer> latestRunningUids = new ArraySet<>();
            final AppsOnVirtualDeviceListener[] listeners;
            synchronized (mVirtualDeviceManagerLock) {
                int size = mAppsOnVirtualDevices.size();
                for (int i = 0; i < size; i++) {
                    latestRunningUids.addAll(mAppsOnVirtualDevices.valueAt(i));
                }
                if (!mAllUidsOnVirtualDevice.equals(latestRunningUids)) {
                    mAllUidsOnVirtualDevice.clear();
                    mAllUidsOnVirtualDevice.addAll(latestRunningUids);
                    listeners =
                            mAppsOnVirtualDeviceListeners.toArray(
                                    new AppsOnVirtualDeviceListener[0]);
                } else {
                    listeners = null;
                }
            }
            if (listeners != null) {
                mHandler.post(() -> {
                    for (AppsOnVirtualDeviceListener listener : listeners) {
                        listener.onAppsOnAnyVirtualDeviceChanged(latestRunningUids);
                    }
                });
            }
        }

        @Override
        public void onPersistentDeviceIdsRemoved(Set<String> removedPersistentDeviceIds) {
            final List<Consumer<String>> persistentDeviceIdRemovedListeners;
            synchronized (mVirtualDeviceManagerLock) {
                persistentDeviceIdRemovedListeners = List.copyOf(
                        mPersistentDeviceIdRemovedListeners);
            }
            mHandler.post(() -> {
                for (String persistentDeviceId : removedPersistentDeviceIds) {
                    for (Consumer<String> listener : persistentDeviceIdRemovedListeners) {
                        listener.accept(persistentDeviceId);
                    }
                }
            });
        }

        @Override
        public void onAuthenticationPrompt(int uid) {
            ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
            for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
                VirtualDeviceImpl device = virtualDevicesSnapshot.get(i);
                device.showToastWhereUidIsRunning(uid,
                        R.string.app_streaming_blocked_message_for_fingerprint_dialog,
                        Toast.LENGTH_LONG, Looper.getMainLooper());
            }
        }

        @Override
        public int getBaseVirtualDisplayFlags(IVirtualDevice virtualDevice) {
            return ((VirtualDeviceImpl) virtualDevice).getBaseVirtualDisplayFlags();
        }

        @Override
        @Nullable
        public LocaleList getPreferredLocaleListForUid(int uid) {
            // TODO: b/263188984 support the case where an app is running on multiple VDs
            VirtualDeviceImpl virtualDevice = null;
            synchronized (mVirtualDeviceManagerLock) {
                for (int i = 0; i < mAppsOnVirtualDevices.size(); i++) {
                    if (mAppsOnVirtualDevices.valueAt(i).contains(uid)) {
                        int deviceId = mAppsOnVirtualDevices.keyAt(i);
                        virtualDevice = mVirtualDevices.get(deviceId);
                        break;
                    }
                }
            }
            return virtualDevice == null ? null : virtualDevice.getDeviceLocaleList();
        }

        @Override
        public boolean isAppRunningOnAnyVirtualDevice(int uid) {
            ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
            for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
                if (virtualDevicesSnapshot.get(i).isAppRunningOnVirtualDevice(uid)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public boolean isInputDeviceOwnedByVirtualDevice(int inputDeviceId) {
            ArrayList<VirtualDeviceImpl> virtualDevicesSnapshot = getVirtualDevicesSnapshot();
            for (int i = 0; i < virtualDevicesSnapshot.size(); i++) {
                if (virtualDevicesSnapshot.get(i)
                        .isInputDeviceOwnedByVirtualDevice(inputDeviceId)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public @NonNull ArraySet<Integer> getDisplayIdsForDevice(int deviceId) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice == null ? new ArraySet<>()
                    : Arrays.stream(virtualDevice.getDisplayIds()).boxed()
                            .collect(Collectors.toCollection(ArraySet::new));
        }

        @Override
        public int getDeviceIdForDisplayId(int displayId) {
            return mImpl.getDeviceIdForDisplayId(displayId);
        }

        @Override
        public VirtualDevice getVirtualDevice(int deviceId) {
            return mImpl.getVirtualDevice(deviceId);
        }

        @Override
        public long getDimDurationMillisForDeviceId(int deviceId) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice == null ? -1 : virtualDevice.getDimDurationMillis();
        }

        @Override
        public long getScreenOffTimeoutMillisForDeviceId(int deviceId) {
            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice == null ? -1 : virtualDevice.getScreenOffTimeoutMillis();
        }

        @Override
        public boolean isValidVirtualDeviceId(int deviceId) {
            return mImpl.isValidVirtualDeviceId(deviceId);
        }

        @Override
        public @Nullable String getPersistentIdForDevice(int deviceId) {
            if (deviceId == Context.DEVICE_ID_DEFAULT) {
                return VirtualDeviceManager.PERSISTENT_DEVICE_ID_DEFAULT;
            }

            VirtualDeviceImpl virtualDevice = getVirtualDeviceForId(deviceId);
            return virtualDevice == null ? null : virtualDevice.getPersistentDeviceId();
        }

        @Override
        public @NonNull Set<String> getAllPersistentDeviceIds() {
            synchronized (mVirtualDeviceManagerLock) {
                return Set.copyOf(mActiveAssociations.keySet());
            }
        }

        @Override
        public void registerAppsOnVirtualDeviceListener(
                @NonNull AppsOnVirtualDeviceListener listener) {
            synchronized (mVirtualDeviceManagerLock) {
                mAppsOnVirtualDeviceListeners.add(listener);
            }
        }

        @Override
        public void unregisterAppsOnVirtualDeviceListener(
                @NonNull AppsOnVirtualDeviceListener listener) {
            synchronized (mVirtualDeviceManagerLock) {
                mAppsOnVirtualDeviceListeners.remove(listener);
            }
        }

        @Override
        public void registerPersistentDeviceIdRemovedListener(
                @NonNull Consumer<String> persistentDeviceIdRemovedListener) {
            synchronized (mVirtualDeviceManagerLock) {
                mPersistentDeviceIdRemovedListeners.add(persistentDeviceIdRemovedListener);
            }
        }

        @Override
        public void unregisterPersistentDeviceIdRemovedListener(
                @NonNull Consumer<String> persistentDeviceIdRemovedListener) {
            synchronized (mVirtualDeviceManagerLock) {
                mPersistentDeviceIdRemovedListeners.remove(persistentDeviceIdRemovedListener);
            }
        }
    }

    private static final class PendingTrampolineMap {
        /**
         * The maximum duration, in milliseconds, to wait for a trampoline activity launch after
         * invoking a pending intent.
         */
        private static final int TRAMPOLINE_WAIT_MS = 5000;

        private final ConcurrentHashMap<String, PendingTrampoline> mMap = new ConcurrentHashMap<>();
        private final Handler mHandler;

        PendingTrampolineMap(Handler handler) {
            mHandler = handler;
        }

        PendingTrampoline put(
                @NonNull String packageName, @NonNull PendingTrampoline pendingTrampoline) {
            PendingTrampoline existing = mMap.put(packageName, pendingTrampoline);
            mHandler.removeCallbacksAndMessages(existing);
            mHandler.postDelayed(
                    () -> {
                        final String creatorPackage =
                                pendingTrampoline.mPendingIntent.getCreatorPackage();
                        if (creatorPackage != null) {
                            remove(creatorPackage);
                        }
                    },
                    pendingTrampoline,
                    TRAMPOLINE_WAIT_MS);
            return existing;
        }

        PendingTrampoline remove(@NonNull String packageName) {
            PendingTrampoline pendingTrampoline = mMap.remove(packageName);
            mHandler.removeCallbacksAndMessages(pendingTrampoline);
            return pendingTrampoline;
        }
    }
}
