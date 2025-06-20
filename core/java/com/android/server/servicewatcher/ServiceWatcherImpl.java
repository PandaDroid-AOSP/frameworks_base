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

package com.android.server.servicewatcher;

import android.annotation.Nullable;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.location.flags.Flags;
import android.os.DeadObjectException;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.os.SystemClock;
import android.os.UserHandle;
import android.util.Log;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.content.PackageMonitor;
import com.android.internal.util.Preconditions;
import com.android.server.servicewatcher.ServiceWatcher.BoundServiceInfo;
import com.android.server.servicewatcher.ServiceWatcher.ServiceChangedListener;

import java.io.PrintWriter;
import java.util.Objects;

/**
 * Implementation of ServiceWatcher. Keeping the implementation separate from the interface allows
 * us to store the generic relationship between the service supplier and the service listener, while
 * hiding the generics from clients, simplifying the API.
 *
 * @hide
 */
class ServiceWatcherImpl<TBoundServiceInfo extends BoundServiceInfo> implements ServiceWatcher,
        ServiceChangedListener {

    static final String TAG = "ServiceWatcher";
    static final boolean D = Log.isLoggable(TAG, Log.DEBUG);

    static final long RETRY_DELAY_MS = 15 * 1000;
    /* Used for the unstable fallback logic, it is the time period in milliseconds where the number
     * of disconnections is tracked in order to determine if the service is unstable. */
    private static final long UNSTABLE_TIME_PERIOD_MS = 60 * 1000;
    /* Used for the unstable fallback logic, it is the number of disconnections within the time
     * period that will mark the service as unstable and allow the fallback to a stable service. */
    private static final int DISCONNECTED_COUNT_BEFORE_MARKED_AS_UNSTABLE = 10;

    final Context mContext;
    final Handler mHandler;
    final String mTag;
    final ServiceSupplier<TBoundServiceInfo> mServiceSupplier;
    final @Nullable ServiceListener<? super TBoundServiceInfo> mServiceListener;
    private boolean mUnstableFallbackEnabled;
    private @Nullable String mDisconnectedService;
    private long mDisconnectedStartTime;
    private int mDisconnectedCount;

    private final PackageMonitor mPackageMonitor = new PackageMonitor() {
        @Override
        public boolean onPackageChanged(String packageName, int uid, String[] components) {
            return true;
        }

        @Override
        public void onSomePackagesChanged() {
            onServiceChanged(false);
        }
    };

    @GuardedBy("this")
    private boolean mRegistered = false;
    @GuardedBy("this")
    private MyServiceConnection mServiceConnection = new MyServiceConnection(null);

    ServiceWatcherImpl(Context context, Handler handler, String tag,
            ServiceSupplier<TBoundServiceInfo> serviceSupplier,
            ServiceListener<? super TBoundServiceInfo> serviceListener) {
        mContext = context;
        mHandler = handler;
        mTag = tag;
        mServiceSupplier = serviceSupplier;
        mServiceListener = serviceListener;
    }

    ServiceWatcherImpl(Context context, Handler handler, String tag,
            boolean unstableFallbackEnabled,
            ServiceSupplier<TBoundServiceInfo> serviceSupplier,
            ServiceListener<? super TBoundServiceInfo> serviceListener) {
        mContext = context;
        mHandler = handler;
        mTag = tag;
        if (Flags.serviceWatcherUnstableFallback()) {
            mUnstableFallbackEnabled = unstableFallbackEnabled;
        }
        mServiceSupplier = serviceSupplier;
        mServiceListener = serviceListener;
    }

    @Override
    public boolean checkServiceResolves() {
        return mServiceSupplier.hasMatchingService();
    }

    @Override
    public synchronized void register() {
        Preconditions.checkState(!mRegistered);

        mRegistered = true;
        mPackageMonitor.register(mContext, UserHandle.ALL, mHandler);
        mServiceSupplier.register(this);

        onServiceChanged(false);
    }

    @Override
    public synchronized void unregister() {
        Preconditions.checkState(mRegistered);

        mServiceSupplier.unregister();
        mPackageMonitor.unregister();
        mRegistered = false;

        onServiceChanged(false);
    }

    @Override
    public synchronized void onServiceChanged() {
        onServiceChanged(false);
    }

    @Override
    public synchronized void runOnBinder(BinderOperation operation) {
        MyServiceConnection serviceConnection = mServiceConnection;
        mHandler.post(() -> serviceConnection.runOnBinder(operation));
    }

    synchronized void onServiceChanged(boolean forceRebind) {
        TBoundServiceInfo newBoundServiceInfo;
        if (mRegistered) {
            newBoundServiceInfo = mServiceSupplier.getServiceInfo();
        } else {
            newBoundServiceInfo = null;
        }

        // if the current connection is not connected, always force a rebind, helping with earlier
        // recovery when something goes wrong with a connection.
        forceRebind |= !mServiceConnection.isConnected();

        if (forceRebind || !Objects.equals(mServiceConnection.getBoundServiceInfo(),
                newBoundServiceInfo)) {
            Log.i(TAG, "[" + mTag + "] chose new implementation " + newBoundServiceInfo);
            MyServiceConnection oldServiceConnection = mServiceConnection;
            MyServiceConnection newServiceConnection = new MyServiceConnection(newBoundServiceInfo);
            mServiceConnection = newServiceConnection;
            mHandler.post(() -> {
                oldServiceConnection.unbind();
                newServiceConnection.bind();
            });
        }
    }

    @Override
    public String toString() {
        MyServiceConnection serviceConnection;
        synchronized (this) {
            serviceConnection = mServiceConnection;
        }

        return serviceConnection.getBoundServiceInfo().toString();
    }

    @Override
    public void dump(PrintWriter pw) {
        MyServiceConnection serviceConnection;
        synchronized (this) {
            serviceConnection = mServiceConnection;
        }

        pw.println("target service=" + serviceConnection.getBoundServiceInfo());
        pw.println("connected=" + serviceConnection.isConnected());
    }

    // runs on the handler thread, and expects most of it's methods to be called from that thread
    private class MyServiceConnection implements ServiceConnection {

        private final @Nullable TBoundServiceInfo mBoundServiceInfo;

        // volatile so that isConnected can be called from any thread easily
        private volatile @Nullable IBinder mBinder;
        private @Nullable Runnable mRebinder;
        private boolean mForcingRebind;

        MyServiceConnection(@Nullable TBoundServiceInfo boundServiceInfo) {
            mBoundServiceInfo = boundServiceInfo;
        }

        // may be called from any thread
        @Nullable TBoundServiceInfo getBoundServiceInfo() {
            return mBoundServiceInfo;
        }

        // may be called from any thread
        boolean isConnected() {
            return mBinder != null;
        }

        void bind() {
            Preconditions.checkState(Looper.myLooper() == mHandler.getLooper());

            if (mBoundServiceInfo == null) {
                return;
            }

            if (D) {
                Log.d(TAG, "[" + mTag + "] binding to " + mBoundServiceInfo);
            }

            mRebinder = null;

            Intent bindIntent = new Intent(mBoundServiceInfo.getAction()).setComponent(
                    mBoundServiceInfo.getComponentName());
            try {
                if (!mContext.bindServiceAsUser(bindIntent, this,
                        mBoundServiceInfo.getFlags(),
                        mHandler, UserHandle.of(mBoundServiceInfo.getUserId()))) {
                    Log.e(TAG, "[" + mTag + "] unexpected bind failure - retrying later");
                    mRebinder = this::bind;
                    mHandler.postDelayed(mRebinder, RETRY_DELAY_MS);
                }
            } catch (SecurityException e) {
                // if anything goes wrong it shouldn't crash the system server
                Log.e(TAG, "[" + mTag + "] " + mBoundServiceInfo + " bind failed", e);
            }
        }

        void unbind() {
            Preconditions.checkState(Looper.myLooper() == mHandler.getLooper());

            if (mBoundServiceInfo == null) {
                return;
            }

            if (D) {
                Log.d(TAG, "[" + mTag + "] unbinding from " + mBoundServiceInfo);
            }

            if (mRebinder != null) {
                mHandler.removeCallbacks(mRebinder);
                mRebinder = null;
            } else {
                mContext.unbindService(this);
            }

            onServiceDisconnected(mBoundServiceInfo.getComponentName());
        }

        void runOnBinder(BinderOperation operation) {
            Preconditions.checkState(Looper.myLooper() == mHandler.getLooper());

            if (mBinder == null) {
                operation.onError(new DeadObjectException());
                return;
            }

            try {
                operation.run(mBinder);
            } catch (RuntimeException | RemoteException e) {
                // binders may propagate some specific non-RemoteExceptions from the other side
                // through the binder as well - we cannot allow those to crash the system server
                Log.e(TAG, "[" + mTag + "] error running operation on " + mBoundServiceInfo, e);
                operation.onError(e);
            }
        }

        @Override
        public final void onServiceConnected(ComponentName component, IBinder binder) {
            Preconditions.checkState(Looper.myLooper() == mHandler.getLooper());
            Preconditions.checkState(mBinder == null);

            Log.i(TAG, "[" + mTag + "] connected to " + component.toShortString());

            mBinder = binder;
            /* Used to keep track of whether we are forcing a rebind, so that we don't force a
             * rebind while in the process of already forcing a rebind. This is needed because
             * onServiceDisconnected and onBindingDied can happen in quick succession and we only
             * want one rebind to happen in this case. */
            mForcingRebind = false;

            if (mServiceListener != null) {
                try {
                    mServiceListener.onBind(binder, mBoundServiceInfo);
                } catch (RuntimeException | RemoteException e) {
                    // binders may propagate some specific non-RemoteExceptions from the other side
                    // through the binder as well - we cannot allow those to crash the system server
                    Log.e(TAG, "[" + mTag + "] error running operation on " + mBoundServiceInfo, e);
                }
            }
        }

        @Override
        public final void onServiceDisconnected(ComponentName component) {
            Preconditions.checkState(Looper.myLooper() == mHandler.getLooper());

            if (mBinder == null) {
                return;
            }

            Log.i(TAG, "[" + mTag + "] disconnected from " + mBoundServiceInfo);

            mBinder = null;
            if (mServiceListener != null) {
                mServiceListener.onUnbind();
            }

            // If unstable fallback is not enabled or no current service is bound, then avoid the
            // unstable fallback logic below and return early.
            if (!mUnstableFallbackEnabled
                    || mBoundServiceInfo == null
                    || mBoundServiceInfo.toString() == null) {
                return;
            }

            String currentService = mBoundServiceInfo.toString();
            // If the service has already disconnected within the time period, increment the count.
            // Otherwise, set the service as disconnected, set the start time, and reset the count.
            if (Objects.equals(mDisconnectedService, currentService)
                    && mDisconnectedStartTime > 0
                    && (SystemClock.elapsedRealtime() - mDisconnectedStartTime
                            <= UNSTABLE_TIME_PERIOD_MS)) {
                mDisconnectedCount++;
            } else {
                mDisconnectedService = currentService;
                mDisconnectedStartTime = SystemClock.elapsedRealtime();
                mDisconnectedCount = 1;
            }
            Log.d(TAG, "[" + mTag + "] Service disconnected : " + currentService + " Count = "
                + mDisconnectedCount);
            if (mDisconnectedCount >= DISCONNECTED_COUNT_BEFORE_MARKED_AS_UNSTABLE) {
                Log.i(TAG, "[" + mTag + "] Service disconnected too many times, set as unstable : "
                    + mDisconnectedService);
                // Alert this service as unstable will last until the next device restart.
                mServiceSupplier.alertUnstableService(mDisconnectedService);
                mDisconnectedService = null;
                mDisconnectedStartTime = 0;
                mDisconnectedCount = 0;
                // Force rebind to allow the possibility of fallback to a stable service.
                if (!mForcingRebind) {
                    mForcingRebind = true;
                    onServiceChanged(/*forceRebind=*/ true);
                }
            }
        }

        @Override
        public final void onBindingDied(ComponentName component) {
            Preconditions.checkState(Looper.myLooper() == mHandler.getLooper());

            Log.w(TAG, "[" + mTag + "] " + mBoundServiceInfo + " died");

            // introduce a small delay to prevent spamming binding over and over, since the likely
            // cause of a binding dying is some package event that may take time to recover from
            if (!mForcingRebind) {
                mForcingRebind = true;
                mHandler.postDelayed(() -> onServiceChanged(/*forceRebind=*/ true), 500);
            }
        }

        @Override
        public final void onNullBinding(ComponentName component) {
            Log.e(TAG, "[" + mTag + "] " + mBoundServiceInfo + " has null binding");
        }
    }
}
