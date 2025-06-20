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

package android.app.appfunctions;

import static android.Manifest.permission.BIND_APP_FUNCTION_SERVICE;
import static android.app.appfunctions.flags.Flags.FLAG_ENABLE_APP_FUNCTION_MANAGER;
import static android.content.pm.PackageManager.PERMISSION_DENIED;

import android.annotation.FlaggedApi;
import android.annotation.MainThread;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.SdkConstant;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.SigningInfo;
import android.os.Binder;
import android.os.CancellationSignal;
import android.os.IBinder;
import android.os.ICancellationSignal;
import android.os.OutcomeReceiver;
import android.os.RemoteException;

/**
 * Abstract base class to provide app functions to the system.
 *
 * <p>Include the following in the manifest:
 *
 * <pre>
 * {@literal
 * <service android:name=".YourService"
 *       android:permission="android.permission.BIND_APP_FUNCTION_SERVICE">
 *    <intent-filter>
 *      <action android:name="android.app.appfunctions.AppFunctionService" />
 *    </intent-filter>
 * </service>
 * }
 * </pre>
 *
 * @see AppFunctionManager
 */
@FlaggedApi(FLAG_ENABLE_APP_FUNCTION_MANAGER)
public abstract class AppFunctionService extends Service {
    /**
     * The {@link Intent} that must be declared as handled by the service. To be supported, the
     * service must also require the {@link BIND_APP_FUNCTION_SERVICE} permission so that other
     * applications can not abuse it.
     */
    @SdkConstant(SdkConstant.SdkConstantType.SERVICE_ACTION)
    @NonNull
    public static final String SERVICE_INTERFACE = "android.app.appfunctions.AppFunctionService";

    /**
     * Functional interface to represent the execution logic of an app function.
     *
     * @hide
     */
    @FunctionalInterface
    public interface OnExecuteFunction {
        /**
         * Performs the semantic of executing the function specified by the provided request and
         * return the response through the provided callback.
         */
        void perform(
                @NonNull ExecuteAppFunctionRequest request,
                @NonNull String callingPackage,
                @NonNull SigningInfo callingPackageSigningInfo,
                @NonNull CancellationSignal cancellationSignal,
                @NonNull
                        OutcomeReceiver<ExecuteAppFunctionResponse, AppFunctionException> callback);
    }

    /** @hide */
    @NonNull
    public static Binder createBinder(
            @NonNull Context context, @NonNull OnExecuteFunction onExecuteFunction) {
        return new IAppFunctionService.Stub() {
            @Override
            public void executeAppFunction(
                    @NonNull ExecuteAppFunctionRequest request,
                    @NonNull String callingPackage,
                    @NonNull SigningInfo callingPackageSigningInfo,
                    @NonNull ICancellationCallback cancellationCallback,
                    @NonNull IExecuteAppFunctionCallback callback) {
                if (context.checkCallingPermission(BIND_APP_FUNCTION_SERVICE)
                        == PERMISSION_DENIED) {
                    throw new SecurityException("Can only be called by the system server.");
                }
                SafeOneTimeExecuteAppFunctionCallback safeCallback =
                        new SafeOneTimeExecuteAppFunctionCallback(callback);
                try {
                    onExecuteFunction.perform(
                            request,
                            callingPackage,
                            callingPackageSigningInfo,
                            buildCancellationSignal(cancellationCallback),
                            new OutcomeReceiver<>() {
                                @Override
                                public void onResult(ExecuteAppFunctionResponse result) {
                                    safeCallback.onResult(result);
                                }

                                @Override
                                public void onError(AppFunctionException exception) {
                                    safeCallback.onError(exception);
                                }
                            });
                } catch (Exception ex) {
                    // Apps should handle exceptions. But if they don't, report the error on
                    // behalf of them.
                    safeCallback.onError(
                            new AppFunctionException(toErrorCode(ex), ex.getMessage()));
                }
            }
        };
    }

    private static CancellationSignal buildCancellationSignal(
            @NonNull ICancellationCallback cancellationCallback) {
        final ICancellationSignal cancellationSignalTransport =
                CancellationSignal.createTransport();
        CancellationSignal cancellationSignal =
                CancellationSignal.fromTransport(cancellationSignalTransport);
        try {
            cancellationCallback.sendCancellationTransport(cancellationSignalTransport);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }

        return cancellationSignal;
    }

    private final Binder mBinder =
            createBinder(AppFunctionService.this, AppFunctionService.this::onExecuteFunction);

    @NonNull
    @Override
    public final IBinder onBind(@Nullable Intent intent) {
        return mBinder;
    }

    /**
     * Called by the system to execute a specific app function.
     *
     * <p>This method is the entry point for handling all app function requests in an app. When the
     * system needs your AppFunctionService to perform a function, it will invoke this method.
     *
     * <p>Each function you've registered is identified by a unique identifier. This identifier
     * doesn't need to be globally unique, but it must be unique within your app. For example, a
     * function to order food could be identified as "orderFood". In most cases, this identifier is
     * automatically generated by the AppFunctions SDK.
     *
     * <p>You can determine which function to execute by calling {@link
     * ExecuteAppFunctionRequest#getFunctionIdentifier()}. This allows your service to route the
     * incoming request to the appropriate logic for handling the specific function.
     *
     * <p>This method is always triggered in the main thread. You should run heavy tasks on a worker
     * thread and dispatch the result with the given callback. You should always report back the
     * result using the callback, no matter if the execution was successful or not.
     *
     * <p>This method also accepts a {@link CancellationSignal} that the app should listen to cancel
     * the execution of function if requested by the system.
     *
     * @param request The function execution request.
     * @param callingPackage The package name of the app that is requesting the execution.
     * @param callingPackageSigningInfo The signing information of the app that is requesting the
     *     execution.
     * @param cancellationSignal A signal to cancel the execution.
     * @param callback A callback to report back the result or error.
     */
    @MainThread
    public abstract void onExecuteFunction(
            @NonNull ExecuteAppFunctionRequest request,
            @NonNull String callingPackage,
            @NonNull SigningInfo callingPackageSigningInfo,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull OutcomeReceiver<ExecuteAppFunctionResponse, AppFunctionException> callback);

    /**
     * Returns result codes from throwable.
     *
     * @hide
     */
    private static @AppFunctionException.ErrorCode int toErrorCode(@NonNull Throwable t) {
        if (t instanceof IllegalArgumentException) {
            return AppFunctionException.ERROR_INVALID_ARGUMENT;
        }
        return AppFunctionException.ERROR_APP_UNKNOWN_ERROR;
    }
}
