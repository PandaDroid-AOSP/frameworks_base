/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.server.location.contexthub;

import static android.content.pm.PackageManager.PERMISSION_GRANTED;

import android.Manifest;
import android.app.AppOpsManager;
import android.content.Context;
import android.hardware.contexthub.EndpointInfo;
import android.hardware.contexthub.HubEndpoint;
import android.hardware.contexthub.HubEndpointInfo;
import android.hardware.contexthub.HubMessage;
import android.hardware.contexthub.HubServiceInfo;
import android.hardware.contexthub.Message;
import android.hardware.contexthub.Reason;
import android.hardware.contexthub.V1_0.AsyncEventType;
import android.hardware.contexthub.V1_0.ContextHubMsg;
import android.hardware.contexthub.V1_0.HostEndPoint;
import android.hardware.contexthub.V1_0.Result;
import android.hardware.contexthub.V1_2.HubAppInfo;
import android.hardware.location.ContextHubInfo;
import android.hardware.location.ContextHubTransaction;
import android.hardware.location.NanoAppBinary;
import android.hardware.location.NanoAppMessage;
import android.hardware.location.NanoAppRpcService;
import android.hardware.location.NanoAppState;
import android.util.Log;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

/**
 * A class encapsulating helper functions used by the ContextHubService class
 */
/* package */ class ContextHubServiceUtil {
    private static final String TAG = "ContextHubServiceUtil";
    private static final String CONTEXT_HUB_PERMISSION = Manifest.permission.ACCESS_CONTEXT_HUB;

    /**
     * A host endpoint that is reserved to identify a broadcasted message.
     */
    private static final char HOST_ENDPOINT_BROADCAST = 0xFFFF;


    /*
     * The format for printing to logs.
     */
    private static final String DATE_FORMAT = "MM/dd HH:mm:ss.SSS";

    /**
     * The DateTimeFormatter for printing to logs.
     */
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern(DATE_FORMAT)
            .withZone(ZoneId.systemDefault());

    /**
     * Creates a ConcurrentHashMap of the Context Hub ID to the ContextHubInfo object given an
     * ArrayList of HIDL ContextHub objects.
     *
     * @param hubList the ContextHub ArrayList
     * @return the HashMap object
     */
    /* package */
    static HashMap<Integer, ContextHubInfo> createContextHubInfoMap(List<ContextHubInfo> hubList) {
        HashMap<Integer, ContextHubInfo> contextHubIdToInfoMap = new HashMap<>();
        for (ContextHubInfo contextHubInfo : hubList) {
            contextHubIdToInfoMap.put(contextHubInfo.getId(), contextHubInfo);
        }

        return contextHubIdToInfoMap;
    }

    /**
     * Copies a primitive byte array to a ArrayList<Byte>.
     *
     * @param inputArray  the primitive byte array
     * @param outputArray the ArrayList<Byte> array to append
     */
    /* package */
    static void copyToByteArrayList(byte[] inputArray, ArrayList<Byte> outputArray) {
        outputArray.clear();
        outputArray.ensureCapacity(inputArray.length);
        for (byte element : inputArray) {
            outputArray.add(element);
        }
    }

    /**
     * Creates a byte array given a ArrayList<Byte> and copies its contents.
     *
     * @param array the ArrayList<Byte> object
     * @return the byte array
     */
    /* package */
    static byte[] createPrimitiveByteArray(ArrayList<Byte> array) {
        byte[] primitiveArray = new byte[array.size()];
        for (int i = 0; i < array.size(); i++) {
            primitiveArray[i] = array.get(i);
        }

        return primitiveArray;
    }

    /**
     * Creates a primitive integer array given a Collection<Integer>.
     *
     * @param collection the collection to iterate
     * @return the primitive integer array
     */
    static int[] createPrimitiveIntArray(Collection<Integer> collection) {
        int[] primitiveArray = new int[collection.size()];

        int i = 0;
        for (int contextHubId : collection) {
            primitiveArray[i++] = contextHubId;
        }

        return primitiveArray;
    }

    /**
     * Generates the Context Hub HAL's HIDL NanoAppBinary object from the client-facing
     * android.hardware.location.NanoAppBinary object.
     *
     * @param nanoAppBinary the client-facing NanoAppBinary object
     * @return the Context Hub HAL's HIDL NanoAppBinary object
     */
    /* package */
    static android.hardware.contexthub.V1_0.NanoAppBinary createHidlNanoAppBinary(
            NanoAppBinary nanoAppBinary) {
        android.hardware.contexthub.V1_0.NanoAppBinary hidlNanoAppBinary =
                new android.hardware.contexthub.V1_0.NanoAppBinary();

        hidlNanoAppBinary.appId = nanoAppBinary.getNanoAppId();
        hidlNanoAppBinary.appVersion = nanoAppBinary.getNanoAppVersion();
        hidlNanoAppBinary.flags = nanoAppBinary.getFlags();
        hidlNanoAppBinary.targetChreApiMajorVersion = nanoAppBinary.getTargetChreApiMajorVersion();
        hidlNanoAppBinary.targetChreApiMinorVersion = nanoAppBinary.getTargetChreApiMinorVersion();

        // Log exceptions while processing the binary, but continue to pass down the binary
        // since the error checking is deferred to the Context Hub.
        try {
            copyToByteArrayList(nanoAppBinary.getBinaryNoHeader(), hidlNanoAppBinary.customBinary);
        } catch (IndexOutOfBoundsException e) {
            Log.w(TAG, e.getMessage());
        } catch (NullPointerException e) {
            Log.w(TAG, "NanoApp binary was null");
        }

        return hidlNanoAppBinary;
    }

    /**
     * Generates the Context Hub HAL's AIDL NanoAppBinary object from the client-facing
     * android.hardware.location.NanoAppBinary object.
     *
     * @param nanoAppBinary the client-facing NanoAppBinary object
     * @return the Context Hub HAL's AIDL NanoAppBinary object
     */
    /* package */
    static android.hardware.contexthub.NanoappBinary createAidlNanoAppBinary(
            NanoAppBinary nanoAppBinary) {
        android.hardware.contexthub.NanoappBinary aidlNanoAppBinary =
                new android.hardware.contexthub.NanoappBinary();

        aidlNanoAppBinary.nanoappId = nanoAppBinary.getNanoAppId();
        aidlNanoAppBinary.nanoappVersion = nanoAppBinary.getNanoAppVersion();
        aidlNanoAppBinary.flags = nanoAppBinary.getFlags();
        aidlNanoAppBinary.targetChreApiMajorVersion = nanoAppBinary.getTargetChreApiMajorVersion();
        aidlNanoAppBinary.targetChreApiMinorVersion = nanoAppBinary.getTargetChreApiMinorVersion();
        // This explicit definition is required to avoid erroneous behavior at the binder.
        aidlNanoAppBinary.customBinary = new byte[0];

        // Log exceptions while processing the binary, but continue to pass down the binary
        // since the error checking is deferred to the Context Hub.
        try {
            aidlNanoAppBinary.customBinary = nanoAppBinary.getBinaryNoHeader();
        } catch (IndexOutOfBoundsException e) {
            Log.w(TAG, e.getMessage());
        } catch (NullPointerException e) {
            Log.w(TAG, "NanoApp binary was null");
        }

        return aidlNanoAppBinary;
    }

    /**
     * Generates a client-facing NanoAppState array from a HAL HubAppInfo array.
     *
     * @param nanoAppInfoList the array of HubAppInfo objects
     * @return the corresponding array of NanoAppState objects
     */
    /* package */
    static List<NanoAppState> createNanoAppStateList(
            List<HubAppInfo> nanoAppInfoList) {
        ArrayList<NanoAppState> nanoAppStateList = new ArrayList<>();
        for (HubAppInfo appInfo : nanoAppInfoList) {
            nanoAppStateList.add(
                    new NanoAppState(appInfo.info_1_0.appId, appInfo.info_1_0.version,
                            appInfo.info_1_0.enabled, appInfo.permissions));
        }

        return nanoAppStateList;
    }

    /**
     * Generates a client-facing NanoAppState array from a AIDL NanoappInfo array.
     *
     * @param nanoAppInfoList the array of NanoappInfo objects
     * @return the corresponding array of NanoAppState objects
     */
    /* package */
    static List<NanoAppState> createNanoAppStateList(
            android.hardware.contexthub.NanoappInfo[] nanoAppInfoList) {
        ArrayList<NanoAppState> nanoAppStateList = new ArrayList<>();
        for (android.hardware.contexthub.NanoappInfo appInfo : nanoAppInfoList) {
            ArrayList<NanoAppRpcService> rpcServiceList = new ArrayList<>();
            for (android.hardware.contexthub.NanoappRpcService service : appInfo.rpcServices) {
                rpcServiceList.add(new NanoAppRpcService(service.id, service.version));
            }
            nanoAppStateList.add(
                    new NanoAppState(appInfo.nanoappId, appInfo.nanoappVersion,
                            appInfo.enabled, new ArrayList<>(Arrays.asList(appInfo.permissions)),
                            rpcServiceList));
        }

        return nanoAppStateList;
    }

    /**
     * Creates a HIDL ContextHubMsg object to send to a nanoapp.
     *
     * @param hostEndPoint the ID of the client sending the message
     * @param message      the client-facing NanoAppMessage object describing the message
     * @return the HIDL ContextHubMsg object
     */
    /* package */
    static ContextHubMsg createHidlContextHubMessage(short hostEndPoint, NanoAppMessage message) {
        ContextHubMsg hidlMessage = new ContextHubMsg();

        hidlMessage.appName = message.getNanoAppId();
        hidlMessage.hostEndPoint = hostEndPoint;
        hidlMessage.msgType = message.getMessageType();
        copyToByteArrayList(message.getMessageBody(), hidlMessage.msg);

        return hidlMessage;
    }

    /**
     * Creates an AIDL ContextHubMessage object to send to a nanoapp.
     *
     * @param hostEndPoint the ID of the client sending the message
     * @param message      the client-facing NanoAppMessage object describing the message
     * @return the AIDL ContextHubMessage object
     */
    /* package */
    static android.hardware.contexthub.ContextHubMessage createAidlContextHubMessage(
            short hostEndPoint, NanoAppMessage message) {
        android.hardware.contexthub.ContextHubMessage aidlMessage =
                new android.hardware.contexthub.ContextHubMessage();

        aidlMessage.nanoappId = message.getNanoAppId();
        aidlMessage.hostEndPoint = (char) hostEndPoint;
        aidlMessage.messageType = message.getMessageType();
        aidlMessage.messageBody = message.getMessageBody();
        // This explicit definition is required to avoid erroneous behavior at the binder.
        aidlMessage.permissions = new String[0];
        aidlMessage.isReliable = message.isReliable();
        aidlMessage.messageSequenceNumber = message.getMessageSequenceNumber();

        return aidlMessage;
    }

    /**
     * Creates a client-facing NanoAppMessage object to send to a client.
     *
     * @param message the HIDL ContextHubMsg object from a nanoapp
     * @return the NanoAppMessage object
     */
    /* package */
    static NanoAppMessage createNanoAppMessage(ContextHubMsg message) {
        byte[] messageArray = createPrimitiveByteArray(message.msg);

        return NanoAppMessage.createMessageFromNanoApp(
                message.appName, message.msgType, messageArray,
                message.hostEndPoint == HostEndPoint.BROADCAST);
    }

    /**
     * Creates a client-facing NanoAppMessage object to send to a client.
     *
     * @param message the AIDL ContextHubMessage object from a nanoapp
     * @return the NanoAppMessage object
     */
    /* package */
    static NanoAppMessage createNanoAppMessage(
            android.hardware.contexthub.ContextHubMessage message) {
        return NanoAppMessage.createMessageFromNanoApp(
                message.nanoappId, message.messageType, message.messageBody,
                message.hostEndPoint == HOST_ENDPOINT_BROADCAST,
                message.isReliable, message.messageSequenceNumber);
    }

    /**
     * Checks for ACCESS_CONTEXT_HUB permissions.
     *
     * @param context the context of the service
     */
    /* package */
    static void checkPermissions(Context context) {
        context.enforceCallingOrSelfPermission(CONTEXT_HUB_PERMISSION,
                "ACCESS_CONTEXT_HUB permission required to use Context Hub");
    }

    /**
     * Helper function to convert from the HAL Result enum error code to the
     * ContextHubTransaction.Result type.
     *
     * @param halResult the Result enum error code
     * @return the ContextHubTransaction.Result equivalent
     */
    @ContextHubTransaction.Result
    /* package */
    static int toTransactionResult(int halResult) {
        switch (halResult) {
            case Result.OK:
                return ContextHubTransaction.RESULT_SUCCESS;
            case Result.BAD_PARAMS:
                return ContextHubTransaction.RESULT_FAILED_BAD_PARAMS;
            case Result.NOT_INIT:
                return ContextHubTransaction.RESULT_FAILED_UNINITIALIZED;
            case Result.TRANSACTION_PENDING:
                return ContextHubTransaction.RESULT_FAILED_BUSY;
            case Result.TRANSACTION_FAILED:
            case Result.UNKNOWN_FAILURE:
            default: /* fall through */
                return ContextHubTransaction.RESULT_FAILED_UNKNOWN;
        }
    }

    /**
     * Converts old list of HubAppInfo received from the HAL to V1.2 HubAppInfo objects.
     *
     * @param oldInfoList list of V1.0 HubAppInfo objects
     * @return list of V1.2 HubAppInfo objects
     */
    /* package */
    static ArrayList<HubAppInfo> toHubAppInfo_1_2(
            ArrayList<android.hardware.contexthub.V1_0.HubAppInfo> oldInfoList) {
        ArrayList newAppInfo = new ArrayList<HubAppInfo>();
        for (android.hardware.contexthub.V1_0.HubAppInfo oldInfo : oldInfoList) {
            HubAppInfo newInfo = new HubAppInfo();
            newInfo.info_1_0.appId = oldInfo.appId;
            newInfo.info_1_0.version = oldInfo.version;
            newInfo.info_1_0.memUsage = oldInfo.memUsage;
            newInfo.info_1_0.enabled = oldInfo.enabled;
            newInfo.permissions = new ArrayList<String>();
            newAppInfo.add(newInfo);
        }
        return newAppInfo;
    }

    /**
     * Converts a HIDL AsyncEventType to the corresponding ContextHubService.CONTEXT_HUB_EVENT_*.
     *
     * @param hidlEventType The AsyncEventType value.
     * @return The converted event type.
     */
    /* package */
    static int toContextHubEvent(int hidlEventType) {
        switch (hidlEventType) {
            case AsyncEventType.RESTARTED:
                return ContextHubService.CONTEXT_HUB_EVENT_RESTARTED;
            default:
                Log.e(TAG, "toContextHubEvent: Unknown event type: " + hidlEventType);
                return ContextHubService.CONTEXT_HUB_EVENT_UNKNOWN;
        }
    }

    /**
     * Converts an AIDL AsyncEventType to the corresponding ContextHubService.CONTEXT_HUB_EVENT_*.
     *
     * @param aidlEventType The AsyncEventType value.
     * @return The converted event type.
     */
    /* package */
    static int toContextHubEventFromAidl(int aidlEventType) {
        switch (aidlEventType) {
            case android.hardware.contexthub.AsyncEventType.RESTARTED:
                return ContextHubService.CONTEXT_HUB_EVENT_RESTARTED;
            default:
                Log.e(TAG, "toContextHubEventFromAidl: Unknown event type: " + aidlEventType);
                return ContextHubService.CONTEXT_HUB_EVENT_UNKNOWN;
        }
    }

    /**
     * Converts a timestamp in milliseconds to a properly-formatted date string for log output.
     *
     * @param timeStampInMs     the timestamp in milliseconds
     * @return                  the formatted date string
     */
    /* package */
    static String formatDateFromTimestamp(long timeStampInMs) {
        return DATE_FORMATTER.format(Instant.ofEpochMilli(timeStampInMs));
    }

    /**
     * Converts a context hub HAL EndpointInfo object based on the provided HubEndpointInfo.
     *
     * @param info the HubEndpointInfo object
     * @return the equivalent EndpointInfo object
     */
    /* package */
    static EndpointInfo convertHalEndpointInfo(HubEndpointInfo info) {
        return createHalEndpointInfo(
                info, info.getIdentifier().getEndpoint(), info.getIdentifier().getHub());
    }

    /**
     * Creates a context hub HAL EndpointInfo object based on the provided HubEndpointInfo. As
     * opposed to convertHalEndpointInfo, this method can be used to overwrite/specify the endpoint
     * and hub ID.
     *
     * @param info the HubEndpointInfo object
     * @param endpointId the endpoint ID of this object
     * @param hubId the hub ID of this object
     * @return the equivalent EndpointInfo object
     */
    /* package */
    static EndpointInfo createHalEndpointInfo(HubEndpointInfo info, long endpointId, long hubId) {
        EndpointInfo outputInfo = new EndpointInfo();
        outputInfo.id = new android.hardware.contexthub.EndpointId();
        outputInfo.id.id = endpointId;
        outputInfo.id.hubId = hubId;
        outputInfo.name = info.getName();
        outputInfo.version = info.getVersion();
        outputInfo.tag = info.getTag();
        Collection<String> permissions = info.getRequiredPermissions();
        outputInfo.requiredPermissions = permissions.toArray(new String[permissions.size()]);
        Collection<HubServiceInfo> services = info.getServiceInfoCollection();
        outputInfo.services = new android.hardware.contexthub.Service[services.size()];
        int i = 0;
        for (HubServiceInfo service : services) {
            outputInfo.services[i] = new android.hardware.contexthub.Service();
            outputInfo.services[i].format = service.getFormat();
            outputInfo.services[i].serviceDescriptor = service.getServiceDescriptor();
            outputInfo.services[i].majorVersion = service.getMajorVersion();
            outputInfo.services[i].minorVersion = service.getMinorVersion();
            i++;
        }
        return outputInfo;
    }

    /**
     * Converts a HubMessage object to a AIDL HAL Message object.
     *
     * @param message the HubMessage message to convert
     * @return the AIDL HAL message
     */
    /* package */
    static Message createHalMessage(HubMessage message) {
        Message outMessage = new Message();
        outMessage.flags = message.isResponseRequired() ? Message.FLAG_REQUIRES_DELIVERY_STATUS : 0;
        outMessage.permissions = new String[0];
        outMessage.sequenceNumber = message.getMessageSequenceNumber();
        outMessage.type = message.getMessageType();
        outMessage.content = message.getMessageBody();
        return outMessage;
    }

    /**
     * Converts a AIDL HAL Message object to a HubMessage object.
     *
     * @param message the AIDL HAL Message message to convert
     * @return the HubMessage
     */
    /* package */
    static HubMessage createHubMessage(Message message) {
        boolean isReliable = (message.flags & Message.FLAG_REQUIRES_DELIVERY_STATUS) != 0;
        HubMessage outMessage = new HubMessage.Builder(message.type, message.content)
                .setResponseRequired(isReliable)
                .build();
        outMessage.setMessageSequenceNumber(message.sequenceNumber);
        return outMessage;
    }

    /**
     * Converts a byte integer defined by Reason.aidl to HubEndpoint.Reason values exposed to apps.
     *
     * @param reason The Reason.aidl value
     * @return The converted HubEndpoint.Reason value
     */
    /* package */
    static @HubEndpoint.Reason int toAppHubEndpointReason(byte reason) {
        switch (reason) {
            case Reason.UNSPECIFIED:
            case Reason.OUT_OF_MEMORY:
            case Reason.TIMEOUT:
                return HubEndpoint.REASON_FAILURE;
            case Reason.OPEN_ENDPOINT_SESSION_REQUEST_REJECTED:
                return HubEndpoint.REASON_OPEN_ENDPOINT_SESSION_REQUEST_REJECTED;
            case Reason.CLOSE_ENDPOINT_SESSION_REQUESTED:
                return HubEndpoint.REASON_CLOSE_ENDPOINT_SESSION_REQUESTED;
            case Reason.ENDPOINT_INVALID:
                return HubEndpoint.REASON_ENDPOINT_INVALID;
            case Reason.ENDPOINT_GONE:
            case Reason.ENDPOINT_CRASHED:
            case Reason.HUB_RESET:
                return HubEndpoint.REASON_ENDPOINT_STOPPED;
            case Reason.PERMISSION_DENIED:
                return HubEndpoint.REASON_PERMISSION_DENIED;
            default:
                Log.w(TAG, "toAppHubEndpointReason: invalid reason: " + reason);
                return HubEndpoint.REASON_FAILURE;
        }
    }

    /**
     * Converts a byte integer defined by Reason.aidl to HubEndpoint.Reason values exposed to apps.
     *
     * @param reason The Reason.aidl value
     * @return The converted HubEndpoint.Reason value
     */
    /* package */
    static byte toHalReason(@HubEndpoint.Reason int reason) {
        switch (reason) {
            case HubEndpoint.REASON_FAILURE:
                return Reason.UNSPECIFIED;
            case HubEndpoint.REASON_OPEN_ENDPOINT_SESSION_REQUEST_REJECTED:
                return Reason.OPEN_ENDPOINT_SESSION_REQUEST_REJECTED;
            case HubEndpoint.REASON_CLOSE_ENDPOINT_SESSION_REQUESTED:
                return Reason.CLOSE_ENDPOINT_SESSION_REQUESTED;
            case HubEndpoint.REASON_ENDPOINT_INVALID:
                return Reason.ENDPOINT_INVALID;
            case HubEndpoint.REASON_ENDPOINT_STOPPED:
                return Reason.ENDPOINT_GONE;
            case HubEndpoint.REASON_PERMISSION_DENIED:
                return Reason.PERMISSION_DENIED;
            default:
                Log.w(TAG, "toHalReason: invalid reason: " + reason);
                return Reason.UNSPECIFIED;
        }
    }

    /**
     * Checks that the module with the provided context/pid/uid has all of the provided permissions.
     *
     * @param context The context to validate permissions for
     * @param pid The PID to validate permissions for
     * @param uid The UID to validate permissions for
     * @param permissions The collection of permissions to check
     * @return true if the module has all of the permissions granted
     */
    /* package */
    static boolean hasPermissions(
            Context context, int pid, int uid, Collection<String> permissions) {
        for (String permission : permissions) {
            if (context.checkPermission(permission, pid, uid) != PERMISSION_GRANTED) {
                Log.e(TAG, "no permission for " + permission);
                return false;
            }
        }
        return true;
    }

    /**
     * Attributes the provided permissions to the package of this client.
     *
     * @param appOpsManager The app ops manager to use
     * @param uid The UID of the module to note permissions for
     * @param packageName The package name of the module to note permissions for
     * @param attributionTag The attribution tag of the module to note permissions for
     * @param permissions The list of permissions covering data the client is about to receive
     * @param noteMessage The message that should be noted alongside permissions attribution to
     *     facilitate debugging
     * @return true if client has ability to use all of the provided permissions
     */
    /* package */
    static boolean notePermissions(
            AppOpsManager appOpsManager,
            int uid,
            String packageName,
            String attributionTag,
            Collection<String> permissions,
            String noteMessage) {
        for (String permission : permissions) {
            int opCode = AppOpsManager.permissionToOpCode(permission);
            if (opCode != AppOpsManager.OP_NONE) {
                try {
                    if (appOpsManager.noteOp(opCode, uid, packageName, attributionTag, noteMessage)
                            != AppOpsManager.MODE_ALLOWED) {
                        return false;
                    }
                } catch (SecurityException e) {
                    Log.e(
                            TAG,
                            "SecurityException: noteOp for pkg "
                                    + packageName
                                    + " opcode "
                                    + opCode
                                    + ": "
                                    + e.getMessage());
                    return false;
                }
            }
        }

        return true;
    }
}
