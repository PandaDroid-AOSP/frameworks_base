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

package com.android.settingslib.ipc

import android.app.Application
import android.content.pm.PackageManager.PERMISSION_GRANTED
import android.os.Bundle

/**
 * Codec to marshall/unmarshall data between given type and [Bundle].
 *
 * The implementation must be threadsafe and stateless.
 */
interface MessageCodec<T> {
    /** Converts given data to [Bundle]. */
    fun encode(data: T): Bundle

    /** Converts [Bundle] to an object of given data type. */
    fun decode(data: Bundle): T
}

/**
 * Descriptor of API.
 *
 * Used by both [MessengerService] and [MessengerServiceClient] to identify API and encode/decode
 * messages.
 */
interface ApiDescriptor<Request, Response> {
    /**
     * Identity of the API.
     *
     * The id must be:
     * - Positive: the negative numbers are reserved for internal messages.
     * - Unique within the [MessengerService].
     * - Permanent to achieve backward compatibility.
     */
    val id: Int

    /** Codec for request. */
    val requestCodec: MessageCodec<Request>

    /** Codec for response. */
    val responseCodec: MessageCodec<Response>
}

/** Permission checker for api. */
fun interface ApiPermissionChecker<R> {
    /**
     * Returns if the request is permitted.
     *
     * @param application application context
     * @param callingPid pid of peer process
     * @param callingUid uid of peer process
     * @param request API request
     * @return `false` if permission is denied, otherwise `true`
     */
    fun hasPermission(
        application: Application,
        callingPid: Int,
        callingUid: Int,
        request: R,
    ): Boolean

    companion object {
        private val ALWAYS_ALLOW = ApiPermissionChecker<Any> { _, _, _, _ -> true }

        /** Returns [ApiPermissionChecker] that allows all the request. */
        @Suppress("UNCHECKED_CAST")
        fun <T> alwaysAllow(): ApiPermissionChecker<T> = ALWAYS_ALLOW as ApiPermissionChecker<T>

        /**
         * Returns [ApiPermissionChecker] that checks if calling app has given [permission].
         *
         * Use [AppOpApiPermissionChecker] if the [permission] is app-op.
         */
        fun <T> of(permission: String) =
            ApiPermissionChecker<T> { application, callingPid, callingUid, _ ->
                application.checkPermission(permission, callingPid, callingUid) ==
                    PERMISSION_GRANTED
            }
    }
}

/**
 * Handler of API.
 *
 * This is the API implementation portion, which is used by [MessengerService] only.
 * [MessengerServiceClient] does NOT need this interface at all to make request.
 *
 * The implementation must be threadsafe.
 */
interface ApiHandler<Request, Response> :
    ApiDescriptor<Request, Response>, ApiPermissionChecker<Request> {

    /**
     * Invokes the API.
     *
     * The API is invoked from Service handler thread, do not perform time-consuming task. Start
     * coroutine in another thread if it takes time to complete.
     */
    suspend fun invoke(
        application: Application,
        callingPid: Int,
        callingUid: Int,
        request: Request,
    ): Response
}
