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

package com.android.systemui.scene.session.ui.composable

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffectResult
import androidx.compose.runtime.DisposableEffectScope
import androidx.compose.runtime.RememberObserver
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.currentCompositeKeyHash
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCompositionContext
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.SaverScope
import androidx.compose.runtime.saveable.mapSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.android.systemui.scene.session.shared.SessionStorage
import com.android.systemui.util.kotlin.mapValuesNotNullTo
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job

/**
 * An explicit storage for remembering composable state outside of the lifetime of a composition.
 *
 * Specifically, this allows easy conversion of standard
 * [remember][androidx.compose.runtime.remember] invocations to ones that are preserved beyond the
 * callsite's existence in the composition.
 *
 * ```kotlin
 * @Composable
 * fun Parent() {
 *   val session = remember { Session() }
 *   ...
 *   if (someCondition) {
 *     Child(session)
 *   }
 * }
 *
 * @Composable
 * fun Child(session: Session) {
 *   val state by session.rememberSession { mutableStateOf(0f) }
 *   ...
 * }
 * ```
 */
interface Session {
    /**
     * Remember the value returned by [init] if all [inputs] are equal (`==`) to the values they had
     * in the previous composition, otherwise produce and remember a new value by calling [init].
     *
     * @param inputs A set of inputs such that, when any of them have changed, will cause the state
     *   to reset and [init] to be rerun
     * @param key An optional key to be used as a key for the saved value. If `null`, we use the one
     *   automatically generated by the Compose runtime which is unique for the every exact code
     *   location in the composition tree
     * @param init A factory function to create the initial value of this state
     * @see androidx.compose.runtime.remember
     */
    @Composable fun <T> rememberSession(key: String?, vararg inputs: Any?, init: () -> T): T
}

/** Returns a new [Session], optionally backed by the provided [SessionStorage]. */
fun Session(storage: SessionStorage = SessionStorage()): Session = SessionImpl(storage)

/**
 * Remember the value returned by [init] if all [inputs] are equal (`==`) to the values they had in
 * the previous composition, otherwise produce and remember a new value by calling [init].
 *
 * @param inputs A set of inputs such that, when any of them have changed, will cause the state to
 *   reset and [init] to be rerun
 * @param key An optional key to be used as a key for the saved value. If not provided we use the
 *   one automatically generated by the Compose runtime which is unique for the every exact code
 *   location in the composition tree
 * @param init A factory function to create the initial value of this state
 * @see androidx.compose.runtime.remember
 */
@Composable
fun <T> Session.rememberSession(vararg inputs: Any?, key: String? = null, init: () -> T): T =
    rememberSession(key, *inputs, init = init)

/**
 * A side effect of composition that must be reversed or cleaned up if the [Session] ends.
 *
 * @see androidx.compose.runtime.DisposableEffect
 */
@Composable
fun Session.SessionDisposableEffect(
    vararg inputs: Any?,
    key: String? = null,
    effect: DisposableEffectScope.() -> DisposableEffectResult,
) {
    rememberSession(inputs, key) {
        object : RememberObserver {

            var onDispose: DisposableEffectResult? = null

            override fun onAbandoned() {
                // no-op
            }

            override fun onForgotten() {
                onDispose?.dispose()
                onDispose = null
            }

            override fun onRemembered() {
                onDispose = DisposableEffectScope().effect()
            }
        }
    }
}

/**
 * Return a [CoroutineScope] bound to this [Session] using the optional [CoroutineContext] provided
 * by [getContext]. [getContext] will only be called once and the same [CoroutineScope] instance
 * will be returned for the duration of the [Session].
 *
 * @see androidx.compose.runtime.rememberCoroutineScope
 */
@Composable
fun Session.sessionCoroutineScope(
    getContext: () -> CoroutineContext = { EmptyCoroutineContext }
): CoroutineScope {
    val effectContext: CoroutineContext = rememberCompositionContext().effectCoroutineContext
    val job = rememberSession { Job() }
    SessionDisposableEffect { onDispose { job.cancel() } }
    return rememberSession { CoroutineScope(effectContext + job + getContext()) }
}

/**
 * An explicit storage for remembering composable state outside of the lifetime of a composition.
 *
 * Specifically, this allows easy conversion of standard [rememberSession] invocations to ones that
 * are preserved beyond the callsite's existence in the composition.
 *
 * ```kotlin
 * @Composable
 * fun Parent() {
 *   val session = rememberSaveableSession()
 *   ...
 *   if (someCondition) {
 *     Child(session)
 *   }
 * }
 *
 * @Composable
 * fun Child(session: SaveableSession) {
 *   val state by session.rememberSaveableSession { mutableStateOf(0f) }
 *   ...
 * }
 * ```
 */
interface SaveableSession : Session {
    /**
     * Remember the value produced by [init].
     *
     * It behaves similarly to [rememberSession], but the stored value will survive the activity or
     * process recreation using the saved instance state mechanism (for example it happens when the
     * screen is rotated in the Android application).
     *
     * @param inputs A set of inputs such that, when any of them have changed, will cause the state
     *   to reset and [init] to be rerun
     * @param saver The [Saver] object which defines how the state is saved and restored.
     * @param key An optional key to be used as a key for the saved value. If not provided we use
     *   the automatically generated by the Compose runtime which is unique for the every exact code
     *   location in the composition tree
     * @param init A factory function to create the initial value of this state
     * @see rememberSaveable
     */
    @Composable
    fun <T : Any> rememberSaveableSession(
        vararg inputs: Any?,
        saver: Saver<T, out Any>,
        key: String?,
        init: () -> T,
    ): T
}

/**
 * Returns a new [SaveableSession] that is preserved across configuration changes.
 *
 * @param inputs A set of inputs such that, when any of them have changed, will cause the state to
 *   reset.
 * @param key An optional key to be used as a key for the saved value. If not provided we use the
 *   automatically generated by the Compose runtime which is unique for the every exact code
 *   location in the composition tree.
 */
@Composable
fun rememberSaveableSession(vararg inputs: Any?, key: String? = null): SaveableSession =
    rememberSaveable(*inputs, SaveableSessionImpl.SessionSaver, key) { SaveableSessionImpl() }

private class SessionImpl(private val storage: SessionStorage = SessionStorage()) : Session {
    @Composable
    override fun <T> rememberSession(key: String?, vararg inputs: Any?, init: () -> T): T {
        val storage = storage.storage
        val compositeKey = currentCompositeKeyHash
        // key is the one provided by the user or the one generated by the compose runtime
        val finalKey =
            if (!key.isNullOrEmpty()) {
                key
            } else {
                compositeKey.toString(MAX_SUPPORTED_RADIX)
            }
        if (finalKey !in storage) {
            val value = init()
            SideEffect {
                storage[finalKey] = SessionStorage.StorageEntry(inputs, value)
                if (value is RememberObserver) {
                    value.onRemembered()
                }
            }
            return value
        }
        val entry = storage[finalKey]!!
        if (!inputs.contentEquals(entry.keys)) {
            val value = init()
            SideEffect {
                val oldValue = entry.stored
                if (oldValue is RememberObserver) {
                    oldValue.onForgotten()
                }
                entry.stored = value
                if (value is RememberObserver) {
                    value.onRemembered()
                }
            }
            return value
        }
        @Suppress("UNCHECKED_CAST")
        return entry.stored as T
    }
}

private class SaveableSessionImpl(
    saveableStorage: MutableMap<String, StorageEntry> = mutableMapOf(),
    sessionStorage: SessionStorage = SessionStorage(),
) : SaveableSession, Session by Session(sessionStorage) {

    var saveableStorage: MutableMap<String, StorageEntry> by mutableStateOf(saveableStorage)

    @Composable
    override fun <T : Any> rememberSaveableSession(
        vararg inputs: Any?,
        saver: Saver<T, out Any>,
        key: String?,
        init: () -> T,
    ): T {
        val compositeKey = currentCompositeKeyHash
        // key is the one provided by the user or the one generated by the compose runtime
        val finalKey =
            if (!key.isNullOrEmpty()) {
                key
            } else {
                compositeKey.toString(MAX_SUPPORTED_RADIX)
            }

        @Suppress("UNCHECKED_CAST") (saver as Saver<T, Any>)

        if (finalKey !in saveableStorage) {
            val value = init()
            SideEffect { saveableStorage[finalKey] = StorageEntry.Restored(inputs, value, saver) }
            return value
        }
        when (val entry = saveableStorage[finalKey]!!) {
            is StorageEntry.Unrestored -> {
                val value = saver.restore(entry.unrestored) ?: init()
                SideEffect {
                    saveableStorage[finalKey] = StorageEntry.Restored(inputs, value, saver)
                }
                return value
            }
            is StorageEntry.Restored<*> -> {
                if (!inputs.contentEquals(entry.inputs)) {
                    val value = init()
                    SideEffect {
                        saveableStorage[finalKey] = StorageEntry.Restored(inputs, value, saver)
                    }
                    return value
                }
                @Suppress("UNCHECKED_CAST")
                return entry.stored as T
            }
        }
    }

    sealed class StorageEntry {
        class Unrestored(val unrestored: Any) : StorageEntry()

        class Restored<T>(val inputs: Array<out Any?>, var stored: T, val saver: Saver<T, Any>) :
            StorageEntry() {
            fun SaverScope.saveEntry() {
                with(saver) { stored?.let { save(it) } }
            }
        }
    }

    object SessionSaver :
        Saver<SaveableSessionImpl, Any> by mapSaver(
            save = { sessionScope: SaveableSessionImpl ->
                sessionScope.saveableStorage.mapValues { (k, v) ->
                    when (v) {
                        is StorageEntry.Unrestored -> v.unrestored
                        is StorageEntry.Restored<*> -> {
                            with(v) { saveEntry() }
                        }
                    }
                }
            },
            restore = { savedMap: Map<String, Any?> ->
                SaveableSessionImpl(
                    saveableStorage =
                        savedMap.mapValuesNotNullTo(mutableMapOf()) { (k, v) ->
                            v?.let { StorageEntry.Unrestored(v) }
                        }
                )
            },
        )
}

private const val MAX_SUPPORTED_RADIX = 36
