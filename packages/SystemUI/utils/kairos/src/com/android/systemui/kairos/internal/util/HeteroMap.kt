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

package com.android.systemui.kairos.internal.util

import com.android.systemui.kairos.util.Maybe
import com.android.systemui.kairos.util.Maybe.Absent
import java.util.concurrent.ConcurrentHashMap

private object NULL

internal class HeteroMap private constructor(private val store: ConcurrentHashMap<Key<*>, Any>) {
    interface Key<A> {}

    constructor() : this(ConcurrentHashMap())

    constructor(capacity: Int) : this(ConcurrentHashMap(capacity))

    @Suppress("UNCHECKED_CAST")
    operator fun <A> get(key: Key<A>): Maybe<A> =
        store[key]?.let { Maybe.present((if (it === NULL) null else it) as A) } ?: Absent

    operator fun <A> set(key: Key<A>, value: A) {
        store[key] = value ?: NULL
    }

    @Suppress("UNCHECKED_CAST")
    fun <A : Any> getOrNull(key: Key<A>): A? =
        store[key]?.let { (if (it === NULL) null else it) as A }

    @Suppress("UNCHECKED_CAST")
    fun <A> getOrError(key: Key<A>, block: () -> String): A {
        store[key]?.let {
            return (if (it === NULL) null else it) as A
        } ?: error(block())
    }

    operator fun contains(key: Key<*>): Boolean = store.containsKey(key)

    fun clear() {
        store.clear()
    }

    @Suppress("UNCHECKED_CAST")
    fun <A> remove(key: Key<A>): Maybe<A> =
        store.remove(key)?.let { Maybe.present((if (it === NULL) null else it) as A) } ?: Absent

    @Suppress("UNCHECKED_CAST")
    fun <A> getOrPut(key: Key<A>, defaultValue: () -> A): A =
        store.compute(key) { _, value -> value ?: defaultValue() ?: NULL } as A
}
