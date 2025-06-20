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

package com.android.systemui.display.data.repository

import com.android.app.displaylib.DisplayInstanceLifecycleManager
import com.android.app.displaylib.FakeDisplayInstanceLifecycleManager
import com.android.app.displaylib.PerDisplayInstanceProviderWithTeardown
import com.android.app.displaylib.PerDisplayInstanceRepositoryImpl
import com.android.systemui.dump.dumpManager
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.applicationCoroutineScope
import com.android.systemui.kosmos.testScope
import kotlinx.coroutines.CoroutineScope

class FakePerDisplayStore(
    backgroundApplicationScope: CoroutineScope,
    displayRepository: DisplayRepository,
) : PerDisplayStoreImpl<TestPerDisplayInstance>(backgroundApplicationScope, displayRepository) {

    val removalActions = mutableListOf<TestPerDisplayInstance>()

    override fun createInstanceForDisplay(displayId: Int): TestPerDisplayInstance {
        return TestPerDisplayInstance(displayId)
    }

    override val instanceClass = TestPerDisplayInstance::class.java

    override suspend fun onDisplayRemovalAction(instance: TestPerDisplayInstance) {
        removalActions += instance
    }
}

data class TestPerDisplayInstance(val displayId: Int)

val Kosmos.fakePerDisplayStore by
    Kosmos.Fixture {
        FakePerDisplayStore(
            backgroundApplicationScope = applicationCoroutineScope,
            displayRepository = displayRepository,
        )
    }

class FakePerDisplayInstanceProviderWithTeardown :
    PerDisplayInstanceProviderWithTeardown<TestPerDisplayInstance> {
    val destroyed = mutableListOf<TestPerDisplayInstance>()

    override fun destroyInstance(instance: TestPerDisplayInstance) {
        destroyed += instance
    }

    override fun createInstance(displayId: Int): TestPerDisplayInstance? {
        return TestPerDisplayInstance(displayId)
    }
}

val Kosmos.fakePerDisplayInstanceProviderWithTeardown by
    Kosmos.Fixture { FakePerDisplayInstanceProviderWithTeardown() }

val Kosmos.perDisplayDumpHelper by Kosmos.Fixture { PerDisplayRepoDumpHelper(dumpManager) }
val Kosmos.fakeDisplayInstanceLifecycleManager by
    Kosmos.Fixture { FakeDisplayInstanceLifecycleManager() }

val Kosmos.fakePerDisplayInstanceRepository by
    Kosmos.Fixture {
        { lifecycleManager: DisplayInstanceLifecycleManager? ->
            PerDisplayInstanceRepositoryImpl(
                debugName = "fakePerDisplayInstanceRepository",
                instanceProvider = fakePerDisplayInstanceProviderWithTeardown,
                lifecycleManager,
                testScope.backgroundScope,
                displayRepository,
                perDisplayDumpHelper,
            )
        }
    }

fun Kosmos.createPerDisplayInstanceRepository(
    overrideLifecycleManager: DisplayInstanceLifecycleManager? = null
): PerDisplayInstanceRepositoryImpl<TestPerDisplayInstance> {
    return fakePerDisplayInstanceRepository(overrideLifecycleManager)
}
