/*
 * Copyright (C) 2025 The Android Open Source Project
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

package com.android.systemui.statusbar.data.repository

import com.android.systemui.display.data.repository.DisplayRepository
import com.android.systemui.display.data.repository.displayRepository
import com.android.systemui.kosmos.Kosmos
import com.android.systemui.kosmos.applicationCoroutineScope
import kotlinx.coroutines.CoroutineScope

class FakeStatusBarPerDisplayStore(
    backgroundApplicationScope: CoroutineScope,
    displayRepository: DisplayRepository,
) :
    StatusBarPerDisplayStoreImpl<TestPerDisplayInstance>(
        backgroundApplicationScope,
        displayRepository,
    ) {

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

val Kosmos.fakeStatusBarPerDisplayStore by
    Kosmos.Fixture {
        FakeStatusBarPerDisplayStore(
            backgroundApplicationScope = applicationCoroutineScope,
            displayRepository = displayRepository,
        )
    }
