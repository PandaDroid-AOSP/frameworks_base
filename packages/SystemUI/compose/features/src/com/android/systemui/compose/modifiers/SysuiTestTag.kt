/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.systemui.compose.modifiers

import androidx.compose.runtime.Stable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId

/**
 * Set a test tag on this node so that it is associated with [resId]. This node will then be
 * accessible by integration tests using `sysuiResSelector(resId)`.
 */
@Stable
fun Modifier.sysuiResTag(resId: String): Modifier {
    // TODO(b/372412931): Only compose the semantics modifier once, at the root of the SystemUI
    // window.
    return this.then(TestTagAsResourceIdModifier).testTag("com.android.systemui:id/$resId")
}

private val TestTagAsResourceIdModifier = Modifier.semantics { testTagsAsResourceId = true }
