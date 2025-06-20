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

package com.android.systemui.qs.panels.ui.viewmodel.toolbar

import com.android.systemui.classifier.domain.interactor.FalsingInteractor
import com.android.systemui.plugins.ActivityStarter
import com.android.systemui.plugins.FalsingManager
import com.android.systemui.qs.panels.ui.viewmodel.EditModeViewModel
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject

class EditModeButtonViewModel
@AssistedInject
constructor(
    private val editModeViewModel: EditModeViewModel,
    private val falsingInteractor: FalsingInteractor,
    private val activityStarter: ActivityStarter,
) {

    fun onButtonClick() {
        if (!falsingInteractor.isFalseTap(FalsingManager.LOW_PENALTY)) {
            activityStarter.postQSRunnableDismissingKeyguard { editModeViewModel.startEditing() }
        }
    }

    @AssistedFactory
    interface Factory {
        fun create(): EditModeButtonViewModel
    }
}
