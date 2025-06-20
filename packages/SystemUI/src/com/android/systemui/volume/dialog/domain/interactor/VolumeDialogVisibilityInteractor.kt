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

package com.android.systemui.volume.dialog.domain.interactor

import android.annotation.SuppressLint
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.android.systemui.accessibility.data.repository.AccessibilityRepository
import com.android.systemui.plugins.VolumeDialogController
import com.android.systemui.shared.settings.data.repository.SecureSettingsRepository
import com.android.systemui.volume.Events
import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogPlugin
import com.android.systemui.volume.dialog.dagger.scope.VolumeDialogPluginScope
import com.android.systemui.volume.dialog.data.VolumeDialogVisibilityRepository
import com.android.systemui.volume.dialog.domain.model.VolumeDialogEventModel
import com.android.systemui.volume.dialog.shared.model.VolumeDialogSafetyWarningModel
import com.android.systemui.volume.dialog.shared.model.VolumeDialogVisibilityModel
import com.android.systemui.volume.dialog.shared.model.VolumeDialogVisibilityModel.Dismissed
import com.android.systemui.volume.dialog.shared.model.VolumeDialogVisibilityModel.Visible
import com.android.systemui.volume.dialog.utils.VolumeTracer
import javax.inject.Inject
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn

/**
 * Handles Volume Dialog visibility state. It might change from several sources:
 * - [com.android.systemui.plugins.VolumeDialogController] requests visibility change;
 * - it might be dismissed by the inactivity timeout;
 * - it can be dismissed by the user;
 */
@VolumeDialogPluginScope
class VolumeDialogVisibilityInteractor
@Inject
constructor(
    @VolumeDialogPlugin coroutineScope: CoroutineScope,
    callbacksInteractor: VolumeDialogCallbacksInteractor,
    private val stateInteractor: VolumeDialogStateInteractor,
    private val tracer: VolumeTracer,
    private val repository: VolumeDialogVisibilityRepository,
    private val accessibilityRepository: AccessibilityRepository,
    private val controller: VolumeDialogController,
    private val secureSettingsRepository: SecureSettingsRepository,
) {

    /** @see computeTimeout */
    private val defaultTimeout = 3.seconds

    @SuppressLint("SharedFlowCreation")
    private val mutableDismissDialogEvents = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val dialogVisibility: Flow<VolumeDialogVisibilityModel> =
        repository.dialogVisibility
            .onEach { controller.notifyVisible(it is Visible) }
            .stateIn(coroutineScope, SharingStarted.Eagerly, VolumeDialogVisibilityModel.Invisible)

    init {
        merge(
                mutableDismissDialogEvents.mapLatest {
                    delay(computeTimeout())
                    VolumeDialogEventModel.DismissRequested(Events.DISMISS_REASON_TIMEOUT)
                },
                callbacksInteractor.event,
            )
            .mapNotNull { it.toVisibilityModel() }
            .onEach { model ->
                updateVisibility { model }
                if (model is Visible) {
                    resetDismissTimeout()
                }
            }
            .launchIn(coroutineScope)
    }

    /**
     * Dismisses the dialog with a given [reason]. The new state will be emitted in the
     * [dialogVisibility].
     */
    fun dismissDialog(reason: Int) {
        updateVisibility { Dismissed(reason) }
    }

    /** Resets current dialog timeout. */
    fun resetDismissTimeout() {
        controller.userActivity()
        mutableDismissDialogEvents.tryEmit(Unit)
    }

    private fun updateVisibility(
        update: (VolumeDialogVisibilityModel) -> VolumeDialogVisibilityModel
    ) {
        repository.updateVisibility { currentVisibility ->
            val newVisibility = update(currentVisibility)
            // Don't update if the visibility is of the same type
            if (currentVisibility::class == newVisibility::class) {
                currentVisibility
            } else {
                tracer.traceVisibilityStart(newVisibility)
                newVisibility
            }
        }
    }

    private suspend fun computeTimeout(): Duration {
        val defaultDialogTimeoutMillis =
            secureSettingsRepository
                .getInt(
                    Settings.Secure.VOLUME_DIALOG_DISMISS_TIMEOUT,
                    defaultTimeout.toInt(DurationUnit.MILLISECONDS),
                )
                .milliseconds
        val currentDialogState = stateInteractor.volumeDialogState.first()
        return when {
            currentDialogState.isHovering ->
                accessibilityRepository.getRecommendedTimeout(
                    defaultDialogTimeoutMillis,
                    AccessibilityManager.FLAG_CONTENT_CONTROLS,
                )

            currentDialogState.isShowingSafetyWarning is VolumeDialogSafetyWarningModel.Visible ->
                accessibilityRepository.getRecommendedTimeout(
                    defaultDialogTimeoutMillis,
                    AccessibilityManager.FLAG_CONTENT_TEXT or
                        AccessibilityManager.FLAG_CONTENT_CONTROLS,
                )

            else ->
                accessibilityRepository.getRecommendedTimeout(
                    defaultDialogTimeoutMillis,
                    AccessibilityManager.FLAG_CONTENT_CONTROLS,
                )
        }
    }

    private fun VolumeDialogEventModel.toVisibilityModel(): VolumeDialogVisibilityModel? {
        return when (this) {
            is VolumeDialogEventModel.DismissRequested -> Dismissed(reason)
            is VolumeDialogEventModel.ShowRequested ->
                Visible(reason, keyguardLocked, lockTaskModeState)

            else -> null
        }
    }
}
