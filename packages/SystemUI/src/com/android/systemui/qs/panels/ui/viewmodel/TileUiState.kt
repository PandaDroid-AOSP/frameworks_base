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

package com.android.systemui.qs.panels.ui.viewmodel

import android.content.res.Resources
import android.graphics.drawable.Drawable
import android.service.quicksettings.Tile
import android.text.TextUtils
import android.widget.Switch
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.Stable
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.state.ToggleableState
import com.android.systemui.plugins.qs.QSTile
import com.android.systemui.qs.tileimpl.SubtitleArrayMapping
import com.android.systemui.res.R
import java.util.function.Supplier

/**
 * Ui State for the tiles. It doesn't contain the icon to be able to invalidate the icon part
 * separately. For the icon, use [IconProvider].
 */
@Immutable
data class TileUiState(
    val label: String,
    val secondaryLabel: String,
    val state: Int,
    val handlesLongClick: Boolean,
    val handlesSecondaryClick: Boolean,
    val sideDrawable: Drawable?,
    val accessibilityUiState: AccessibilityUiState,
)

data class AccessibilityUiState(
    val contentDescription: String,
    val stateDescription: String,
    val accessibilityRole: Role,
    val toggleableState: ToggleableState? = null,
    val clickLabel: String? = null,
)

fun QSTile.State.toUiState(resources: Resources): TileUiState {
    val accessibilityRole =
        if (expandedAccessibilityClassName == Switch::class.java.name && !handlesSecondaryClick) {
            Role.Switch
        } else {
            Role.Button
        }
    // State handling and description
    val stateDescription = StringBuilder()
    val stateText =
        if (accessibilityRole == Role.Switch || state == Tile.STATE_UNAVAILABLE) {
            getStateText(resources)
        } else {
            ""
        }
    val secondaryLabel = getSecondaryLabel(stateText)
    if (!TextUtils.isEmpty(stateText)) {
        stateDescription.append(stateText)
    }
    if (disabledByPolicy && state != Tile.STATE_UNAVAILABLE) {
        stateDescription.append(", ")
        stateDescription.append(getUnavailableText(spec, resources))
    }
    if (
        !TextUtils.isEmpty(this.stateDescription) &&
            !stateDescription.contains(this.stateDescription!!)
    ) {
        stateDescription.append(", ")
        stateDescription.append(this.stateDescription)
    }
    val toggleableState =
        if (accessibilityRole == Role.Switch || handlesSecondaryClick) {
            ToggleableState(state == Tile.STATE_ACTIVE)
        } else {
            null
        }
    return TileUiState(
        label = label?.toString() ?: "",
        secondaryLabel = secondaryLabel?.toString() ?: "",
        state = if (disabledByPolicy) Tile.STATE_UNAVAILABLE else state,
        handlesLongClick = handlesLongClick,
        handlesSecondaryClick = handlesSecondaryClick,
        sideDrawable = sideViewCustomDrawable,
        AccessibilityUiState(
            contentDescription?.toString() ?: "",
            stateDescription.toString(),
            accessibilityRole,
            toggleableState,
            resources
                .getString(R.string.accessibility_tile_disabled_by_policy_action_description)
                .takeIf { disabledByPolicy },
        ),
    )
}

fun QSTile.State.toIconProvider(): IconProvider {
    return when {
        icon != null -> IconProvider.ConstantIcon(icon)
        iconSupplier != null -> IconProvider.IconSupplier(iconSupplier)
        else -> IconProvider.Empty
    }
}

private fun QSTile.State.getStateText(resources: Resources): CharSequence {
    val arrayResId = SubtitleArrayMapping.getSubtitleId(spec)
    val array = resources.getStringArray(arrayResId)
    return array[state]
}

private fun getUnavailableText(spec: String?, resources: Resources): String {
    val arrayResId = SubtitleArrayMapping.getSubtitleId(spec)
    return resources.getStringArray(arrayResId)[Tile.STATE_UNAVAILABLE]
}

@Stable
sealed interface IconProvider {

    val icon: QSTile.Icon?

    data class ConstantIcon(override val icon: QSTile.Icon) : IconProvider

    data class IconSupplier(val supplier: Supplier<QSTile.Icon?>) : IconProvider {
        override val icon: QSTile.Icon?
            get() = supplier.get()
    }

    data object Empty : IconProvider {
        override val icon: QSTile.Icon?
            get() = null
    }
}
