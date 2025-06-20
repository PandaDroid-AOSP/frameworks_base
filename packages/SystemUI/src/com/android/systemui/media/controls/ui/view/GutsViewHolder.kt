/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.systemui.media.controls.ui.view

import android.content.res.ColorStateList
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import com.android.systemui.Flags
import com.android.systemui.media.controls.ui.animation.accentPrimaryFromScheme
import com.android.systemui.media.controls.ui.animation.onPrimaryFromScheme
import com.android.systemui.media.controls.ui.animation.primaryFromScheme
import com.android.systemui.media.controls.ui.animation.surfaceFromScheme
import com.android.systemui.media.controls.ui.animation.textPrimaryFromScheme
import com.android.systemui.monet.ColorScheme
import com.android.systemui.res.R

/**
 * A view holder for the guts menu of a media player. The guts are shown when the user long-presses
 * on the media player.
 *
 * Both [MediaViewHolder] and [RecommendationViewHolder] use the same guts menu layout, so this
 * class helps share logic between the two.
 */
class GutsViewHolder(itemView: View) {
    val gutsText: TextView = itemView.requireViewById(R.id.remove_text)
    val cancel: View = itemView.requireViewById(R.id.cancel)
    val cancelText: TextView = itemView.requireViewById(R.id.cancel_text)
    val dismiss: ViewGroup = itemView.requireViewById(R.id.dismiss)
    val dismissText: TextView = itemView.requireViewById(R.id.dismiss_text)
    val settings: ImageButton = itemView.requireViewById(R.id.settings)

    private var isDismissible: Boolean = true
    // TODO(media_controls_a11y_colors): make private
    var colorScheme: ColorScheme? = null
    private var textColorFixed: Int? = null

    /** Marquees the main text of the guts menu. */
    fun marquee(start: Boolean, delay: Long, tag: String) {
        val gutsTextHandler = gutsText.handler
        if (gutsTextHandler == null) {
            Log.d(tag, "marquee while longPressText.getHandler() is null", Exception())
            return
        }
        gutsTextHandler.postDelayed({ gutsText.isSelected = start }, delay)
    }

    /** Set whether this control can be dismissed, and update appearance to match */
    fun setDismissible(dismissible: Boolean) {
        if (isDismissible == dismissible) return

        isDismissible = dismissible
        colorScheme?.let { setColors(it) }
    }

    /** Sets the right colors on all the guts views based on the given [ColorScheme]. */
    fun setColors(scheme: ColorScheme) {
        colorScheme = scheme

        if (Flags.mediaControlsA11yColors()) {
            textColorFixed?.let { setTextColor(it) }
            setPrimaryColor(primaryFromScheme(scheme))
            setOnPrimaryColor(onPrimaryFromScheme(scheme))
        } else {
            setSurfaceColor(surfaceFromScheme(scheme))
            setTextPrimaryColor(textPrimaryFromScheme(scheme))
            setAccentPrimaryColor(accentPrimaryFromScheme(scheme))
        }
    }

    private fun setPrimaryColor(color: Int) {
        val colorList = ColorStateList.valueOf(color)
        dismissText.backgroundTintList = colorList
        cancelText.backgroundTintList = colorList
    }

    private fun setOnPrimaryColor(color: Int) {
        dismissText.setTextColor(color)
        if (!isDismissible) {
            cancelText.setTextColor(color)
        }
    }

    fun setTextColor(color: Int) {
        textColorFixed = color
        gutsText.setTextColor(color)
        settings.imageTintList = ColorStateList.valueOf(color)

        if (isDismissible) {
            cancelText.setTextColor(color)
        }
    }

    /** Sets the surface color on all guts views that use it. */
    @Deprecated("Remove with media_controls_a11y_colors")
    fun setSurfaceColor(surfaceColor: Int) {
        dismissText.setTextColor(surfaceColor)
        if (!isDismissible) {
            cancelText.setTextColor(surfaceColor)
        }
    }

    /** Sets the primary accent color on all guts views that use it. */
    @Deprecated("Remove with media_controls_a11y_colors")
    fun setAccentPrimaryColor(accentPrimary: Int) {
        val accentColorList = ColorStateList.valueOf(accentPrimary)
        settings.imageTintList = accentColorList
        cancelText.backgroundTintList = accentColorList
        dismissText.backgroundTintList = accentColorList
    }

    /** Sets the primary text color on all guts views that use it. */
    @Deprecated("Remove with media_controls_a11y_colors")
    fun setTextPrimaryColor(textPrimary: Int) {
        val textColorList = ColorStateList.valueOf(textPrimary)
        gutsText.setTextColor(textColorList)
        if (isDismissible) {
            cancelText.setTextColor(textColorList)
        }
    }

    companion object {
        val ids = setOf(R.id.remove_text, R.id.cancel, R.id.dismiss, R.id.settings)
    }
}
