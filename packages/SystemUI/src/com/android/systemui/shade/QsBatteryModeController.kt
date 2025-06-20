package com.android.systemui.shade

import android.content.Context
import android.view.DisplayCutout
import com.android.systemui.battery.BatteryMeterView
import com.android.systemui.res.R
import com.android.systemui.statusbar.data.repository.StatusBarContentInsetsProviderStore
import com.android.systemui.statusbar.layout.StatusBarContentInsetsProvider
import javax.inject.Inject

/**
 * Controls [BatteryMeterView.BatteryPercentMode]. It takes into account cutout and qs-qqs
 * transition fraction when determining the mode.
 */
class QsBatteryModeController
@Inject
constructor(
    @ShadeDisplayAware private val context: Context,
    private val insetsProviderStore: StatusBarContentInsetsProviderStore,
) {

    private companion object {
        // MotionLayout frames are in [0, 100]. Where 0 and 100 are reserved for start and end
        // frames.
        const val MOTION_LAYOUT_MAX_FRAME = 100
        // We add a single buffer frame to ensure that battery view faded out completely when we are
        // about to change it's state
        const val BUFFER_FRAME_COUNT = 1
    }

    private var fadeInStartFraction: Float = 0f
    private var fadeOutCompleteFraction: Float = 0f

    init {
        updateResources()
    }

    /**
     * Returns an appropriate [BatteryMeterView.BatteryPercentMode] for the [qsExpandedFraction] and
     * [cutout]. We don't show battery estimation in qqs header on the devices with center cutout.
     * The result might be null when the battery icon is invisible during the qs-qqs transition
     * animation.
     */
    @BatteryMeterView.BatteryPercentMode
    fun getBatteryMode(cutout: DisplayCutout?, qsExpandedFraction: Float): Int? {
        val insetsProvider = insetsProviderStore.forDisplay(context.displayId)
        return when {
            qsExpandedFraction > fadeInStartFraction -> BatteryMeterView.MODE_ESTIMATE
            insetsProvider != null && qsExpandedFraction < fadeOutCompleteFraction ->
                if (hasCenterCutout(cutout, insetsProvider)) {
                    BatteryMeterView.MODE_ON
                } else {
                    BatteryMeterView.MODE_ESTIMATE
                }
            else -> null
        }
    }

    fun updateResources() {
        fadeInStartFraction =
            (context.resources.getInteger(R.integer.fade_in_start_frame) - BUFFER_FRAME_COUNT) /
                MOTION_LAYOUT_MAX_FRAME.toFloat()
        fadeOutCompleteFraction =
            (context.resources.getInteger(R.integer.fade_out_complete_frame) + BUFFER_FRAME_COUNT) /
                MOTION_LAYOUT_MAX_FRAME.toFloat()
    }

    private fun hasCenterCutout(
        cutout: DisplayCutout?,
        insetsProvider: StatusBarContentInsetsProvider,
    ): Boolean =
        cutout?.let {
            !insetsProvider.currentRotationHasCornerCutout() && !it.boundingRectTop.isEmpty
        } ?: false
}
