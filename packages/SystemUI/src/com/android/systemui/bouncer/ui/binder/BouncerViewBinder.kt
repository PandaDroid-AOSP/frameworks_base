package com.android.systemui.bouncer.ui.binder

import android.view.ViewGroup
import com.android.keyguard.KeyguardMessageAreaController
import com.android.keyguard.dagger.KeyguardBouncerComponent
import com.android.systemui.Flags.contAuthPlugin
import com.android.systemui.biometrics.plugins.AuthContextPlugins
import com.android.systemui.bouncer.domain.interactor.BouncerMessageInteractor
import com.android.systemui.bouncer.domain.interactor.PrimaryBouncerInteractor
import com.android.systemui.bouncer.shared.flag.ComposeBouncerFlags
import com.android.systemui.bouncer.ui.BouncerDialogFactory
import com.android.systemui.bouncer.ui.viewmodel.BouncerContainerViewModel
import com.android.systemui.bouncer.ui.viewmodel.BouncerOverlayContentViewModel
import com.android.systemui.bouncer.ui.viewmodel.KeyguardBouncerViewModel
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Application
import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor
import com.android.systemui.keyguard.ui.viewmodel.GlanceableHubToPrimaryBouncerTransitionViewModel
import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel
import com.android.systemui.log.BouncerLogger
import com.android.systemui.user.domain.interactor.SelectedUserInteractor
import dagger.Lazy
import java.util.Optional
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope

/** Helper data class that allows to lazy load all the dependencies of the legacy bouncer. */
@SysUISingleton
data class LegacyBouncerDependencies
@Inject
constructor(
    val viewModel: KeyguardBouncerViewModel,
    val primaryBouncerToGoneTransitionViewModel: PrimaryBouncerToGoneTransitionViewModel,
    val glanceableHubToPrimaryBouncerTransitionViewModel:
        GlanceableHubToPrimaryBouncerTransitionViewModel,
    val componentFactory: KeyguardBouncerComponent.Factory,
    val messageAreaControllerFactory: KeyguardMessageAreaController.Factory,
    val bouncerMessageInteractor: BouncerMessageInteractor,
    val bouncerLogger: BouncerLogger,
    val selectedUserInteractor: SelectedUserInteractor,
)

/** Helper data class that allows to lazy load all the dependencies of the compose based bouncer. */
@SysUISingleton
data class ComposeBouncerDependencies
@Inject
constructor(
    @Application val applicationScope: CoroutineScope,
    val keyguardInteractor: KeyguardInteractor,
    val selectedUserInteractor: SelectedUserInteractor,
    val legacyInteractor: PrimaryBouncerInteractor,
    val viewModelFactory: BouncerOverlayContentViewModel.Factory,
    val dialogFactory: BouncerDialogFactory,
    val bouncerContainerViewModelFactory: BouncerContainerViewModel.Factory,
)

/**
 * Toggles between the compose and non compose version of the bouncer, instantiating only the
 * dependencies required for each.
 */
@SysUISingleton
class BouncerViewBinder
@Inject
constructor(
    private val legacyBouncerDependencies: Lazy<LegacyBouncerDependencies>,
    private val composeBouncerDependencies: Lazy<ComposeBouncerDependencies>,
    private val contextPlugins: Optional<AuthContextPlugins>,
) {
    fun bind(view: ViewGroup) {
        if (ComposeBouncerFlags.isOnlyComposeBouncerEnabled()) {
            val deps = composeBouncerDependencies.get()
            ComposeBouncerViewBinder.bind(
                view,
                deps.applicationScope,
                deps.legacyInteractor,
                deps.keyguardInteractor,
                deps.selectedUserInteractor,
                deps.viewModelFactory,
                deps.dialogFactory,
                deps.bouncerContainerViewModelFactory,
            )
        } else {
            val deps = legacyBouncerDependencies.get()
            KeyguardBouncerViewBinder.bind(
                view,
                deps.viewModel,
                deps.primaryBouncerToGoneTransitionViewModel,
                deps.glanceableHubToPrimaryBouncerTransitionViewModel,
                deps.componentFactory,
                deps.messageAreaControllerFactory,
                deps.bouncerMessageInteractor,
                deps.bouncerLogger,
                deps.selectedUserInteractor,
                if (contAuthPlugin()) contextPlugins.orElse(null) else null,
            )
        }
    }
}
