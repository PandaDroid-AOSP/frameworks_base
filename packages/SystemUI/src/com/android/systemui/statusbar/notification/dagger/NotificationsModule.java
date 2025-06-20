/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.systemui.statusbar.notification.dagger;

import android.app.NotificationManager;
import android.content.Context;
import android.os.Handler;
import android.service.notification.NotificationListenerService;

import com.android.internal.jank.InteractionJankMonitor;
import com.android.settingslib.notification.data.repository.ZenModeRepository;
import com.android.settingslib.notification.data.repository.ZenModeRepositoryImpl;
import com.android.settingslib.notification.domain.interactor.NotificationsSoundPolicyInteractor;
import com.android.settingslib.notification.modes.ZenModesBackend;
import com.android.systemui.CoreStartable;
import com.android.systemui.Flags;
import com.android.systemui.dagger.SysUISingleton;
import com.android.systemui.dagger.qualifiers.Application;
import com.android.systemui.dagger.qualifiers.Background;
import com.android.systemui.res.R;
import com.android.systemui.shade.ShadeDisplayAware;
import com.android.systemui.statusbar.NotificationListener;
import com.android.systemui.statusbar.notification.NotificationActivityStarter;
import com.android.systemui.statusbar.notification.NotificationLaunchAnimatorControllerProvider;
import com.android.systemui.statusbar.notification.VisibilityLocationProvider;
import com.android.systemui.statusbar.notification.collection.EntryAdapterFactory;
import com.android.systemui.statusbar.notification.collection.EntryAdapterFactoryImpl;
import com.android.systemui.statusbar.notification.collection.NotifInflaterImpl;
import com.android.systemui.statusbar.notification.collection.NotifLiveDataStore;
import com.android.systemui.statusbar.notification.collection.NotifLiveDataStoreImpl;
import com.android.systemui.statusbar.notification.collection.NotifPipeline;
import com.android.systemui.statusbar.notification.collection.NotifPipelineChoreographerModule;
import com.android.systemui.statusbar.notification.collection.coordinator.ShadeEventCoordinator;
import com.android.systemui.statusbar.notification.collection.inflation.BindEventManager;
import com.android.systemui.statusbar.notification.collection.inflation.BindEventManagerImpl;
import com.android.systemui.statusbar.notification.collection.inflation.NotifInflater;
import com.android.systemui.statusbar.notification.collection.inflation.OnUserInteractionCallbackImpl;
import com.android.systemui.statusbar.notification.collection.notifcollection.CommonNotifCollection;
import com.android.systemui.statusbar.notification.collection.provider.NotificationDismissibilityProvider;
import com.android.systemui.statusbar.notification.collection.provider.NotificationDismissibilityProviderImpl;
import com.android.systemui.statusbar.notification.collection.provider.NotificationVisibilityProviderImpl;
import com.android.systemui.statusbar.notification.collection.provider.VisibilityLocationProviderDelegator;
import com.android.systemui.statusbar.notification.collection.render.GroupExpansionManager;
import com.android.systemui.statusbar.notification.collection.render.GroupExpansionManagerImpl;
import com.android.systemui.statusbar.notification.collection.render.GroupMembershipManager;
import com.android.systemui.statusbar.notification.collection.render.GroupMembershipManagerImpl;
import com.android.systemui.statusbar.notification.collection.render.NotifGutsViewManager;
import com.android.systemui.statusbar.notification.collection.render.NotifShadeEventSource;
import com.android.systemui.statusbar.notification.collection.render.NotificationVisibilityProvider;
import com.android.systemui.statusbar.notification.data.NotificationDataLayerModule;
import com.android.systemui.statusbar.notification.domain.NotificationDomainLayerModule;
import com.android.systemui.statusbar.notification.domain.interactor.NotificationLaunchAnimationInteractor;
import com.android.systemui.statusbar.notification.headsup.HeadsUpManager;
import com.android.systemui.statusbar.notification.icon.ConversationIconManager;
import com.android.systemui.statusbar.notification.icon.IconManager;
import com.android.systemui.statusbar.notification.init.NotificationsController;
import com.android.systemui.statusbar.notification.init.NotificationsControllerImpl;
import com.android.systemui.statusbar.notification.init.NotificationsControllerStub;
import com.android.systemui.statusbar.notification.interruption.KeyguardNotificationVisibilityProviderModule;
import com.android.systemui.statusbar.notification.interruption.NotificationInterruptStateProvider;
import com.android.systemui.statusbar.notification.interruption.NotificationInterruptStateProviderImpl;
import com.android.systemui.statusbar.notification.interruption.NotificationInterruptStateProviderWrapper;
import com.android.systemui.statusbar.notification.interruption.VisualInterruptionDecisionProvider;
import com.android.systemui.statusbar.notification.interruption.VisualInterruptionDecisionProviderImpl;
import com.android.systemui.statusbar.notification.interruption.VisualInterruptionRefactor;
import com.android.systemui.statusbar.notification.logging.NotificationPanelLogger;
import com.android.systemui.statusbar.notification.logging.NotificationPanelLoggerImpl;
import com.android.systemui.statusbar.notification.logging.dagger.NotificationsLogModule;
import com.android.systemui.statusbar.notification.promoted.PromotedNotificationContentExtractor;
import com.android.systemui.statusbar.notification.promoted.PromotedNotificationContentExtractorImpl;
import com.android.systemui.statusbar.notification.promoted.shared.model.PromotedNotificationContentModel;
import com.android.systemui.statusbar.notification.row.NotificationEntryProcessorFactory;
import com.android.systemui.statusbar.notification.row.NotificationEntryProcessorFactoryLooperImpl;
import com.android.systemui.statusbar.notification.row.NotificationGutsManager;
import com.android.systemui.statusbar.notification.row.OnUserInteractionCallback;
import com.android.systemui.statusbar.notification.row.ui.viewmodel.ActivatableNotificationViewModelModule;
import com.android.systemui.statusbar.notification.stack.MagneticNotificationRowManager;
import com.android.systemui.statusbar.notification.stack.MagneticNotificationRowManagerImpl;
import com.android.systemui.statusbar.notification.stack.NotificationListContainer;
import com.android.systemui.statusbar.notification.stack.NotificationSectionsManager;
import com.android.systemui.statusbar.notification.stack.NotificationStackScrollLayoutController;
import com.android.systemui.statusbar.notification.stack.StackScrollAlgorithm;
import com.android.systemui.statusbar.phone.KeyguardBypassController;
import com.android.systemui.statusbar.phone.StatusBarNotificationActivityStarter;
import com.android.systemui.statusbar.policy.ZenModesCleanupStartable;

import dagger.Binds;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.ClassKey;
import dagger.multibindings.IntoMap;

import kotlin.coroutines.CoroutineContext;

import kotlinx.coroutines.CoroutineScope;

import javax.inject.Provider;

/**
 * Dagger Module for classes found within the com.android.systemui.statusbar.notification package.
 */
@Module(includes = {
        KeyguardNotificationVisibilityProviderModule.class,
        NotificationDataLayerModule.class,
        NotificationDomainLayerModule.class,
        NotifPipelineChoreographerModule.class,
        NotificationSectionHeadersModule.class,
        ActivatableNotificationViewModelModule.class,
        NotificationMemoryModule.class,
        NotificationStatsLoggerModule.class,
        NotificationsLogModule.class,
})
public interface NotificationsModule {
    @Binds
    StackScrollAlgorithm.SectionProvider bindSectionProvider(NotificationSectionsManager impl);

    @Binds
    StackScrollAlgorithm.BypassController bindBypassController(KeyguardBypassController impl);

    /** Provides an instance of {@link NotifGutsViewManager} */
    @Binds
    NotifGutsViewManager bindNotifGutsViewManager(NotificationGutsManager notificationGutsManager);

    /** Binds {@link NotificationGutsManager} as a {@link CoreStartable}. */
    @Binds
    @IntoMap
    @ClassKey(NotificationGutsManager.class)
    CoreStartable bindsNotificationGutsManager(NotificationGutsManager notificationGutsManager);


    /** Provides an instance of {@link VisibilityLocationProvider} */
    @Binds
    VisibilityLocationProvider bindVisibilityLocationProvider(
            VisibilityLocationProviderDelegator visibilityLocationProviderDelegator);

    /** Provides an instance of {@link NotificationPanelLogger} */
    @SysUISingleton
    @Provides
    static NotificationPanelLogger provideNotificationPanelLogger() {
        return new NotificationPanelLoggerImpl();
    }

    /** Provides an instance of {@link GroupMembershipManager} */
    @Binds
    GroupMembershipManager provideGroupMembershipManager(GroupMembershipManagerImpl impl);

    /** Provides an instance of {@link GroupExpansionManager} */
    @Binds
    GroupExpansionManager provideGroupExpansionManager(GroupExpansionManagerImpl impl);

    /** Provides an instance of {@link NotificationActivityStarter}. */
    @Binds
    NotificationActivityStarter bindActivityStarter(StatusBarNotificationActivityStarter impl);

    /** Initializes the notification data pipeline (can be disabled via config). */
    @SysUISingleton
    @Provides
    static NotificationsController provideNotificationsController(
            @ShadeDisplayAware Context context,
            Provider<NotificationsControllerImpl> realController,
            Provider<NotificationsControllerStub> stubController) {
        if (context.getResources().getBoolean(R.bool.config_renderNotifications)) {
            return realController.get();
        } else {
            return stubController.get();
        }
    }

    /** Provides the container for the notification list. */
    @Provides
    @SysUISingleton
    static NotificationListContainer provideListContainer(
            NotificationStackScrollLayoutController nsslController) {
        return nsslController.getNotificationListContainer();
    }

    /** Provides notification launch animator. */
    @Provides
    @SysUISingleton
    static NotificationLaunchAnimatorControllerProvider
            provideNotificationTransitionAnimatorControllerProvider(
                    NotificationLaunchAnimationInteractor notificationLaunchAnimationInteractor,
                    NotificationListContainer notificationListContainer,
                    HeadsUpManager headsUpManager,
                    InteractionJankMonitor jankMonitor) {
        return new NotificationLaunchAnimatorControllerProvider(
                notificationLaunchAnimationInteractor,
                notificationListContainer,
                headsUpManager,
                jankMonitor);
    }

    /**
     * Provide the active notification collection managing the notifications to render.
     */
    @Binds
    CommonNotifCollection provideCommonNotifCollection(NotifPipeline pipeline);

    /**
     * Provide the object which can be used to obtain dismissibility of a Notification.
     */
    @Binds
    NotificationDismissibilityProvider provideNotificationDismissibilityProvider(
            NotificationDismissibilityProviderImpl impl);

    /**
     * Provide the object which can be used to obtain NotificationVisibility objects.
     */
    @Binds
    NotificationVisibilityProvider provideNotificationVisibilityProvider(
            NotificationVisibilityProviderImpl impl);

    /**
     * Provide the active implementation for presenting notifications.
     */
    @Binds
    NotifShadeEventSource provideNotifShadeEventSource(ShadeEventCoordinator shadeEventCoordinator);

    /**
     * Provide a dismissal callback that's triggered when a user manually dismissed a notification
     * from the notification shade or it gets auto-cancelled by click.
     */
    @Binds
    OnUserInteractionCallback provideOnUserInteractionCallback(OnUserInteractionCallbackImpl impl);

    /** */
    @Binds
    NotificationInterruptStateProvider bindNotificationInterruptStateProvider(
            NotificationInterruptStateProviderImpl notificationInterruptStateProviderImpl);

    /** */
    @Binds
    NotifInflater bindNotifInflater(NotifInflaterImpl notifInflaterImpl);

    /** */
    @Binds
    NotificationEntryProcessorFactory bindNotificationEntryProcessorFactory(
            NotificationEntryProcessorFactoryLooperImpl factoryImpl);

    /** */
    @Binds
    ConversationIconManager bindConversationIconManager(IconManager iconManager);

    /** */
    @Binds
    BindEventManager bindBindEventManagerImpl(BindEventManagerImpl bindEventManagerImpl);

    /** */
    @Binds
    NotifLiveDataStore bindNotifLiveDataStore(NotifLiveDataStoreImpl notifLiveDataStoreImpl);

    /** */
    @Binds
    NotificationListenerService bindNotificationListener(NotificationListener notificationListener);

    /** */
    @Provides
    @SysUISingleton
    static VisualInterruptionDecisionProvider provideVisualInterruptionDecisionProvider(
            Provider<NotificationInterruptStateProviderImpl> oldImplProvider,
            Provider<VisualInterruptionDecisionProviderImpl> newImplProvider) {
        if (VisualInterruptionRefactor.isEnabled()) {
            return newImplProvider.get();
        } else {
            return new NotificationInterruptStateProviderWrapper(oldImplProvider.get());
        }
    }

    /** */
    @Binds
    @IntoMap
    @ClassKey(VisualInterruptionDecisionProvider.class)
    CoreStartable startVisualInterruptionDecisionProvider(
            VisualInterruptionDecisionProvider provider);

    @Provides
    @SysUISingleton
    static ZenModeRepository provideZenModeRepository(
            Context context,
            NotificationManager notificationManager,
            @Application CoroutineScope coroutineScope,
            @Background CoroutineContext coroutineContext,
            @Background Handler handler
    ) {
        return new ZenModeRepositoryImpl(context, notificationManager,
                ZenModesBackend.getInstance(context), context.getContentResolver(),
                coroutineScope, coroutineContext, handler);
    }

    @Provides
    @SysUISingleton
    static NotificationsSoundPolicyInteractor provideNotificationsSoundPolicyInteractor(
            ZenModeRepository repository) {
        return new NotificationsSoundPolicyInteractor(repository);
    }

    /** Binds {@link ZenModesCleanupStartable} as a {@link CoreStartable}. */
    @Binds
    @IntoMap
    @ClassKey(ZenModesCleanupStartable.class)
    CoreStartable bindsZenModesCleanup(ZenModesCleanupStartable zenModesCleanup);

    /** Provides the default implementation of {@link PromotedNotificationContentExtractor} if at
     * least one of the relevant feature flags is enabled, or an implementation that always returns
     * null if none are enabled. */
    @Provides
    @SysUISingleton
    static PromotedNotificationContentExtractor providesPromotedNotificationContentExtractor(
            Provider<PromotedNotificationContentExtractorImpl> implProvider) {
        if (PromotedNotificationContentModel.featureFlagEnabled()) {
            return implProvider.get();
        } else {
            return (entry, recoveredBuilder, redactionType, imageModelProvider) -> null;
        }
    }

    /**
     * Provide an implementation of {@link MagneticNotificationRowManager} based on its flag.
     */
    @Provides
    @SysUISingleton
    static MagneticNotificationRowManager provideMagneticNotificationRowManager(
            Provider<MagneticNotificationRowManagerImpl> implProvider
    ) {
        if (Flags.magneticNotificationSwipes()) {
            return implProvider.get();
        } else {
            return MagneticNotificationRowManager.getEmpty();
        }
    }

    /** Provides an instance of {@link EntryAdapterFactory} */
    @Binds
    EntryAdapterFactory provideEntryAdapterFactory(EntryAdapterFactoryImpl impl);

}
