/*
 * Copyright 2019 The Android Open Source Project
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

package android.media;

import android.media.MediaRoute2ProviderInfo;
import android.media.MediaRoute2Info;
import android.media.RouteDiscoveryPreference;
import android.media.RouteListingPreference;
import android.media.RoutingSessionInfo;
import android.media.SuggestedDeviceInfo;

/**
 * {@hide}
 */
oneway interface IMediaRouter2Manager {
    void notifySessionCreated(int requestId, in RoutingSessionInfo session);
    void notifySessionUpdated(in RoutingSessionInfo session);
    void notifySessionReleased(in RoutingSessionInfo session);
    void notifyDiscoveryPreferenceChanged(String packageName,
            in RouteDiscoveryPreference discoveryPreference);
    void notifyRouteListingPreferenceChange(String packageName,
            in @nullable RouteListingPreference routeListingPreference);
    void notifyDeviceSuggestionsUpdated(String packageName, String suggestingPackageName,
            in @nullable List<SuggestedDeviceInfo> suggestedDeviceInfo);
    void notifyRoutesUpdated(in List<MediaRoute2Info> routes);
    void notifyRequestFailed(int requestId, int reason);
    void invalidateInstance();
}
