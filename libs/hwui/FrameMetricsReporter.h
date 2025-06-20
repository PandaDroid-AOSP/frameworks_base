/*
 * Copyright (C) 2016 The Android Open Source Project
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

#pragma once

#include <utils/Mutex.h>
#include <utils/Log.h>
#include <utils/RefBase.h>

#include <ui/FatVector.h>

#include "FrameInfo.h"
#include "FrameMetricsObserver.h"

#include <string.h>
#include <mutex>

namespace android {
namespace uirenderer {

class FrameMetricsReporter {
public:
    FrameMetricsReporter() {}

    void addObserver(sp<FrameMetricsObserver>&& observer) {
        std::lock_guard lock(mObserversLock);
        mObservers.push_back(std::move(observer));
    }

    bool removeObserver(const sp<FrameMetricsObserver>& observer) {
        std::lock_guard lock(mObserversLock);
        for (size_t i = 0; i < mObservers.size(); i++) {
            if (mObservers[i].get() == observer) {
                mObservers.erase(mObservers.begin() + i);
                return true;
            }
        }
        return false;
    }

    bool hasObservers() {
        std::lock_guard lock(mObserversLock);
        return mObservers.size() > 0;
    }

    /**
     * Notify observers about the metrics contained in 'stats'.
     * If an observer is waiting for present time, notify when 'stats' has present time.
     *
     * If an observer does not want present time, only notify when 'hasPresentTime' is false.
     * Never notify both types of observers from the same callback, because the callback with
     * 'hasPresentTime' is sent at a different time than the one without.
     *
     * The 'frameNumber' and 'surfaceControlId' associated to the frame whose's stats are being
     * reported are used to determine whether or not the stats should be reported. We won't report
     * stats of frames that are from "old" surfaces (i.e. with surfaceControlIds older than the one
     * the observer was attached on) nor those that are from "old" frame numbers.
     */
    void reportFrameMetrics(const FrameInfoBuffer& stats, bool hasPresentTime, uint64_t frameNumber,
                            int32_t surfaceControlId);

private:
    FatVector<sp<FrameMetricsObserver>, 10> mObservers GUARDED_BY(mObserversLock);
    std::mutex mObserversLock;
};

}  // namespace uirenderer
}  // namespace android
