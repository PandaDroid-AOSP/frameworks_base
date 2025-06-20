/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <private/hwui/WebViewFunctor.h>
#include <renderthread/RenderProxy.h>
#include <utils/LightRefBase.h>
#include <utils/Log.h>
#include <utils/StrongPointer.h>

#include <mutex>
#include <vector>

namespace android {

class SurfaceControl;

namespace uirenderer {

class WebViewFunctorManager;

class WebViewFunctor {
public:
    WebViewFunctor(void* data, const WebViewFunctorCallbacks& callbacks, RenderMode functorMode);
    ~WebViewFunctor();

    class Handle : public LightRefBase<Handle> {
    public:
        ~Handle() { renderthread::RenderProxy::destroyFunctor(id()); }

        int id() const { return mReference.id(); }

        void sync(const WebViewSyncData& syncData) const { mReference.sync(syncData); }

        void drawGl(const DrawGlInfo& drawInfo) const { mReference.drawGl(drawInfo); }

        void initVk(const VkFunctorInitParams& params) { mReference.initVk(params); }

        void drawVk(const VkFunctorDrawParams& params) { mReference.drawVk(params); }

        void postDrawVk() { mReference.postDrawVk(); }

        void removeOverlays() { mReference.removeOverlays(); }

        void onRemovedFromTree() { mReference.onRemovedFromTree(); }

        const std::vector<pid_t>& getRenderingThreads() const {
            return mReference.getRenderingThreads();
        }

    private:
        friend class WebViewFunctor;

        Handle(WebViewFunctor& ref) : mReference(ref) {}

        WebViewFunctor& mReference;
    };

    int id() const { return mFunctor; }
    void sync(const WebViewSyncData& syncData) const;
    void drawGl(const DrawGlInfo& drawInfo);
    void initVk(const VkFunctorInitParams& params);
    void drawVk(const VkFunctorDrawParams& params);
    void postDrawVk();
    void destroyContext();
    void removeOverlays();
    void onRemovedFromTree();

    ASurfaceControl* getSurfaceControl();
    void mergeTransaction(ASurfaceTransaction* transaction);

    void reportRenderingThreads(const pid_t* thread_ids, size_t size);
    const std::vector<pid_t>& getRenderingThreads() const { return mRenderingThreads; }

    sp<Handle> createHandle() {
        LOG_ALWAYS_FATAL_IF(mCreatedHandle);
        mCreatedHandle = true;
        return sp<Handle>{new Handle(*this)};
    }

private:
    bool prepareRootSurfaceControl();
    void reparentSurfaceControl(ASurfaceControl* parent);

private:
    WebViewFunctorCallbacks mCallbacks;
    void* const mData;
    int mFunctor;
    RenderMode mMode;
    bool mHasContext = false;
    bool mCreatedHandle = false;
    int32_t mParentSurfaceControlGenerationId = 0;
#ifdef __ANDROID__
    sp<SurfaceControl> mSurfaceControl = nullptr;
#endif
    std::vector<pid_t> mRenderingThreads;
};

class WebViewFunctorManager {
public:
    static WebViewFunctorManager& instance();

    int createFunctor(void* data, const WebViewFunctorCallbacks& callbacks, RenderMode functorMode);
    void releaseFunctor(int functor);
    void onContextDestroyed();
    void destroyFunctor(int functor);
    void reportRenderingThreads(int functor, const pid_t* thread_ids, size_t size);
    std::vector<pid_t> getRenderingThreadsForActiveFunctors();

    sp<WebViewFunctor::Handle> handleFor(int functor);

private:
    WebViewFunctorManager() = default;
    ~WebViewFunctorManager() = default;

    std::mutex mLock;
    std::vector<std::unique_ptr<WebViewFunctor>> mFunctors;
    std::vector<sp<WebViewFunctor::Handle>> mActiveFunctors;
};

}  // namespace uirenderer
}  // namespace android
