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

#include "WebViewFunctorManager.h"

#include <gui/SurfaceComposerClient.h>
#include <log/log.h>
#include <private/hwui/WebViewFunctor.h>
#include <utils/Trace.h>

#include <atomic>

#include "Properties.h"
#include "renderthread/CanvasContext.h"
#include "renderthread/RenderThread.h"

namespace android::uirenderer {

namespace {
class ScopedCurrentFunctor {
public:
    ScopedCurrentFunctor(WebViewFunctor* functor) {
        ALOG_ASSERT(!sCurrentFunctor);
        ALOG_ASSERT(functor);
        sCurrentFunctor = functor;
    }
    ~ScopedCurrentFunctor() {
        ALOG_ASSERT(sCurrentFunctor);
        sCurrentFunctor = nullptr;
    }

    static ASurfaceControl* getSurfaceControl() {
        ALOG_ASSERT(sCurrentFunctor);
        return reinterpret_cast<ASurfaceControl*>(sCurrentFunctor->getSurfaceControl());
    }
    static void mergeTransaction(ASurfaceTransaction* transaction) {
        ALOG_ASSERT(sCurrentFunctor);
        sCurrentFunctor->mergeTransaction(transaction);
    }

private:
    static WebViewFunctor* sCurrentFunctor;
};

WebViewFunctor* ScopedCurrentFunctor::sCurrentFunctor = nullptr;
}  // namespace

RenderMode WebViewFunctor_queryPlatformRenderMode() {
    auto pipelineType = Properties::getRenderPipelineType();
    switch (pipelineType) {
        case RenderPipelineType::SkiaGL:
            return RenderMode::OpenGL_ES;
        case RenderPipelineType::SkiaVulkan:
            return RenderMode::Vulkan;
        default:
            LOG_ALWAYS_FATAL("Unknown render pipeline type: %d", (int)pipelineType);
    }
}

int WebViewFunctor_create(void* data, const WebViewFunctorCallbacks& prototype,
                          RenderMode functorMode) {
    if (functorMode != RenderMode::OpenGL_ES && functorMode != RenderMode::Vulkan) {
        ALOGW("Unknown rendermode %d", (int)functorMode);
        return -1;
    }
    if (functorMode == RenderMode::Vulkan &&
        WebViewFunctor_queryPlatformRenderMode() != RenderMode::Vulkan) {
        ALOGW("Unable to map from GLES platform to a vulkan functor");
        return -1;
    }
    return WebViewFunctorManager::instance().createFunctor(data, prototype, functorMode);
}

void WebViewFunctor_release(int functor) {
    WebViewFunctorManager::instance().releaseFunctor(functor);
}

void WebViewFunctor_reportRenderingThreads(int functor, const pid_t* thread_ids, size_t size) {
    WebViewFunctorManager::instance().reportRenderingThreads(functor, thread_ids, size);
}

static std::atomic_int sNextId{1};

WebViewFunctor::WebViewFunctor(void* data, const WebViewFunctorCallbacks& callbacks,
                               RenderMode functorMode)
        : mData(data) {
    mFunctor = sNextId++;
    mCallbacks = callbacks;
    mMode = functorMode;
}

WebViewFunctor::~WebViewFunctor() {
    destroyContext();

    ATRACE_NAME("WebViewFunctor::onDestroy");
    if (mSurfaceControl) {
        removeOverlays();
    }
    mCallbacks.onDestroyed(mFunctor, mData);
}

void WebViewFunctor::sync(const WebViewSyncData& syncData) const {
    ATRACE_NAME("WebViewFunctor::sync");
    mCallbacks.onSync(mFunctor, mData, syncData);
}

void WebViewFunctor::onRemovedFromTree() {
    ATRACE_NAME("WebViewFunctor::onRemovedFromTree");
    if (mSurfaceControl) {
        removeOverlays();
    }
}

bool WebViewFunctor::prepareRootSurfaceControl() {
    if (!Properties::enableWebViewOverlays) return false;

    renderthread::CanvasContext* activeContext = renderthread::CanvasContext::getActiveContext();
    if (!activeContext) return false;

    sp<SurfaceControl> rootSurfaceControl = activeContext->getSurfaceControl();
    if (!rootSurfaceControl) return false;

    int32_t rgid = activeContext->getSurfaceControlGenerationId();
    if (mParentSurfaceControlGenerationId != rgid) {
        reparentSurfaceControl(reinterpret_cast<ASurfaceControl*>(rootSurfaceControl.get()));
        mParentSurfaceControlGenerationId = rgid;
    }

    return true;
}

void WebViewFunctor::drawGl(const DrawGlInfo& drawInfo) {
    ATRACE_NAME("WebViewFunctor::drawGl");
    if (!mHasContext) {
        mHasContext = true;
    }
    ScopedCurrentFunctor currentFunctor(this);

    WebViewOverlayData overlayParams = {
            .overlaysMode = OverlaysMode::Disabled,
            .getSurfaceControl = currentFunctor.getSurfaceControl,
            .mergeTransaction = currentFunctor.mergeTransaction,
    };

    if (!drawInfo.isLayer && prepareRootSurfaceControl()) {
        overlayParams.overlaysMode = OverlaysMode::Enabled;
    }

    mCallbacks.gles.draw(mFunctor, mData, drawInfo, overlayParams);
}

void WebViewFunctor::initVk(const VkFunctorInitParams& params) {
    ATRACE_NAME("WebViewFunctor::initVk");
    if (!mHasContext) {
        mHasContext = true;
    } else {
        return;
    }
    mCallbacks.vk.initialize(mFunctor, mData, params);
}

void WebViewFunctor::drawVk(const VkFunctorDrawParams& params) {
    ATRACE_NAME("WebViewFunctor::drawVk");
    ScopedCurrentFunctor currentFunctor(this);

    WebViewOverlayData overlayParams = {
            .overlaysMode = OverlaysMode::Disabled,
            .getSurfaceControl = currentFunctor.getSurfaceControl,
            .mergeTransaction = currentFunctor.mergeTransaction,
    };

    if (!params.is_layer && prepareRootSurfaceControl()) {
        overlayParams.overlaysMode = OverlaysMode::Enabled;
    }

    mCallbacks.vk.draw(mFunctor, mData, params, overlayParams);
}

void WebViewFunctor::postDrawVk() {
    ATRACE_NAME("WebViewFunctor::postDrawVk");
    mCallbacks.vk.postDraw(mFunctor, mData);
}

void WebViewFunctor::destroyContext() {
    if (mHasContext) {
        mHasContext = false;
        ATRACE_NAME("WebViewFunctor::onContextDestroyed");
        mCallbacks.onContextDestroyed(mFunctor, mData);

        // grContext may be null in unit tests.
        auto* grContext = renderthread::RenderThread::getInstance().getGrContext();
        if (grContext) grContext->resetContext();
    }
}

void WebViewFunctor::removeOverlays() {
    ScopedCurrentFunctor currentFunctor(this);
    mCallbacks.removeOverlays(mFunctor, mData, currentFunctor.mergeTransaction);
    if (mSurfaceControl) {
        reparentSurfaceControl(nullptr);
        mSurfaceControl = nullptr;
    }
}

ASurfaceControl* WebViewFunctor::getSurfaceControl() {
    ATRACE_NAME("WebViewFunctor::getSurfaceControl");
    if (mSurfaceControl != nullptr) {
        return reinterpret_cast<ASurfaceControl*>(mSurfaceControl.get());
    }

    renderthread::CanvasContext* activeContext = renderthread::CanvasContext::getActiveContext();
    LOG_ALWAYS_FATAL_IF(activeContext == nullptr, "Null active canvas context!");

    sp<SurfaceControl> rootSurfaceControl = activeContext->getSurfaceControl();
    LOG_ALWAYS_FATAL_IF(rootSurfaceControl == nullptr, "Null root surface control!");

    mParentSurfaceControlGenerationId = activeContext->getSurfaceControlGenerationId();

    SurfaceComposerClient* client = rootSurfaceControl->getClient().get();
    mSurfaceControl = client->createSurface(
            String8("Webview Overlay SurfaceControl"), 0 /* width */, 0 /* height */,
            // Format is only relevant for buffer queue layers.
            PIXEL_FORMAT_UNKNOWN /* format */, ISurfaceComposerClient::eFXSurfaceBufferState,
            rootSurfaceControl->getHandle());

    activeContext->prepareSurfaceControlForWebview();
    SurfaceComposerClient::Transaction transaction;
    transaction.setLayer(mSurfaceControl, -1).show(mSurfaceControl).apply();
    return reinterpret_cast<ASurfaceControl*>(mSurfaceControl.get());
}

void WebViewFunctor::mergeTransaction(ASurfaceTransaction* transaction) {
    ATRACE_NAME("WebViewFunctor::mergeTransaction");
    if (transaction == nullptr) return;
    bool done = false;
    renderthread::CanvasContext* activeContext = renderthread::CanvasContext::getActiveContext();
    // activeContext might be null when called from mCallbacks.removeOverlays()
    if (activeContext != nullptr) {
        done = activeContext->mergeTransaction(transaction, mSurfaceControl);
    }
    if (!done) {
        reinterpret_cast<SurfaceComposerClient::Transaction*>(transaction)->apply();
    }
}

void WebViewFunctor::reparentSurfaceControl(ASurfaceControl* parent) {
    ATRACE_NAME("WebViewFunctor::reparentSurfaceControl");
    if (mSurfaceControl == nullptr) return;

    SurfaceComposerClient::Transaction transaction;
    transaction.reparent(mSurfaceControl, sp<SurfaceControl>::fromExisting(
                                                  reinterpret_cast<SurfaceControl*>(parent)));
    mergeTransaction(reinterpret_cast<ASurfaceTransaction*>(&transaction));
}

void WebViewFunctor::reportRenderingThreads(const pid_t* thread_ids, size_t size) {
    mRenderingThreads = std::vector<pid_t>(thread_ids, thread_ids + size);
}

WebViewFunctorManager& WebViewFunctorManager::instance() {
    static WebViewFunctorManager sInstance;
    return sInstance;
}

static void validateCallbacks(const WebViewFunctorCallbacks& callbacks) {
    // TODO: Should we do a stack peek to see if this is really webview?
    LOG_ALWAYS_FATAL_IF(callbacks.onSync == nullptr, "onSync is null");
    LOG_ALWAYS_FATAL_IF(callbacks.onContextDestroyed == nullptr, "onContextDestroyed is null");
    LOG_ALWAYS_FATAL_IF(callbacks.onDestroyed == nullptr, "onDestroyed is null");
    LOG_ALWAYS_FATAL_IF(callbacks.removeOverlays == nullptr, "removeOverlays is null");
    switch (auto mode = WebViewFunctor_queryPlatformRenderMode()) {
        case RenderMode::OpenGL_ES:
            LOG_ALWAYS_FATAL_IF(callbacks.gles.draw == nullptr, "gles.draw is null");
            break;
        case RenderMode::Vulkan:
            LOG_ALWAYS_FATAL_IF(callbacks.vk.initialize == nullptr, "vk.initialize is null");
            LOG_ALWAYS_FATAL_IF(callbacks.vk.draw == nullptr, "vk.draw is null");
            LOG_ALWAYS_FATAL_IF(callbacks.vk.postDraw == nullptr, "vk.postDraw is null");
            break;
        default:
            LOG_ALWAYS_FATAL("unknown platform mode? %d", (int)mode);
            break;
    }
}

int WebViewFunctorManager::createFunctor(void* data, const WebViewFunctorCallbacks& callbacks,
                                         RenderMode functorMode) {
    validateCallbacks(callbacks);
    auto object = std::make_unique<WebViewFunctor>(data, callbacks, functorMode);
    int id = object->id();
    auto handle = object->createHandle();
    {
        std::lock_guard _lock{mLock};
        mActiveFunctors.push_back(std::move(handle));
        mFunctors.push_back(std::move(object));
    }
    return id;
}

void WebViewFunctorManager::releaseFunctor(int functor) {
    sp<WebViewFunctor::Handle> toRelease;
    {
        std::lock_guard _lock{mLock};
        for (auto iter = mActiveFunctors.begin(); iter != mActiveFunctors.end(); iter++) {
            if ((*iter)->id() == functor) {
                toRelease = std::move(*iter);
                mActiveFunctors.erase(iter);
                break;
            }
        }
    }
}

void WebViewFunctorManager::onContextDestroyed() {
    // WARNING: SKETCHY
    // Because we know that we always remove from mFunctors on RenderThread, the same
    // thread that always invokes onContextDestroyed, we know that the functor pointers
    // will remain valid without the lock held.
    // However, we won't block new functors from being added in the meantime.
    mLock.lock();
    const size_t size = mFunctors.size();
    WebViewFunctor* toDestroyContext[size];
    for (size_t i = 0; i < size; i++) {
        toDestroyContext[i] = mFunctors[i].get();
    }
    mLock.unlock();
    for (size_t i = 0; i < size; i++) {
        toDestroyContext[i]->destroyContext();
    }
}

void WebViewFunctorManager::destroyFunctor(int functor) {
    std::unique_ptr<WebViewFunctor> toRelease;
    {
        std::lock_guard _lock{mLock};
        for (auto iter = mFunctors.begin(); iter != mFunctors.end(); iter++) {
            if ((*iter)->id() == functor) {
                toRelease = std::move(*iter);
                mFunctors.erase(iter);
                break;
            }
        }
    }
}

void WebViewFunctorManager::reportRenderingThreads(int functor, const pid_t* thread_ids,
                                                   size_t size) {
    std::lock_guard _lock{mLock};
    for (auto& iter : mFunctors) {
        if (iter->id() == functor) {
            iter->reportRenderingThreads(thread_ids, size);
            break;
        }
    }
}

std::vector<pid_t> WebViewFunctorManager::getRenderingThreadsForActiveFunctors() {
    std::vector<pid_t> renderingThreads;
    std::lock_guard _lock{mLock};
    for (const auto& iter : mActiveFunctors) {
        const auto& functorThreads = iter->getRenderingThreads();
        for (const auto& tid : functorThreads) {
            if (std::find(renderingThreads.begin(), renderingThreads.end(), tid) ==
                renderingThreads.end()) {
                renderingThreads.push_back(tid);
            }
        }
    }
    return renderingThreads;
}

sp<WebViewFunctor::Handle> WebViewFunctorManager::handleFor(int functor) {
    std::lock_guard _lock{mLock};
    for (auto& iter : mActiveFunctors) {
        if (iter->id() == functor) {
            return iter;
        }
    }
    return nullptr;
}

}  // namespace android::uirenderer
