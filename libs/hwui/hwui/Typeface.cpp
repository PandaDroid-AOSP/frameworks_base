/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include "Typeface.h"

#include <fcntl.h>  // For tests.
#include <pthread.h>
#ifndef _WIN32
#include <sys/mman.h>  // For tests.
#endif
#include <sys/stat.h>  // For tests.

#include "MinikinSkia.h"
#include "SkPaint.h"
#include "SkStream.h"  // For tests.
#include "SkTypeface.h"
#include "utils/TypefaceUtils.h"

#include <minikin/FontCollection.h>
#include <minikin/FontFamily.h>
#include <minikin/Layout.h>
#include <utils/Log.h>
#include <utils/MathUtils.h>

namespace android {

static Typeface::Style computeAPIStyle(int weight, bool italic) {
    // This bold detection comes from SkTypeface.h
    if (weight >= SkFontStyle::kSemiBold_Weight) {
        return italic ? Typeface::kBoldItalic : Typeface::kBold;
    } else {
        return italic ? Typeface::kItalic : Typeface::kNormal;
    }
}

static minikin::FontStyle computeMinikinStyle(int weight, bool italic) {
    return minikin::FontStyle(uirenderer::MathUtils::clamp(weight, 1, 1000),
                              static_cast<minikin::FontStyle::Slant>(italic));
}

// Resolve the relative weight from the baseWeight and target style.
static minikin::FontStyle computeRelativeStyle(int baseWeight, Typeface::Style relativeStyle) {
    int weight = baseWeight;
    if ((relativeStyle & Typeface::kBold) != 0) {
        weight += 300;
    }
    bool italic = (relativeStyle & Typeface::kItalic) != 0;
    return computeMinikinStyle(weight, italic);
}

const Typeface* gDefaultTypeface = NULL;

const Typeface* Typeface::resolveDefault(const Typeface* src) {
    LOG_ALWAYS_FATAL_IF(src == nullptr && gDefaultTypeface == nullptr);
    return src == nullptr ? gDefaultTypeface : src;
}

Typeface* Typeface::createRelative(Typeface* src, Typeface::Style style) {
    const Typeface* resolvedFace = Typeface::resolveDefault(src);
    return new Typeface(resolvedFace->getFontCollection(),
                        computeRelativeStyle(resolvedFace->getBaseWeight(), style), style,
                        resolvedFace->getBaseWeight(), resolvedFace->isVariationInstance());
}

Typeface* Typeface::createAbsolute(Typeface* base, int weight, bool italic) {
    const Typeface* resolvedFace = Typeface::resolveDefault(base);
    return new Typeface(resolvedFace->getFontCollection(), computeMinikinStyle(weight, italic),
                        computeAPIStyle(weight, italic), resolvedFace->getBaseWeight(),
                        resolvedFace->isVariationInstance());
}

Typeface* Typeface::createFromTypefaceWithVariation(Typeface* src,
                                                    const minikin::VariationSettings& variations) {
    const Typeface* resolvedFace = Typeface::resolveDefault(src);
    const std::shared_ptr<minikin::FontCollection>& fc =
            resolvedFace->getFontCollection()->createCollectionWithVariation(variations);
    return new Typeface(
            // None of passed axes are supported by this collection.
            // So we will reuse the same collection with incrementing reference count.
            fc ? fc : resolvedFace->getFontCollection(),
            // Do not update styles.
            // TODO: We may want to update base weight if the 'wght' is specified.
            resolvedFace->fStyle, resolvedFace->getAPIStyle(), resolvedFace->getBaseWeight(), true);
}

Typeface* Typeface::createWithDifferentBaseWeight(Typeface* src, int weight) {
    const Typeface* resolvedFace = Typeface::resolveDefault(src);
    return new Typeface(resolvedFace->getFontCollection(),
                        computeRelativeStyle(weight, resolvedFace->getAPIStyle()),
                        resolvedFace->getAPIStyle(), weight, resolvedFace->isVariationInstance());
}

Typeface* Typeface::createFromFamilies(std::vector<std::shared_ptr<minikin::FontFamily>>&& families,
                                       int weight, int italic, const Typeface* fallback) {
    const std::shared_ptr<minikin::FontCollection>& fc =
            fallback ? fallback->getFontCollection()->createCollectionWithFamilies(
                               std::move(families))
                     : minikin::FontCollection::create(std::move(families));

    if (weight == RESOLVE_BY_FONT_TABLE || italic == RESOLVE_BY_FONT_TABLE) {
        int weightFromFont;
        bool italicFromFont;

        const minikin::FontStyle defaultStyle;
        const minikin::MinikinFont* mf =
                families.empty() ? nullptr
                                 : families[0]->getClosestMatch(defaultStyle).typeface().get();
        if (mf != nullptr) {
            SkTypeface* skTypeface = reinterpret_cast<const MinikinFontSkia*>(mf)->GetSkTypeface();
            const SkFontStyle& style = skTypeface->fontStyle();
            weightFromFont = style.weight();
            italicFromFont = style.slant() != SkFontStyle::kUpright_Slant;
        } else {
            // We can't obtain any information from fonts. Just use default values.
            weightFromFont = SkFontStyle::kNormal_Weight;
            italicFromFont = false;
        }

        if (weight == RESOLVE_BY_FONT_TABLE) {
            weight = weightFromFont;
        }
        if (italic == RESOLVE_BY_FONT_TABLE) {
            italic = italicFromFont ? 1 : 0;
        }
    }

    // Sanitize the invalid value passed from public API.
    if (weight < 0) {
        weight = SkFontStyle::kNormal_Weight;
    }

    return new Typeface(fc, computeMinikinStyle(weight, italic), computeAPIStyle(weight, italic),
                        weight, false);
}

void Typeface::setDefault(const Typeface* face) {
    gDefaultTypeface = face;
}

void Typeface::setRobotoTypefaceForTest() {
#ifndef _WIN32
    const char* kRobotoFont = "/system/fonts/Roboto-Regular.ttf";

    int fd = open(kRobotoFont, O_RDONLY);
    LOG_ALWAYS_FATAL_IF(fd == -1, "Failed to open file %s", kRobotoFont);
    struct stat st = {};
    LOG_ALWAYS_FATAL_IF(fstat(fd, &st) == -1, "Failed to stat file %s", kRobotoFont);
    void* data = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    std::unique_ptr<SkStreamAsset> fontData(new SkMemoryStream(data, st.st_size));
    sk_sp<SkFontMgr> fm = android::FreeTypeFontMgr();
    LOG_ALWAYS_FATAL_IF(fm == nullptr, "Could not load FreeType SkFontMgr");
    sk_sp<SkTypeface> typeface = fm->makeFromStream(std::move(fontData));
    LOG_ALWAYS_FATAL_IF(typeface == nullptr, "Failed to make typeface from %s", kRobotoFont);

    std::shared_ptr<minikin::MinikinFont> font = std::make_shared<MinikinFontSkia>(
            std::move(typeface), 0, data, st.st_size, kRobotoFont, 0, minikin::VariationSettings());
    std::vector<std::shared_ptr<minikin::Font>> fonts;
    fonts.push_back(minikin::Font::Builder(font).build());

    std::shared_ptr<minikin::FontCollection> collection =
            minikin::FontCollection::create(minikin::FontFamily::create(std::move(fonts)));

    Typeface* hwTypeface = new Typeface(collection, minikin::FontStyle(), Typeface::kNormal,
                                        SkFontStyle::kNormal_Weight, false);

    Typeface::setDefault(hwTypeface);
#endif
}
}  // namespace android
