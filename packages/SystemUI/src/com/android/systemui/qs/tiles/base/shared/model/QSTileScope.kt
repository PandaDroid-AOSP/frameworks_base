/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.systemui.qs.tiles.base.shared.model

import javax.inject.Scope

/**
 * Scope annotation for QS tiles. This scope is created for each tile and is disposed when the tile
 * is no longer needed (ex. it's removed from QS). So, it lives along the instance of
 * [com.android.systemui.qs.tiles.base.viewmodel.QSTileViewModelImpl]. This doesn't align with tile
 * visibility. For example, the tile scope survives shade open/close.
 */
@MustBeDocumented @Retention(AnnotationRetention.RUNTIME) @Scope annotation class QSTileScope
