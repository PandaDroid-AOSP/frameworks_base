/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package android.util;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.fail;

import android.platform.test.annotations.Presubmit;
import android.platform.test.ravenwood.RavenwoodRule;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ConcurrentModificationException;

/**
 * Unit tests for ArrayMap that don't belong in CTS.
 */
@LargeTest
@Presubmit
@RunWith(AndroidJUnit4.class)
public class ArrayMapTest {
    private static final String TAG = "ArrayMapTest";
    ArrayMap<String, String> map = new ArrayMap<>();

    @Rule
    public final RavenwoodRule mRavenwood = new RavenwoodRule();

    /**
     * Attempt to generate a ConcurrentModificationException in ArrayMap.
     * <p>
     * ArrayMap is explicitly documented to be non-thread-safe, yet it's easy to accidentally screw
     * this up; ArrayMap should (in the spirit of the core Java collection types) make an effort to
     * catch this and throw ConcurrentModificationException instead of crashing somewhere in its
     * internals.
     *
     * @throws Exception
     */
    @Test
    @Ignore("Failing; b/399137661")
    public void testConcurrentModificationException() throws Exception {
        final int TEST_LEN_MS = 5000;
        System.out.println("Starting ArrayMap concurrency test");
        new Thread(() -> {
            int i = 0;
            while (map != null) {
                try {
                    map.put(String.format("key %d", i++), "B_DONT_DO_THAT");
                } catch (ArrayIndexOutOfBoundsException e) {
                    Log.e(TAG, "concurrent modification uncaught, causing indexing failure", e);
                    fail();
                } catch (ClassCastException e) {
                    Log.e(TAG, "concurrent modification uncaught, causing cache corruption", e);
                    fail();
                } catch (ConcurrentModificationException e) {
                    System.out.println("[successfully caught CME at put #" + i
                            + " size=" + (map == null ? "??" : String.valueOf(map.size())) + "]");
                }
                if (i % 200 == 0) {
                    System.out.print(".");
                }
            }
        }).start();
        for (int i = 0; i < (TEST_LEN_MS / 100); i++) {
            try {
                Thread.sleep(100);
                map.clear();
                System.out.print("X");
            } catch (InterruptedException e) {
            } catch (ArrayIndexOutOfBoundsException e) {
                Log.e(TAG, "concurrent modification uncaught, causing indexing failure");
                fail();
            } catch (ClassCastException e) {
                Log.e(TAG, "concurrent modification uncaught, causing cache corruption");
                fail();
            } catch (ConcurrentModificationException e) {
                System.out.println(
                        "[successfully caught CME at clear #"
                                + i + " size=" + map.size() + "]");
            }
        }
        map = null; // will stop other thread
        System.out.println();
    }

    /**
     * Check to make sure the same operations behave as expected in a single thread.
     */
    @Test
    public void testNonConcurrentAccesses() throws Exception {
        for (int i = 0; i < 100000; i++) {
            try {
                map.put(String.format("key %d", i++), "B_DONT_DO_THAT");
                if (i % 200 == 0) {
                    System.out.print(".");
                }
                if (i % 500 == 0) {
                    map.clear();
                    System.out.print("X");
                }
            } catch (ConcurrentModificationException e) {
                Log.e(TAG, "concurrent modification caught on single thread", e);
                fail();
            }
        }
    }

    @Test
    public void testToString() {
        map.put("1", "One");
        map.put("2", "Two");
        map.put("3", "Five");
        map.put("3", "Three");

        assertThat(map.toString()).isEqualTo("{1=One, 2=Two, 3=Three}");
        assertThat(map.keySet().toString()).isEqualTo("[1, 2, 3]");
        assertThat(map.values().toString()).isEqualTo("[One, Two, Three]");
    }

    @Test
    public void testToStringRecursive() {
        ArrayMap<Object, Object> weird = new ArrayMap<>();
        weird.put("1", weird);

        assertThat(weird.toString()).isEqualTo("{1=(this Map)}");
        assertThat(weird.keySet().toString()).isEqualTo("[1]");
        assertThat(weird.values().toString()).isEqualTo("[{1=(this Map)}]");
    }

    @Test
    public void testToStringRecursiveKeySet() {
        ArrayMap<Object, Object> weird = new ArrayMap<>();
        weird.put("1", weird.keySet());
        weird.put(weird.keySet(), "2");

        assertThat(weird.toString()).isEqualTo("{1=[1, (this KeySet)], [1, (this KeySet)]=2}");
        assertThat(weird.keySet().toString()).isEqualTo("[1, (this KeySet)]");
        assertThat(weird.values().toString()).isEqualTo("[[1, (this KeySet)], 2]");
    }

    @Test
    public void testToStringRecursiveValues() {
        ArrayMap<Object, Object> weird = new ArrayMap<>();
        weird.put("1", weird.values());
        weird.put(weird.values(), "2");

        assertThat(weird.toString()).isEqualTo(
                "{1=[(this ValuesCollection), 2], [(this ValuesCollection), 2]=2}");
        assertThat(weird.keySet().toString()).isEqualTo("[1, [(this ValuesCollection), 2]]");
        assertThat(weird.values().toString()).isEqualTo("[(this ValuesCollection), 2]");
    }
}
