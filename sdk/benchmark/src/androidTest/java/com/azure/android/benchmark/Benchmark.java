package com.azure.android.benchmark;

import android.os.AsyncTask;

import androidx.benchmark.BenchmarkState;
import androidx.benchmark.junit4.BenchmarkRule;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.azure.core.reactor.android.AndroidSchedulers;
import com.azure.storage.blob.BlobAsyncClient;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobClientBuilder;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import reactor.core.Disposable;
import reactor.core.Disposables;
import reactor.core.scheduler.Schedulers;

/**
 * Benchmark, which will execute on an Android device.
 * <p>
 * The while loop will measure the contents of the loop, and Studio will
 * output the result. Modify your code to see how it affects performance.
 */
@RunWith(AndroidJUnit4.class)
public class Benchmark {
    private final String BLOB_SERVICE_SAS_URL_INDIAN = "https://androidbenchmark.blob.core.windows.net/test-blobs/Indian.jpg?sp=r&st=2019-10-02T21:05:37Z&se=2020-01-02T06:05:37Z&spr=https&sv=2018-03-28&sig=b6SdCovmkCSicMmPA%2BC3WkEObwm0POT65zCo6l6jAFc%3D&sr=b";
    private final String BLOB_SERVICE_SAS_URL_TEST = "https://androidbenchmark.blob.core.windows.net/test-blobs/BenchmarkTest.txt?sp=r&st=2019-10-03T00:39:40Z&se=2020-01-01T09:39:40Z&spr=https&sv=2018-03-28&sig=6Vn%2Fv4SP73EQpSMU7%2F%2F67CG0fR%2Fc8%2FaG7HhpAw7B6%2F8%3D&sr=b";
    private boolean asyncDownloadComplete;
    private boolean downloadComplete;

    @Rule
    public BenchmarkRule mBenchmarkRule = new BenchmarkRule();

    @Test
    public void downloadBlobAsync() {
        final BenchmarkState state = mBenchmarkRule.getState();
        final Disposable.Composite disposables = Disposables.composite();
        BlobAsyncClient blobAsyncClient = new BlobClientBuilder()
            .endpoint(BLOB_SERVICE_SAS_URL_TEST)
            .buildBlobAsyncClient();

        while (state.keepRunning()) {
            state.pauseTiming();
            asyncDownloadComplete = false;
            state.resumeTiming();

            disposables.add(blobAsyncClient
                .download()
                .subscribeOn(Schedulers.elastic())
                .publishOn(AndroidSchedulers.mainThread())
                .subscribe(result -> {
                    ByteArrayOutputStream downloadData = new ByteArrayOutputStream();
                    result.subscribe(data -> {
                        try {
                            downloadData.write(data.array());
                            downloadData.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }

                        asyncDownloadComplete = true;
                    });
                }));

            while (!asyncDownloadComplete) {
                // Wait
            }
        }

        disposables.dispose();
    }

    @Test
    public void downloadBlob() {
        final BenchmarkState state = mBenchmarkRule.getState();
        BlobClient blobClient = new BlobClientBuilder()
            .endpoint(BLOB_SERVICE_SAS_URL_TEST)
            .buildBlobClient();

        while (state.keepRunning()) {
            state.pauseTiming();
            downloadComplete = false;
            AsyncTask<BlobClient, Object, Object> asyncTask = new AsyncTaskDownload();
            state.resumeTiming();

            asyncTask.execute(blobClient);

            while (!downloadComplete) {
                // Wait
            }
        }
    }

    private class AsyncTaskDownload extends AsyncTask<BlobClient, Object, Object> {
        @Override
        protected Object doInBackground(BlobClient... params) {
            try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
                params[0].download(byteArrayOutputStream);
            } catch (IOException e) {
                e.printStackTrace();
            }

            return null;
        }

        @Override
        protected void onPostExecute(Object o) {
            super.onPostExecute(o);
            downloadComplete = true;
        }
    }
}
