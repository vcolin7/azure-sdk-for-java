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
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * StorageBenchmark, which will execute on an Android device.
 * <p>
 * The while loop will measure the contents of the loop, and Studio will
 * output the result. Modify your code to see how it affects performance.
 */
@RunWith(AndroidJUnit4.class)
public class StorageBenchmark {
    private final String BLOB_SERVICE_SAS_URL_TEST = "https://androidbenchmark.blob.core.windows.net/test-blobs/BenchmarkTest.txt?sp=r&st=2019-10-03T00:39:40Z&se=2020-01-01T09:39:40Z&spr=https&sv=2018-03-28&sig=6Vn%2Fv4SP73EQpSMU7%2F%2F67CG0fR%2Fc8%2FaG7HhpAw7B6%2F8%3D&sr=b";
    private final int targetDownloads = 15;
    private AtomicInteger totalDownloads = new AtomicInteger(0);
    private boolean downloadComplete;

    @Rule
    public BenchmarkRule mBenchmarkRule = new BenchmarkRule();

    @Test
    public void downloadSingleBlobReactorBenchmark() {
        final BenchmarkState state = mBenchmarkRule.getState();
        BlobAsyncClient blobAsyncClient = new BlobClientBuilder()
            .endpoint(BLOB_SERVICE_SAS_URL_TEST)
            .buildBlobAsyncClient();

        while (state.keepRunning()) {
            state.pauseTiming();
            downloadComplete = false;
            state.resumeTiming();

            downloadBlobReactor(blobAsyncClient);

            while (!downloadComplete) {
                // Wait
            }
        }
    }

    @Test
    public void downloadSingleBlobAsyncTaskBenchmark() {
        final BenchmarkState state = mBenchmarkRule.getState();
        BlobClient blobClient = new BlobClientBuilder()
            .endpoint(BLOB_SERVICE_SAS_URL_TEST)
            .buildBlobClient();

        while (state.keepRunning()) {
            state.pauseTiming();
            downloadComplete = false;
            AsyncTask<Object, Object, Object> asyncTask = new AsyncTaskDownload();
            state.resumeTiming();

            asyncTask.execute(blobClient);

            while (!downloadComplete) {
                // Wait
            }
        }
    }

    @Test
    public void downloadMultipleBlobsReactorBenchmark() {
        final BenchmarkState state = mBenchmarkRule.getState();
        BlobAsyncClient blobAsyncClient = new BlobClientBuilder()
            .endpoint(BLOB_SERVICE_SAS_URL_TEST)
            .buildBlobAsyncClient();

        while (state.keepRunning()) {
            state.pauseTiming();
            totalDownloads.set(0);
            state.resumeTiming();

            Flux.just(true).repeat(targetDownloads - 1).flatMap(aBoolean -> Mono.fromCallable(() -> downloadBlobReactor(blobAsyncClient))).blockLast();

            while (totalDownloads.get() != targetDownloads) {
                // Wait
            }
        }
    }

    @Test
    public void downloadMultipleBlobsAsyncTaskBenchmark() {
        final BenchmarkState state = mBenchmarkRule.getState();
        BlobClient blobClient = new BlobClientBuilder()
            .endpoint(BLOB_SERVICE_SAS_URL_TEST)
            .buildBlobClient();
        ArrayList<AsyncTask<Object, Object, Object>> asyncTasks = new ArrayList<>(targetDownloads);

        while (state.keepRunning()) {
            state.pauseTiming();
            totalDownloads.set(0);
            for (int i = 0; i < targetDownloads; i++)
                asyncTasks.add(new AsyncTaskDownload());
            state.resumeTiming();

            for (AsyncTask<Object, Object, Object> asyncTask : asyncTasks)
                asyncTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, blobClient, totalDownloads);

            while (totalDownloads.get() != targetDownloads) {
                // Wait
            }

            state.pauseTiming();
            asyncTasks.clear();
            state.resumeTiming();
        }
    }

    private Disposable downloadBlobReactor(BlobAsyncClient blobAsyncClient) {
        return blobAsyncClient
            .download()
            .subscribeOn(Schedulers.elastic())
            .publishOn(AndroidSchedulers.mainThread())
            .subscribe(this::writeBlobToOutputStream);
    }

    private void writeBlobToOutputStream(Flux<ByteBuffer> flux) {
        ByteArrayOutputStream downloadedData = new ByteArrayOutputStream();
        flux.subscribe(data -> {
            try {
                downloadedData.write(data.array());
                downloadedData.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            downloadComplete = true;
            totalDownloads.incrementAndGet();
        });
    }

    private class AsyncTaskDownload extends AsyncTask<Object, Object, Object> {
        @Override
        protected Object doInBackground(Object... params) {
            try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
                ((BlobClient) params[0]).download(byteArrayOutputStream);
            } catch (IOException e) {
                e.printStackTrace();
            }

            return params;
        }

        @Override
        protected void onPostExecute(Object object) {
            super.onPostExecute(object);
            Object[] objectArray = (Object[]) object;

            if (objectArray.length > 1)
                ((AtomicInteger) objectArray[1]).incrementAndGet();
            else
                downloadComplete = true;
        }
    }
}
