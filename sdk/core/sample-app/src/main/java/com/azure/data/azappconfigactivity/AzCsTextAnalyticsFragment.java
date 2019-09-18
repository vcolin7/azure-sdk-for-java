package com.azure.data.azappconfigactivity;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.preference.PreferenceManager;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.policy.AddHeadersPolicy;
import com.azure.core.http.policy.CookiePolicy;
import com.azure.core.http.policy.HttpPipelinePolicy;
import com.azure.core.http.policy.RetryPolicy;
import com.azure.core.http.policy.UserAgentPolicy;
import com.azure.core.reactor.android.AndroidSchedulers;
import com.azure.data.appconfiguration.credentials.ConfigurationClientCredentials;
import com.microsoft.azure.cognitiveservices.language.textanalytics.implementation.TextAnalyticsClientBuilder;
import com.microsoft.azure.cognitiveservices.language.textanalytics.implementation.TextAnalyticsClientImpl;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.DetectedLanguage;
import com.microsoft.azure.cognitiveservices.language.textanalytics.models.LanguageInput;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import reactor.core.Disposable;
import reactor.core.Disposables;
import reactor.core.scheduler.Schedulers;

/**
 * A simple {@link Fragment} subclass.
 * Use the {@link AzCsTextAnalyticsFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class AzCsTextAnalyticsFragment extends Fragment implements View.OnClickListener {
    private final Disposable.Composite disposables = Disposables.composite();

    public AzCsTextAnalyticsFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @return A new instance of fragment AzCsTextAnalyticsFragment.
     */
    public static AzCsTextAnalyticsFragment newInstance() {
        return new AzCsTextAnalyticsFragment();
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.az_cs_text_analytics_fragment, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View rootView, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(rootView, savedInstanceState);

        Button detectLanguageButton = rootView.findViewById(R.id.detectLanguageButton);
        detectLanguageButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View buttonView) {
        SharedPreferences preference = PreferenceManager.getDefaultSharedPreferences(Objects.requireNonNull(getActivity()).getBaseContext());
        String serviceEndpoint = preference.getString("az_cs_endpoint", "<unset>");
        String key = preference.getString("az_cs_key", "<unset>");

        if (serviceEndpoint.isEmpty() || serviceEndpoint.equals("<unset>") || key.isEmpty() || key.equals("<unset>")) {
            TextView responseTextView = buttonView.getRootView().findViewById(R.id.setResponseTxt);
            responseTextView.setText(R.string.az_cs_error);
        } else {
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.put("Ocp-Apim-Subscription-Key", key);
            httpHeaders.put("Content-Type", "application/json");

            List<HttpPipelinePolicy> policies = new ArrayList<>();
            policies.add(new UserAgentPolicy());
            policies.add(new RetryPolicy());
            policies.add(new CookiePolicy());
            policies.add(new AddHeadersPolicy(httpHeaders));

            TextAnalyticsClientImpl client = new TextAnalyticsClientBuilder()
                .endpoint(serviceEndpoint)
                .pipeline(new HttpPipelineBuilder()
                    .policies(policies.toArray(new HttpPipelinePolicy[0]))
                    .build())
                .build();

            // Will add more cases (e.g. sentiment analysis)
            switch (buttonView.getId()) {
                case R.id.detectLanguageButton:
                    onDetectLanguageButtonClick(client, buttonView);
                    break;
            }
        }
    }

    private void onDetectLanguageButtonClick(TextAnalyticsClientImpl client, View buttonView) {
        EditText inputTextView = buttonView.getRootView().findViewById(R.id.inputText);
        String inputText = inputTextView.getText().toString();

        if (Util.isNullOrEmpty(inputText) || inputText.length() < 1)
            Toast.makeText(Objects.requireNonNull(getActivity()).getApplicationContext(), "Input text cannot be empty", Toast.LENGTH_SHORT).show();
        else {
            ArrayList<LanguageInput> documents = new ArrayList<>();
            documents.add(new LanguageInput().id("1").text(inputText));

            Disposable disposable = client.detectLanguageWithRestResponseAsync(false, documents)
                .subscribeOn(Schedulers.elastic())
                .publishOn(AndroidSchedulers.mainThread())
                .subscribe(result -> {
                    // Getting one item for now since we only allow for one document to be sent
                    StringBuilder stringBuilder = new StringBuilder("Detected languages: ").append(System.lineSeparator()).append(System.lineSeparator());
                    List<DetectedLanguage> detectedLanguages = result.value().documents().get(0).detectedLanguages();

                    for (DetectedLanguage detectedLanguage : detectedLanguages) {
                        stringBuilder.append("Language: ").append(detectedLanguage.name()).append(System.lineSeparator())
                            .append("ISO 639-1 Name: ").append(detectedLanguage.iso6391Name()).append(System.lineSeparator())
                            .append("Confidence Score: ").append(detectedLanguage.score()).append(System.lineSeparator())
                            .append(System.lineSeparator());
                    }

                    TextView textView = buttonView.getRootView().findViewById(R.id.detectLanguageResult);
                    textView.setText(stringBuilder.toString());
                }, throwable -> {
                    HttpResponseException responseException = (HttpResponseException) throwable;
                    Toast.makeText(Objects.requireNonNull(getActivity()).getApplicationContext(),
                                   String.format("Operation failed: { code: %d error: %s }", responseException.response().statusCode(), responseException.value()),
                                   Toast.LENGTH_SHORT).show();
                });

            disposables.add(disposable);
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        disposables.dispose();
    }

    private static ConfigurationClientCredentials getClientCredentials(String key) {
        try {
            return new ConfigurationClientCredentials(key);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
