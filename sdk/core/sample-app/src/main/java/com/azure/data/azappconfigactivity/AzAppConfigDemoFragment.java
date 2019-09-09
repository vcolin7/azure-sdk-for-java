package com.azure.data.azappconfigactivity;

import android.content.SharedPreferences;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.preference.PreferenceManager;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.reactor.android.AndroidSchedulers;
import com.azure.data.appconfiguration.ConfigurationAsyncClient;
import com.azure.data.appconfiguration.ConfigurationClientBuilder;
import com.azure.data.appconfiguration.credentials.ConfigurationClientCredentials;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import reactor.core.Disposable;
import reactor.core.Disposables;
import reactor.core.scheduler.Schedulers;

public class AzAppConfigDemoFragment extends Fragment implements View.OnClickListener {
    private final Disposable.Composite disposables = Disposables.composite();
    //
    public static AzAppConfigDemoFragment newInstance() {
        return new AzAppConfigDemoFragment();
    }

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.az_app_config_demo_fragment, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View rootView, @Nullable Bundle savedInstanceState) {
        Button setBtn = rootView.findViewById(R.id.setBtn);
        setBtn.setOnClickListener(this);
        //
        Button getBtn = rootView.findViewById(R.id.getBtn);
        getBtn.setOnClickListener(this);
    }

    @Override
    public void onClick(View buttonView) {
        SharedPreferences preference = PreferenceManager.getDefaultSharedPreferences(getActivity().getBaseContext());
        String conString = preference.getString("az_conf_connection", "<unset>");
        String serviceEndpoint = preference.getString("az_conf_endpoint", "<unset>");
        if (conString == "<unset>" || serviceEndpoint == "<unset>") {
            TextView responseTextView = buttonView.getRootView().findViewById(R.id.setResponseTxt);
            responseTextView.setText("Az config connection string or service endpoint is not set in the preference.");
            return;
        } else {
            ConfigurationAsyncClient client = new ConfigurationClientBuilder()
                    .credential(toConfigurationClientCredentails(conString))
                    .endpoint(serviceEndpoint)
                    .buildAsyncClient();

            switch (buttonView.getId()) {
                case R.id.setBtn:
                    onSetButtonClick(client, buttonView);
                    return;
                case R.id.getBtn:
                    onGetButtonClick(client,  buttonView);
                    return;
            }
        }
    }

    private void  onSetButtonClick(ConfigurationAsyncClient client, View buttonView) {
        EditText key = buttonView.getRootView().findViewById(R.id.setConfigKey);
        EditText value = buttonView.getRootView().findViewById(R.id.setConfigValue);
        //
        String keyString = key.getText().toString();
        String valueString = value.getText().toString();
        //
        //
        if (Util.isNullOrEmpty(keyString) || Util.isNullOrEmpty(valueString)) {
            TextView textView = buttonView.getRootView().findViewById(R.id.setResponseTxt);
            textView.setText("key and value required");
            return;
        } else {
            Disposable disposable = client.addSetting(keyString, valueString)
                    .subscribeOn(Schedulers.elastic())
                    .publishOn(AndroidSchedulers.mainThread())
                    .subscribe(settings -> {
                        TextView textView = buttonView.getRootView().findViewById(R.id.setResponseTxt);
                        textView.setText(String.format("Operation succeeded: Result: %s [CurrentThreadName:%s]", settings.key(), Thread.currentThread().getName()));
                    }, throwable -> {
                        HttpResponseException responseException = (HttpResponseException) throwable;
                        TextView textView = buttonView.getRootView().findViewById(R.id.setResponseTxt);
                        textView.setText(String.format("Operation failed: { code: %d error:%s } [CurrentThreadName:%s]", responseException.response().statusCode(), responseException.value(), Thread.currentThread().getName()));
                    });

            disposables.add(disposable);
        }
    }

    private void  onGetButtonClick(ConfigurationAsyncClient client, View buttonView) {
        EditText key = buttonView.getRootView().findViewById(R.id.getConfigKey);
        //
        String keyString = key.getText().toString();
        //
        if (Util.isNullOrEmpty(keyString)) {
            TextView textView = buttonView.getRootView().findViewById(R.id.getResponseTxt);
            textView.setText("key required");
            return;
        } else {
            Disposable disposable = client.getSetting(keyString)
                    .subscribeOn(Schedulers.elastic())
                    .publishOn(AndroidSchedulers.mainThread())
                    .subscribe(settings -> {
                        TextView textView = buttonView.getRootView().findViewById(R.id.setResponseTxt);
                        textView.setText(String.format("Operation succeeded: Retrieved Value: %s [CurrentThreadName:%s]", settings.key(), Thread.currentThread().getName()));
                    }, throwable -> {
                        HttpResponseException responseException = (HttpResponseException) throwable;
                        TextView textView = buttonView.getRootView().findViewById(R.id.setResponseTxt);
                        textView.setText(String.format("Operation failed: { code: %d error:%s } [CurrentThreadName:%s]", responseException.response().statusCode(), responseException.value(), Thread.currentThread().getName()));
                    });

            disposables.add(disposable);
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        disposables.dispose();
    }

    private static ConfigurationClientCredentials toConfigurationClientCredentails(String connectionString) {
        try {
            return new ConfigurationClientCredentials(connectionString);
        } catch (InvalidKeyException ive) {
            throw new RuntimeException(ive);
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
    }
}
