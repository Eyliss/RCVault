package com.riddleandcode.vault.fragments;


import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;

import com.riddleandcode.vault.R;
import com.riddleandcode.vault.activities.TagReaderActivity;
import com.riddleandcode.vault.utils.Constants;

/**
 * A simple {@link Fragment} subclass.
 */
public class VerifyFragment extends Fragment {

    private Button mVerifyButton;

    public VerifyFragment() {
        // Required empty public constructor
    }


    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {

        View rootView = inflater.inflate(R.layout.fragment_verify, container, false);

        mVerifyButton = (Button)rootView.findViewById(R.id.verify_button);
        mVerifyButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startVerificationProcess();

            }
        });
        return rootView;
    }

    private void startVerificationProcess(){
        Intent intent = new Intent(getActivity(), TagReaderActivity.class);
        intent.putExtra(Constants.INTENT_PROCESS_TYPE, Constants.VERIFICATION);
        startActivity(intent);
    }
}
