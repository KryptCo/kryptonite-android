package co.krypt.krypton.onboarding;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Rect;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;

import java.util.Iterator;

import co.krypt.krypton.R;
import co.krypt.krypton.analytics.Analytics;
import co.krypt.krypton.approval.ApprovalDialog;
import co.krypt.krypton.pairing.Pairing;
import co.krypt.krypton.policy.LocalAuthentication;
import co.krypt.krypton.silo.Silo;
import co.krypt.krypton.utils.Services;

import static co.krypt.kryptonite.MainActivity.CAMERA_PERMISSION_GRANTED_ACTION;
import static co.krypt.kryptonite.MainActivity.CAMERA_PERMISSION_REQUEST;
import static co.krypt.kryptonite.MainActivity.USER_AUTHENTICATION_REQUEST;

public class OnboardingActivity extends FragmentActivity {

    private static final String TAG = "Onboarding";

    private static final Services services = new Services();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        setTheme(R.style.AppTheme);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_onboarding);

        new Analytics(getApplicationContext()).postEvent("onboard", "start", null, null, false);

        FragmentTransaction fragmentTransaction = getSupportFragmentManager().beginTransaction();

        OnboardingProgress progress = new OnboardingProgress(getApplicationContext());
        GenerateFragment generateFragment;
        FirstPairExtFragment firstPairExtFragment;
        FirstPairCliFragment firstPairCliFragment;
        TestSSHFragment testSSHFragment;
        switch (progress.currentStage()) {
            case NONE:
                generateFragment = new GenerateFragment();
                fragmentTransaction.add(R.id.activity_onboarding, generateFragment).commit();
                break;
            case GENERATE:
                generateFragment = new GenerateFragment();
                fragmentTransaction.add(R.id.activity_onboarding, generateFragment).commit();
                break;
            case GENERATING:
                //  generation must have failed, start from beginning
                generateFragment = new GenerateFragment();
                fragmentTransaction.add(R.id.activity_onboarding, generateFragment).commit();
                break;
            case FIRST_PAIR_EXT:
                firstPairExtFragment = new FirstPairExtFragment();
                fragmentTransaction.add(R.id.activity_onboarding, firstPairExtFragment).commit();
                break;
            case FIRST_PAIR_CLI:
                firstPairCliFragment = new FirstPairCliFragment();
                fragmentTransaction.add(R.id.activity_onboarding, firstPairCliFragment).commit();
                break;
            case TEST_SSH:
                Iterator<Pairing> pairings = Silo.shared(getApplicationContext()).pairings().loadAll().iterator();
                if (pairings.hasNext()) {
                    testSSHFragment = TestSSHFragment.newInstance(pairings.next().workstationName);
                    fragmentTransaction.add(R.id.activity_onboarding, testSSHFragment).commit();
                } else {
                    //  revert to FirstPair stage
                    firstPairExtFragment = new FirstPairExtFragment();
                    fragmentTransaction.add(R.id.activity_onboarding, firstPairExtFragment).commit();
                }
                break;
        }

        if (getIntent() != null) {
            onNewIntent(getIntent());
        }
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        if (event.getAction() == MotionEvent.ACTION_DOWN) {
            View v = getCurrentFocus();
            if ( v instanceof EditText) {
                Rect outRect = new Rect();
                v.getGlobalVisibleRect(outRect);
                if (v.hasFocus() && !outRect.contains((int)event.getRawX(), (int)event.getRawY())) {
                    v.clearFocus();
                    InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                    imm.hideSoftInputFromWindow(v.getWindowToken(), 0);
                }
            }
        }
        return super.dispatchTouchEvent(event);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        switch (requestCode) {
            case CAMERA_PERMISSION_REQUEST:
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    Intent cameraIntent = new Intent(CAMERA_PERMISSION_GRANTED_ACTION);
                    LocalBroadcastManager.getInstance(this).sendBroadcast(cameraIntent);
                }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == USER_AUTHENTICATION_REQUEST) {
            if (resultCode == RESULT_OK) {
                LocalAuthentication.onSuccess();
            }
        }
    }

    @Override
    public void onBackPressed() {
        FragmentTransaction fragmentTransaction = getSupportFragmentManager().beginTransaction();
        fragmentTransaction.setCustomAnimations(R.anim.enter_from_left, R.anim.exit_to_right);
        OnboardingProgress progress = new OnboardingProgress(getApplicationContext());

        Fragment currentFragment = getSupportFragmentManager().findFragmentById(R.id.activity_onboarding);
        if (currentFragment != null) {
            fragmentTransaction.remove(currentFragment);
        }

        switch (progress.currentStage()) {
            case NONE:
                break;
            case GENERATE:
                break;
            case GENERATING:
                break;
            case FIRST_PAIR_EXT:
                break;
            case FIRST_PAIR_CLI:
                break;
            case TEST_SSH:
                break;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Silo.shared(getApplicationContext()).start();
    }

    @Override
    protected void onPause() {
        Silo.shared(getApplicationContext()).stop();
        super.onPause();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        if (intent.getStringExtra("requestID") != null) {
            final String requestID = intent.getStringExtra("requestID");
            ApprovalDialog.showApprovalDialog(this, requestID);
        } else {
            Log.d(TAG, "empty intent");
        }
    }
}
