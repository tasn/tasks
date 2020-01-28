package org.tasks.etesync;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.appcompat.widget.Toolbar;
import androidx.lifecycle.ViewModelProviders;
import butterknife.OnFocusChange;
import butterknife.OnTextChanged;
import com.todoroo.astrid.helper.UUIDHelper;
import javax.inject.Inject;
import org.tasks.R;
import org.tasks.activities.AddEteSyncAccountViewModel;
import org.tasks.analytics.Tracking.Events;
import org.tasks.caldav.BaseCaldavAccountSettingsActivity;
import org.tasks.data.CaldavAccount;
import org.tasks.gtasks.PlayServices;
import org.tasks.injection.ActivityComponent;
import org.tasks.injection.ForApplication;

public class EteSyncAccountSettingsActivity extends BaseCaldavAccountSettingsActivity
    implements Toolbar.OnMenuItemClickListener {

  @Inject @ForApplication Context context;
  @Inject PlayServices playServices;
  @Inject EteSyncClient eteSyncClient;

  private AddEteSyncAccountViewModel addAccountViewModel;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    binding.repeat.setVisibility(View.GONE);
    binding.encryptionPasswordLayout.setVisibility(View.VISIBLE);

    addAccountViewModel = ViewModelProviders.of(this).get(AddEteSyncAccountViewModel.class);

    if (savedInstanceState == null) {
      if (caldavAccount == null) {
        binding.url.setText(R.string.etesync_url);
      }
    }

    addAccountViewModel.observe(this, this::addAccount, this::requestFailed);
  }

  private void addAccount(String authToken) {
    CaldavAccount newAccount = new CaldavAccount();
    newAccount.setAccountType(CaldavAccount.TYPE_ETESYNC);
    newAccount.setName(getNewName());
    newAccount.setUrl(getNewURL());
    newAccount.setUsername(getNewUsername());
    newAccount.setPassword(encryption.encrypt(getNewPassword()));
    newAccount.setUuid(UUIDHelper.newUUID());
    newAccount.setEncryptionPassword(encryption.encrypt(getNewEncryptionPassword()));
    newAccount.setAuthToken(authToken);
    newAccount.setId(caldavDao.insert(newAccount));

    tracker.reportEvent(Events.CALDAV_ACCOUNT_ADDED);

    setResult(RESULT_OK);
    finish();
  }

  @Override
  protected void addAccount(
      String url, String username, String password, String encryptionPassword) {
    addAccountViewModel.addAccount(
        playServices, context, eteSyncClient, url, username, password, encryptionPassword);
  }

  @Override
  protected void updateAccount(
      String url, String username, String password, String encryptionPassword) {}

  @Override
  public void inject(ActivityComponent component) {
    component.inject(this);
  }

  @OnTextChanged(R.id.encryption_password)
  void onEncryptionPasswordChanged(CharSequence text) {
    binding.encryptionPasswordLayout.setError(null);
  }

  @OnFocusChange(R.id.encryption_password)
  void onEncryptionPasswordFocused(boolean hasFocus) {
    changePasswordFocus(binding.encryptionPassword, hasFocus);
  }
}
