package org.tasks.caldav;

import android.content.Context;
import android.os.Bundle;
import androidx.appcompat.widget.Toolbar;
import androidx.lifecycle.ViewModelProviders;
import com.todoroo.astrid.helper.UUIDHelper;
import javax.inject.Inject;
import org.tasks.activities.AddCaldavAccountViewModel;
import org.tasks.activities.UpdateCaldavAccountViewModel;
import org.tasks.analytics.Tracking.Events;
import org.tasks.data.CaldavAccount;
import org.tasks.gtasks.PlayServices;
import org.tasks.injection.ActivityComponent;
import org.tasks.injection.ForApplication;
import timber.log.Timber;

public class CaldavAccountSettingsActivity extends BaseCaldavAccountSettingsActivity
    implements Toolbar.OnMenuItemClickListener {

  @Inject @ForApplication Context context;
  @Inject CaldavClient client;
  @Inject PlayServices playServices;

  private AddCaldavAccountViewModel addCaldavAccountViewModel;
  private UpdateCaldavAccountViewModel updateCaldavAccountViewModel;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    addCaldavAccountViewModel = ViewModelProviders.of(this).get(AddCaldavAccountViewModel.class);
    updateCaldavAccountViewModel =
        ViewModelProviders.of(this).get(UpdateCaldavAccountViewModel.class);

    addCaldavAccountViewModel.observe(this, this::addAccount, this::requestFailed);
    updateCaldavAccountViewModel.observe(this, this::updateAccount, this::requestFailed);
  }

  private void addAccount(String principal) {
    Timber.d("Found principal: %s", principal);

    CaldavAccount newAccount = new CaldavAccount();
    newAccount.setName(getNewName());
    newAccount.setUrl(principal);
    newAccount.setUsername(getNewUsername());
    newAccount.setPassword(encryption.encrypt(getNewPassword()));
    newAccount.setUuid(UUIDHelper.newUUID());
    newAccount.setId(caldavDao.insert(newAccount));

    tracker.reportEvent(Events.CALDAV_ACCOUNT_ADDED);

    setResult(RESULT_OK);
    finish();
  }

  @Override
  protected void addAccount(
      String url, String username, String password, String encryptionPassword) {
    addCaldavAccountViewModel.addAccount(playServices, context, client, url, username, password);
  }

  @Override
  protected void updateAccount(
      String url, String username, String password, String encryptionPassword) {
    updateCaldavAccountViewModel.updateCaldavAccount(client, url, username, password);
  }

  @Override
  public void inject(ActivityComponent component) {
    component.inject(this);
  }
}
