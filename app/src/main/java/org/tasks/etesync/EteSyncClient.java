package org.tasks.etesync;

import static android.text.TextUtils.isEmpty;
import static at.bitfire.dav4jvm.XmlUtils.NS_CALDAV;
import static at.bitfire.dav4jvm.XmlUtils.NS_CARDDAV;
import static at.bitfire.dav4jvm.XmlUtils.NS_WEBDAV;

import android.content.Context;
import at.bitfire.cert4android.CustomCertManager;
import at.bitfire.cert4android.CustomCertManager.CustomHostnameVerifier;
import at.bitfire.dav4jvm.DavResource;
import at.bitfire.dav4jvm.Property.Name;
import at.bitfire.dav4jvm.Response;
import at.bitfire.dav4jvm.XmlUtils;
import at.bitfire.dav4jvm.exception.DavException;
import at.bitfire.dav4jvm.exception.HttpException;
import at.bitfire.dav4jvm.property.CalendarHomeSet;
import com.etesync.journalmanager.Crypto;
import com.etesync.journalmanager.Crypto.AsymmetricKeyPair;
import com.etesync.journalmanager.Crypto.CryptoManager;
import com.etesync.journalmanager.Exceptions;
import com.etesync.journalmanager.Exceptions.IntegrityException;
import com.etesync.journalmanager.Exceptions.VersionTooNewException;
import com.etesync.journalmanager.JournalAuthenticator;
import com.etesync.journalmanager.JournalManager;
import com.etesync.journalmanager.JournalManager.Journal;
import com.etesync.journalmanager.UserInfoManager;
import com.etesync.journalmanager.UserInfoManager.UserInfo;
import com.todoroo.astrid.helper.UUIDHelper;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClient.Builder;
import okhttp3.internal.tls.OkHostnameVerifier;
import org.tasks.DebugNetworkInterceptor;
import org.tasks.R;
import org.tasks.caldav.MemoryCookieStore;
import org.tasks.caldav.ResponseList;
import org.tasks.data.CaldavAccount;
import org.tasks.data.CaldavCalendar;
import org.tasks.injection.ForApplication;
import org.tasks.preferences.Preferences;
import org.tasks.security.Encryption;
import org.tasks.ui.DisplayableException;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import org.xmlpull.v1.XmlSerializer;
import timber.log.Timber;

public class EteSyncClient {

  private final Encryption encryption;
  private final Preferences preferences;
  private final DebugNetworkInterceptor interceptor;
  private final String username;
  private final String token;
  private final String encryptionPassword;
  private final OkHttpClient httpClient;
  private final HttpUrl httpUrl;
  private final Context context;
  private final JournalManager journalManager;
  private boolean foreground;

  @Inject
  public EteSyncClient(
      @ForApplication Context context,
      Encryption encryption,
      Preferences preferences,
      DebugNetworkInterceptor interceptor) {
    this.context = context;
    this.encryption = encryption;
    this.preferences = preferences;
    this.interceptor = interceptor;
    username = null;
    token = null;
    encryptionPassword = null;
    httpClient = null;
    httpUrl = null;
    journalManager = null;
  }

  private EteSyncClient(
      Context context,
      Encryption encryption,
      Preferences preferences,
      DebugNetworkInterceptor interceptor,
      String url,
      String username,
      String token,
      String encryptionPassword,
      boolean foreground)
      throws NoSuchAlgorithmException, KeyManagementException {
    this.context = context;
    this.encryption = encryption;
    this.preferences = preferences;
    this.interceptor = interceptor;
    this.username = username;
    this.token = token;
    this.encryptionPassword = encryptionPassword;

    CustomCertManager customCertManager = new CustomCertManager(context);
    customCertManager.setAppInForeground(foreground);
    CustomHostnameVerifier hostnameVerifier =
        customCertManager.hostnameVerifier(OkHostnameVerifier.INSTANCE);
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, new TrustManager[] {customCertManager}, null);

    Builder builder =
        new OkHttpClient()
            .newBuilder()
            .addNetworkInterceptor(new TokenAuthenticator(token))
            .cookieJar(new MemoryCookieStore())
            .followRedirects(false)
            .followSslRedirects(true)
            .sslSocketFactory(sslContext.getSocketFactory(), customCertManager)
            .hostnameVerifier(hostnameVerifier)
            .readTimeout(30, TimeUnit.SECONDS);
    if (preferences.isFlipperEnabled()) {
      interceptor.add(builder);
    }
    httpClient = builder.build();
    httpUrl = HttpUrl.parse(url);
    journalManager = new JournalManager(httpClient, httpUrl);
  }

  public EteSyncClient forAccount(CaldavAccount account)
      throws NoSuchAlgorithmException, KeyManagementException {
    return forUrl(
        account.getUrl(),
        account.getUsername(),
        account.getAuthToken(),
        account.getEncryptionPassword(encryption));
  }

  public EteSyncClient forCalendar(CaldavAccount account, CaldavCalendar calendar)
      throws NoSuchAlgorithmException, KeyManagementException {
    return forUrl(
        calendar.getUrl(),
        account.getUsername(),
        account.getAuthToken(),
        account.getEncryptionPassword(encryption));
  }

  public EteSyncClient forUrl(String url, String username, String token, String encryptionPassword)
      throws KeyManagementException, NoSuchAlgorithmException {
    return new EteSyncClient(
        context,
        encryption,
        preferences,
        interceptor,
        url,
        username,
        token,
        encryptionPassword,
        foreground);
  }

  private String findHomeset(HttpUrl httpUrl) throws DavException, IOException {
    DavResource davResource = new DavResource(httpClient, httpUrl);
    ResponseList responses = new ResponseList();
    davResource.propfind(0, new Name[] {CalendarHomeSet.NAME}, responses);
    Response response = responses.get(0);
    CalendarHomeSet calendarHomeSet = response.get(CalendarHomeSet.class);
    if (calendarHomeSet == null) {
      throw new DisplayableException(R.string.caldav_home_set_not_found);
    }
    List<String> hrefs = calendarHomeSet.getHrefs();
    if (hrefs.size() != 1) {
      throw new DisplayableException(R.string.caldav_home_set_not_found);
    }
    String homeSet = hrefs.get(0);
    if (isEmpty(homeSet)) {
      throw new DisplayableException(R.string.caldav_home_set_not_found);
    }
    return davResource.getLocation().resolve(homeSet).toString();
  }

  public EteSyncClient fetchToken(String url, String username, String password)
      throws IOException, Exceptions.HttpException, NoSuchAlgorithmException,
          KeyManagementException {
    JournalAuthenticator journalAuthenticator =
        new JournalAuthenticator(httpClient, HttpUrl.parse(url));
    String token = journalAuthenticator.getAuthToken(username, password);
    return forUrl(url, username, token, encryptionPassword);
  }

  public EteSyncClient testEncryptionPassword()
      throws IntegrityException, VersionTooNewException, Exceptions.HttpException {
    getKeyPair();
    return this;
  }

  private AsymmetricKeyPair getKeyPair()
      throws VersionTooNewException, IntegrityException, Exceptions.HttpException {
    UserInfoManager userInfoManager = new UserInfoManager(httpClient, httpUrl);
    UserInfo userInfo = userInfoManager.fetch(username);
    String key = Crypto.deriveKey(username, encryptionPassword);
    CryptoManager cryptoManager = new CryptoManager(userInfo.getVersion(), key, "userInfo");
    userInfo.verify(cryptoManager);
    return new AsymmetricKeyPair(userInfo.getContent(cryptoManager), userInfo.getPubkey());
  }

  public List<Response> getCalendars()
      throws Exceptions.HttpException, VersionTooNewException, IntegrityException {
    for (Journal journal : journalManager.list()) {
      CryptoManager cryptoManager;
      if (journal.getKey() != null) {
        cryptoManager = new CryptoManager(journal.getVersion(), getKeyPair(), journal.getKey());
      } else {
        cryptoManager =
            new CryptoManager(journal.getVersion(), encryptionPassword, journal.getUid());
      }
      journal.verify(cryptoManager);
      String content = journal.getContent(cryptoManager);
      Timber.d(content);
    }

    return Collections.emptyList();
  }

  public void deleteCollection() throws IOException, HttpException {
    new DavResource(httpClient, httpUrl).delete(null, response -> null);
  }

  public String makeCollection(String displayName)
      throws IOException, XmlPullParserException, HttpException {
    DavResource davResource =
        new DavResource(httpClient, httpUrl.resolve(UUIDHelper.newUUID() + "/"));
    String mkcolString = getMkcolString(displayName);
    davResource.mkCol(mkcolString, response -> null);
    return davResource.getLocation().toString();
  }

  private String getMkcolString(String displayName) throws IOException, XmlPullParserException {
    XmlPullParserFactory xmlPullParserFactory = XmlPullParserFactory.newInstance();
    XmlSerializer xml = xmlPullParserFactory.newSerializer();
    StringWriter stringWriter = new StringWriter();
    xml.setOutput(stringWriter);
    xml.startDocument("UTF-8", null);
    xml.setPrefix("", NS_WEBDAV);
    xml.setPrefix("CAL", NS_CALDAV);
    xml.setPrefix("CARD", NS_CARDDAV);
    xml.startTag(NS_WEBDAV, "mkcol");
    xml.startTag(XmlUtils.NS_WEBDAV, "set");
    xml.startTag(XmlUtils.NS_WEBDAV, "prop");
    xml.startTag(XmlUtils.NS_WEBDAV, "resourcetype");
    xml.startTag(XmlUtils.NS_WEBDAV, "collection");
    xml.endTag(XmlUtils.NS_WEBDAV, "collection");
    xml.startTag(XmlUtils.NS_CALDAV, "calendar");
    xml.endTag(XmlUtils.NS_CALDAV, "calendar");
    xml.endTag(XmlUtils.NS_WEBDAV, "resourcetype");
    xml.startTag(XmlUtils.NS_WEBDAV, "displayname");
    xml.text(displayName);
    xml.endTag(XmlUtils.NS_WEBDAV, "displayname");
    xml.startTag(XmlUtils.NS_CALDAV, "supported-calendar-component-set");
    xml.startTag(XmlUtils.NS_CALDAV, "comp");
    xml.attribute(null, "name", "VTODO");
    xml.endTag(XmlUtils.NS_CALDAV, "comp");
    xml.endTag(XmlUtils.NS_CALDAV, "supported-calendar-component-set");
    xml.endTag(XmlUtils.NS_WEBDAV, "prop");
    xml.endTag(XmlUtils.NS_WEBDAV, "set");
    xml.endTag(XmlUtils.NS_WEBDAV, "mkcol");
    xml.endDocument();
    xml.flush();
    return stringWriter.toString();
  }

  OkHttpClient getHttpClient() {
    return httpClient;
  }

  public String getAuthToken() {
    return token;
  }

  public EteSyncClient setForeground() {
    foreground = true;
    return this;
  }
}
