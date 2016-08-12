package org.tasks.injection;

import com.todoroo.astrid.actfm.FilterSettingsActivity;
import com.todoroo.astrid.actfm.TagSettingsActivity;
import com.todoroo.astrid.activity.BeastModePreferences;
import com.todoroo.astrid.activity.ShareLinkActivity;
import com.todoroo.astrid.activity.TaskListActivity;
import com.todoroo.astrid.core.CustomFilterActivity;
import com.todoroo.astrid.core.DefaultsPreferences;
import com.todoroo.astrid.core.OldTaskPreferences;
import com.todoroo.astrid.files.AACRecordingActivity;
import com.todoroo.astrid.gcal.CalendarReminderActivity;
import com.todoroo.astrid.reminders.ReminderPreferences;

import org.tasks.activities.AddAttachmentActivity;
import org.tasks.activities.CalendarSelectionActivity;
import org.tasks.activities.CameraActivity;
import org.tasks.activities.ClearGtaskDataActivity;
import org.tasks.activities.ColorPickerActivity;
import org.tasks.activities.DateAndTimePickerActivity;
import org.tasks.activities.DatePickerActivity;
import org.tasks.activities.ExportTaskActivity;
import org.tasks.activities.FilterSelectionActivity;
import org.tasks.activities.ImportTaskActivity;
import org.tasks.activities.TimePickerActivity;
import org.tasks.files.FileExplore;
import org.tasks.files.MyFilePickerActivity;
import org.tasks.preferences.AppearancePreferences;
import org.tasks.preferences.BackupPreferences;
import org.tasks.preferences.BasicPreferences;
import org.tasks.preferences.DateShortcutPreferences;
import org.tasks.preferences.HelpAndFeedbackActivity;
import org.tasks.preferences.MiscellaneousPreferences;
import org.tasks.reminders.MissedCallActivity;
import org.tasks.reminders.NotificationActivity;
import org.tasks.reminders.SnoozeActivity;
import org.tasks.themes.Theme;
import org.tasks.voice.VoiceCommandActivity;
import org.tasks.widget.ShortcutConfigActivity;
import org.tasks.widget.WidgetConfigActivity;

public interface BaseActivityComponent {

    Theme getTheme();

    FragmentComponent plus(FragmentModule module);

    DialogFragmentComponent plus(DialogFragmentModule dialogFragmentModule);

    NativeDialogFragmentComponent plus(NativeDialogFragmentModule nativeDialogFragmentModule);

    void inject(AACRecordingActivity aacRecordingActivity);

    void inject(CustomFilterActivity customFilterActivity);

    void inject(CalendarReminderActivity calendarReminderActivity);

    void inject(FilterSettingsActivity filterSettingsActivity);

    void inject(TagSettingsActivity tagSettingsActivity);

    void inject(ShareLinkActivity shareLinkActivity);

    void inject(TaskListActivity taskListActivity);

    void inject(BeastModePreferences beastModePreferences);

    void inject(NotificationActivity notificationActivity);

    void inject(SnoozeActivity snoozeActivity);

    void inject(MissedCallActivity missedCallActivity);

    void inject(FileExplore fileExplore);

    void inject(CalendarSelectionActivity calendarSelectionActivity);

    void inject(FilterSelectionActivity filterSelectionActivity);

    void inject(DateAndTimePickerActivity dateAndTimePickerActivity);

    void inject(ExportTaskActivity exportTaskActivity);

    void inject(ImportTaskActivity importTaskActivity);

    void inject(AddAttachmentActivity addAttachmentActivity);

    void inject(DatePickerActivity datePickerActivity);

    void inject(CameraActivity cameraActivity);

    void inject(TimePickerActivity timePickerActivity);

    void inject(VoiceCommandActivity voiceCommandActivity);

    void inject(ClearGtaskDataActivity clearGtaskDataActivity);

    void inject(ReminderPreferences reminderPreferences);

    void inject(WidgetConfigActivity widgetConfigActivity);

    void inject(OldTaskPreferences oldTaskPreferences);

    void inject(DefaultsPreferences defaultsPreferences);

    void inject(ShortcutConfigActivity shortcutConfigActivity);

    void inject(BackupPreferences backupPreferences);

    void inject(MiscellaneousPreferences miscellaneousPreferences);

    void inject(BasicPreferences basicPreferences);

    void inject(HelpAndFeedbackActivity helpAndFeedbackActivity);

    void inject(DateShortcutPreferences dateShortcutPreferences);

    void inject(AppearancePreferences appearancePreferences);

    void inject(MyFilePickerActivity myFilePickerActivity);

    void inject(ColorPickerActivity colorPickerActivity);
}
