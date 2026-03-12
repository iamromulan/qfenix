#ifndef QFENIX_GUI_HOMEPANEL_H
#define QFENIX_GUI_HOMEPANEL_H

#include <wx/wx.h>

class MainFrame;

class HomePanel : public wxPanel {
public:
	HomePanel(wxWindow *parent, MainFrame *frame);

	/* Getters for current configuration (used by OpsPanel to build args) */
	wxString GetDiagPort() const;
	wxString GetATPort() const;
	wxString GetEDLSerial() const;
	wxString GetFirmwareDir() const;
	wxString GetWorkingDir() const;
	wxString GetProgrammer() const;
	wxString GetStorageType() const;

	/* Refresh device list from qfenix list.
	 * quiet=true suppresses "Scanning..." status and uses
	 * wxEXEC_NOEVENTS to prevent dock icon bounce on macOS. */
	void RefreshDevices(bool quiet = false);

	/* Auto-refresh control (paused during operations) */
	void StartAutoRefresh();
	void StopAutoRefresh();

private:
	void OnRefresh(wxCommandEvent &event);
	void OnAutoRefreshTimer(wxTimerEvent &event);
	void OnCountdownTimer(wxTimerEvent &event);
	void OnBrowseFirmware(wxCommandEvent &event);
	void OnBrowseWorkDir(wxCommandEvent &event);
	void OnBrowseProgrammer(wxCommandEvent &event);
	void ParseDeviceList(const wxString &output);
	void UpdateDaemonStatus(bool quiet = false);

	MainFrame *m_frame;
	wxTimer m_autoRefreshTimer;
	wxTimer m_countdownTimer;
	int m_countdownSeconds = 0;
	wxStaticText *m_countdownLabel;

	/* Device/port controls */
	wxComboBox *m_diagPort;
	wxComboBox *m_atPort;
	wxComboBox *m_edlSerial;

	/* Path controls */
	wxTextCtrl *m_firmwareDir;
	wxTextCtrl *m_workingDir;
	wxTextCtrl *m_programmer;

	/* Storage type */
	wxChoice *m_storageType;

	/* Status display */
	wxStaticText *m_statusText;
};

#endif
