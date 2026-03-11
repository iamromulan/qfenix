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

	/* Refresh device list from qfenix list */
	void RefreshDevices();

private:
	void OnRefresh(wxCommandEvent &event);
	void OnBrowseFirmware(wxCommandEvent &event);
	void OnBrowseWorkDir(wxCommandEvent &event);
	void OnBrowseProgrammer(wxCommandEvent &event);
	void ParseDeviceList(const wxString &output);
	void UpdateDaemonStatus();

	MainFrame *m_frame;

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
