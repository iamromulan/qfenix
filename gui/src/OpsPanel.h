#ifndef QFENIX_GUI_OPSPANEL_H
#define QFENIX_GUI_OPSPANEL_H

#include <wx/wx.h>

class MainFrame;

class OpsPanel : public wxPanel {
public:
	OpsPanel(wxWindow *parent, MainFrame *frame);

	/* Lock/unlock all buttons during operation */
	void SetRunning(bool running);

private:
	/* Build qfenix args from HomePanel config + operation specifics */
	wxArrayString BuildArgs(const wxString &subcommand,
				const wxArrayString &extraArgs = {});

	/* Operation handlers */
	void OnFlash(wxCommandEvent &event);
	void OnFlashErase(wxCommandEvent &event);
	void OnReadAll(wxCommandEvent &event);
	void OnXQCNBackup(wxCommandEvent &event);
	void OnXQCNRestore(wxCommandEvent &event);
	void OnEFSBackupTar(wxCommandEvent &event);
	void OnEFSRestore(wxCommandEvent &event);
	void OnPrintGPT(wxCommandEvent &event);
	void OnStorageInfo(wxCommandEvent &event);
	void OnGetSlot(wxCommandEvent &event);
	void OnSetSlotA(wxCommandEvent &event);
	void OnSetSlotB(wxCommandEvent &event);
	void OnNVRead(wxCommandEvent &event);
	void OnNVWrite(wxCommandEvent &event);
	void OnDiag2EDL(wxCommandEvent &event);
	void OnDeviceReset(wxCommandEvent &event);
	void OnDeviceList(wxCommandEvent &event);
	void OnATConsole(wxCommandEvent &event);
	void OnATCommand(wxCommandEvent &event);
	void OnSMSSend(wxCommandEvent &event);
	void OnSMSRead(wxCommandEvent &event);
	void OnUSSD(wxCommandEvent &event);

	MainFrame *m_frame;
	wxVector<wxButton *> m_buttons;
};

#endif
