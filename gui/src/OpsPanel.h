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
	/* Build qfenix args with EDL serial + storage type from HomePanel */
	wxArrayString BuildArgs(const wxString &subcommand,
				const wxArrayString &extraArgs = {});

	/* Firmware Flashing */
	void OnFlash(wxCommandEvent &event);
	void OnFlashErase(wxCommandEvent &event);

	/* EDL Partition Ops */
	void OnPrintGPT(wxCommandEvent &event);
	void OnStorageInfo(wxCommandEvent &event);
	void OnReadPartition(wxCommandEvent &event);
	void OnReadAll(wxCommandEvent &event);
	void OnErasePartition(wxCommandEvent &event);
	void OnEraseAll(wxCommandEvent &event);
	void OnGetSlot(wxCommandEvent &event);
	void OnSetSlotA(wxCommandEvent &event);
	void OnSetSlotB(wxCommandEvent &event);
	void OnDeviceReset(wxCommandEvent &event);

	/* EFS Backup & Restore */
	void OnXQCNBackup(wxCommandEvent &event);
	void OnXQCNRestore(wxCommandEvent &event);
	void OnEFSBackupTar(wxCommandEvent &event);
	void OnEFSRestoreTar(wxCommandEvent &event);

	/* DIAG */
	void OnDiag2EDL(wxCommandEvent &event);
	void OnNVRead(wxCommandEvent &event);
	void OnNVWrite(wxCommandEvent &event);

	/* AT Commands & SMS */
	void OnATConsole(wxCommandEvent &event);
	void OnATCommand(wxCommandEvent &event);
	void OnSMSSend(wxCommandEvent &event);
	void OnSMSRead(wxCommandEvent &event);
	void OnSMSDelete(wxCommandEvent &event);
	void OnSMSStatus(wxCommandEvent &event);
	void OnUSSD(wxCommandEvent &event);

	/* Utilities */
	void OnDeviceList(wxCommandEvent &event);
	void OnXQCN2TAR(wxCommandEvent &event);
	void OnTAR2XQCN(wxCommandEvent &event);

	MainFrame *m_frame;
	wxVector<wxButton *> m_buttons;
};

#endif
