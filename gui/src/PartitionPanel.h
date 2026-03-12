#ifndef QFENIX_GUI_PARTITIONPANEL_H
#define QFENIX_GUI_PARTITIONPANEL_H

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <vector>

class MainFrame;

struct StorageInfo {
	wxString memType;
	wxString prodName;
	unsigned long totalBlocks = 0;
	unsigned int blockSize = 0;
	unsigned int pageSize = 0;
	unsigned int sectorSize = 0;
	unsigned int numPhysical = 0;
};

struct PartitionEntry {
	int index = 0;
	wxString name;
	wxString startStr;
	wxString endStr;	/* GPT only */
	wxString sizeStr;
	wxString typeGuid;	/* GPT only */
	wxString attrs;
};

enum PartitionFormat { PART_NONE, PART_NAND, PART_GPT };

class PartitionPanel : public wxPanel {
public:
	PartitionPanel(wxWindow *parent, MainFrame *frame);

	/* Lock/unlock buttons during async operations */
	void SetRunning(bool running);

	/* Update the device status label from HomePanel's detected devices */
	void UpdateDeviceStatus();

private:
	wxArrayString BuildEDLArgs(const wxString &subcommand,
				   const wxArrayString &extraArgs = {});
	void ParsePartInfo(const wxString &output);
	void PopulateListCtrl();
	void UpdateStorageInfoDisplay();

	void OnScanDevice(wxCommandEvent &event);
	void OnBackup(wxCommandEvent &event);
	void OnReplace(wxCommandEvent &event);
	void OnErase(wxCommandEvent &event);
	void OnPartitionSelected(wxListEvent &event);
	void OnPartitionDeselected(wxListEvent &event);

	MainFrame *m_frame;
	wxStaticText *m_deviceStatus;
	wxStaticText *m_storageInfoText;
	wxListCtrl *m_partList;

	wxButton *m_scanBtn;
	wxButton *m_backupBtn;
	wxButton *m_replaceBtn;
	wxButton *m_eraseBtn;
	wxVector<wxButton *> m_allButtons;

	std::vector<PartitionEntry> m_partitions;
	StorageInfo m_storageInfo;
	PartitionFormat m_partFormat = PART_NONE;
};

#endif
