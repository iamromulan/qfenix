#ifndef QFENIX_GUI_NVBROWSERPANEL_H
#define QFENIX_GUI_NVBROWSERPANEL_H

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <vector>

class MainFrame;

struct EfsEntry {
	wxString type;	/* dir, file, item, link */
	int size = 0;
	int mode = 0;	/* octal mode, e.g. 0755 */
	wxString name;
};

class NVBrowserPanel : public wxPanel {
public:
	NVBrowserPanel(wxWindow *parent, MainFrame *frame);

private:
	int RunEfsCommand(const wxString &subcmd,
			  const wxArrayString &extraArgs,
			  wxArrayString *output = nullptr);
	void RefreshListing();
	void ParseEfsListing(const wxArrayString &output);
	void PopulateListCtrl();
	void UpdateButtonState();

	void OnRefresh(wxCommandEvent &event);
	void OnUp(wxCommandEvent &event);
	void OnItemActivated(wxListEvent &event);
	void OnItemSelected(wxListEvent &event);
	void OnItemDeselected(wxListEvent &event);
	void OnDownload(wxCommandEvent &event);
	void OnUpload(wxCommandEvent &event);
	void OnDelete(wxCommandEvent &event);
	void OnNewFolder(wxCommandEvent &event);
	void OnProperties(wxCommandEvent &event);

	MainFrame *m_frame;
	wxTextCtrl *m_pathBar;
	wxListCtrl *m_fileList;
	wxStaticText *m_statusText;

	wxButton *m_downloadBtn;
	wxButton *m_uploadBtn;
	wxButton *m_deleteBtn;
	wxButton *m_propertiesBtn;

	std::vector<EfsEntry> m_entries;
	wxString m_currentPath = "/";
};

#endif
