#include "NVBrowserPanel.h"
#include "MainFrame.h"
#include "HomePanel.h"
#include "ProcessRunner.h"
#include <wx/filedlg.h>
#include <wx/textdlg.h>
#include <wx/tokenzr.h>
#include <wx/busyinfo.h>

NVBrowserPanel::NVBrowserPanel(wxWindow *parent, MainFrame *frame)
	: wxPanel(parent), m_frame(frame)
{
	auto *mainSizer = new wxBoxSizer(wxVERTICAL);

	/* --- Top row: Up + path bar + Refresh --- */
	auto *topRow = new wxBoxSizer(wxHORIZONTAL);

	auto *upBtn = new wxButton(this, wxID_ANY, "Up");
	upBtn->Bind(wxEVT_BUTTON, &NVBrowserPanel::OnUp, this);
	topRow->Add(upBtn, 0, wxRIGHT, 4);

	m_pathBar = new wxTextCtrl(this, wxID_ANY, "/",
				   wxDefaultPosition, wxDefaultSize,
				   wxTE_READONLY);
	topRow->Add(m_pathBar, 1, wxRIGHT, 4);

	auto *refreshBtn = new wxButton(this, wxID_ANY, "Refresh");
	refreshBtn->Bind(wxEVT_BUTTON, &NVBrowserPanel::OnRefresh, this);
	topRow->Add(refreshBtn, 0);

	mainSizer->Add(topRow, 0, wxEXPAND | wxALL, 8);

	/* --- File list (wxListCtrl) --- */
	m_fileList = new wxListCtrl(this, wxID_ANY, wxDefaultPosition,
				    wxDefaultSize,
				    wxLC_REPORT | wxLC_SINGLE_SEL);
	m_fileList->InsertColumn(0, "Type", wxLIST_FORMAT_LEFT, 50);
	m_fileList->InsertColumn(1, "Size", wxLIST_FORMAT_RIGHT, 90);
	m_fileList->InsertColumn(2, "Mode", wxLIST_FORMAT_RIGHT, 60);
	m_fileList->InsertColumn(3, "Name", wxLIST_FORMAT_LEFT, 400);

	m_fileList->Bind(wxEVT_LIST_ITEM_ACTIVATED,
			 &NVBrowserPanel::OnItemActivated, this);
	m_fileList->Bind(wxEVT_LIST_ITEM_SELECTED,
			 &NVBrowserPanel::OnItemSelected, this);
	m_fileList->Bind(wxEVT_LIST_ITEM_DESELECTED,
			 &NVBrowserPanel::OnItemDeselected, this);

	mainSizer->Add(m_fileList, 1, wxEXPAND | wxLEFT | wxRIGHT, 8);

	/* --- Bottom row: action buttons --- */
	auto *btnRow = new wxBoxSizer(wxHORIZONTAL);

	m_downloadBtn = new wxButton(this, wxID_ANY, "Download");
	m_downloadBtn->Bind(wxEVT_BUTTON, &NVBrowserPanel::OnDownload, this);
	m_downloadBtn->Enable(false);
	btnRow->Add(m_downloadBtn, 1, wxALL, 4);

	m_uploadBtn = new wxButton(this, wxID_ANY, "Upload");
	m_uploadBtn->Bind(wxEVT_BUTTON, &NVBrowserPanel::OnUpload, this);
	btnRow->Add(m_uploadBtn, 1, wxALL, 4);

	m_deleteBtn = new wxButton(this, wxID_ANY, "Delete");
	m_deleteBtn->Bind(wxEVT_BUTTON, &NVBrowserPanel::OnDelete, this);
	m_deleteBtn->Enable(false);
	btnRow->Add(m_deleteBtn, 1, wxALL, 4);

	auto *mkdirBtn = new wxButton(this, wxID_ANY, "New Folder");
	mkdirBtn->Bind(wxEVT_BUTTON, &NVBrowserPanel::OnNewFolder, this);
	btnRow->Add(mkdirBtn, 1, wxALL, 4);

	m_propertiesBtn = new wxButton(this, wxID_ANY, "Properties");
	m_propertiesBtn->Bind(wxEVT_BUTTON, &NVBrowserPanel::OnProperties, this);
	m_propertiesBtn->Enable(false);
	btnRow->Add(m_propertiesBtn, 1, wxALL, 4);

	mainSizer->Add(btnRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 4);

	/* --- Status bar --- */
	m_statusText = new wxStaticText(this, wxID_ANY, "");
	mainSizer->Add(m_statusText, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

	SetSizer(mainSizer);
}

int NVBrowserPanel::RunEfsCommand(const wxString &subcmd,
				  const wxArrayString &extraArgs,
				  wxArrayString *output)
{
	auto *runner = m_frame->GetProcessRunner();
	wxString qfenix = ProcessRunner::FindQfenixBinary();

	/* Build command: qfenix <subcmd> [-S diagPort] <extraArgs...> */
	wxString cmd = qfenix + " " + subcmd;

	wxString diagPort = m_frame->GetHomePanel()->GetDiagPort();
	if (!diagPort.IsEmpty())
		cmd += " -S " + diagPort;

	for (const auto &arg : extraArgs)
		cmd += " " + arg;

	wxArrayString out, err;

	if (runner->IsAuthenticated()) {
		int rc = runner->RunSudoSync(cmd, &out, &err);
		if (output)
			*output = out;
		return rc;
	}

	long rc = wxExecute(cmd, out, err, wxEXEC_SYNC);
	if (output)
		*output = out;
	return (int)rc;
}

void NVBrowserPanel::RefreshListing()
{
	wxString diagPort = m_frame->GetHomePanel()->GetDiagPort();
	if (diagPort.IsEmpty()) {
		m_statusText->SetLabel("No DIAG port detected. "
				       "Set a DIAG port on the Home tab.");
		return;
	}

	m_statusText->SetLabel("Loading...");
	wxBusyCursor wait;

	wxArrayString output;
	wxArrayString args;
	args.Add(m_currentPath);

	int rc = RunEfsCommand("efsls", args, &output);

	if (rc != 0) {
		wxString errMsg;
		for (const auto &line : output)
			errMsg += line + "\n";
		m_statusText->SetLabel("Error listing " + m_currentPath);
		if (!errMsg.IsEmpty())
			wxMessageBox("efsls failed:\n" + errMsg, "QFenix",
				     wxOK | wxICON_ERROR);
		return;
	}

	ParseEfsListing(output);
	m_pathBar->SetValue(m_currentPath);
	m_statusText->SetLabel(wxString::Format(
		"%zu entries in %s", m_entries.size(), m_currentPath));
}

void NVBrowserPanel::ParseEfsListing(const wxArrayString &output)
{
	m_entries.clear();

	for (const auto &line : output) {
		wxString trimmed = line.Strip(wxString::both);

		/* Skip header and separator lines */
		if (trimmed.IsEmpty() || trimmed.StartsWith("Type") ||
		    trimmed.StartsWith("----"))
			continue;

		/* Format: "%-4s %8d  %04o  %s" */
		wxStringTokenizer tok(trimmed);
		if (tok.CountTokens() < 4)
			continue;

		EfsEntry entry;
		entry.type = tok.GetNextToken();

		long sz;
		tok.GetNextToken().ToLong(&sz);
		entry.size = (int)sz;

		long md;
		tok.GetNextToken().ToLong(&md, 8); /* octal */
		entry.mode = (int)md;

		/* Name is the rest (may contain spaces) */
		entry.name = tok.GetString().Strip(wxString::leading);

		m_entries.push_back(entry);
	}

	PopulateListCtrl();
}

void NVBrowserPanel::PopulateListCtrl()
{
	m_fileList->DeleteAllItems();

	for (size_t i = 0; i < m_entries.size(); i++) {
		const auto &e = m_entries[i];
		long row = m_fileList->InsertItem(i, e.type);
		m_fileList->SetItem(row, 1, wxString::Format("%d", e.size));
		m_fileList->SetItem(row, 2, wxString::Format("%04o", e.mode));
		m_fileList->SetItem(row, 3, e.name);
	}

	UpdateButtonState();
}

void NVBrowserPanel::UpdateButtonState()
{
	long sel = m_fileList->GetNextItem(-1, wxLIST_NEXT_ALL,
					   wxLIST_STATE_SELECTED);
	bool hasSel = (sel >= 0 && sel < (long)m_entries.size());
	bool isFile = hasSel && (m_entries[sel].type != "dir");

	m_downloadBtn->Enable(isFile);
	m_deleteBtn->Enable(hasSel);
	m_propertiesBtn->Enable(hasSel);
}

void NVBrowserPanel::OnRefresh(wxCommandEvent &event)
{
	RefreshListing();
}

void NVBrowserPanel::OnUp(wxCommandEvent &event)
{
	if (m_currentPath == "/")
		return;

	/* Strip trailing slash, then find last slash */
	wxString path = m_currentPath;
	if (path.EndsWith("/") && path.length() > 1)
		path = path.Left(path.length() - 1);

	int pos = path.Find('/', true); /* reverse find */
	if (pos == wxNOT_FOUND || pos == 0)
		m_currentPath = "/";
	else
		m_currentPath = path.Left(pos + 1);

	RefreshListing();
}

void NVBrowserPanel::OnItemActivated(wxListEvent &event)
{
	long sel = event.GetIndex();
	if (sel < 0 || sel >= (long)m_entries.size())
		return;

	const auto &entry = m_entries[sel];
	if (entry.type == "dir") {
		if (m_currentPath.EndsWith("/"))
			m_currentPath += entry.name + "/";
		else
			m_currentPath += "/" + entry.name + "/";
		RefreshListing();
	}
}

void NVBrowserPanel::OnItemSelected(wxListEvent &event)
{
	UpdateButtonState();
}

void NVBrowserPanel::OnItemDeselected(wxListEvent &event)
{
	UpdateButtonState();
}

void NVBrowserPanel::OnDownload(wxCommandEvent &event)
{
	long sel = m_fileList->GetNextItem(-1, wxLIST_NEXT_ALL,
					   wxLIST_STATE_SELECTED);
	if (sel < 0 || sel >= (long)m_entries.size())
		return;

	const auto &entry = m_entries[sel];
	if (entry.type == "dir")
		return;

	wxString remotePath = m_currentPath + entry.name;

	wxFileDialog dlg(this, "Save EFS file as", "", entry.name,
			 "All files (*.*)|*.*",
			 wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxBusyCursor wait;
	wxArrayString args;
	args.Add(remotePath);
	args.Add("-o");
	args.Add(dlg.GetPath());

	wxArrayString output;
	int rc = RunEfsCommand("efspull", args, &output);

	if (rc == 0) {
		m_statusText->SetLabel("Downloaded: " + entry.name);
	} else {
		wxString errMsg;
		for (const auto &line : output)
			errMsg += line + "\n";
		wxMessageBox("Download failed:\n" + errMsg, "QFenix",
			     wxOK | wxICON_ERROR);
	}
}

void NVBrowserPanel::OnUpload(wxCommandEvent &event)
{
	wxFileDialog dlg(this, "Select file to upload", "", "",
			 "All files (*.*)|*.*",
			 wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxString localPath = dlg.GetPath();
	wxString filename = dlg.GetFilename();
	wxString remotePath = m_currentPath + filename;

	wxBusyCursor wait;
	wxArrayString args;
	args.Add(localPath);
	args.Add(remotePath);

	wxArrayString output;
	int rc = RunEfsCommand("efspush", args, &output);

	if (rc == 0) {
		m_statusText->SetLabel("Uploaded: " + filename);
		RefreshListing();
	} else {
		wxString errMsg;
		for (const auto &line : output)
			errMsg += line + "\n";
		wxMessageBox("Upload failed:\n" + errMsg, "QFenix",
			     wxOK | wxICON_ERROR);
	}
}

void NVBrowserPanel::OnDelete(wxCommandEvent &event)
{
	long sel = m_fileList->GetNextItem(-1, wxLIST_NEXT_ALL,
					   wxLIST_STATE_SELECTED);
	if (sel < 0 || sel >= (long)m_entries.size())
		return;

	const auto &entry = m_entries[sel];
	wxString remotePath = m_currentPath + entry.name;

	int confirm = wxMessageBox(
		wxString::Format("Delete '%s'?\n\nThis cannot be undone.",
				 remotePath),
		"QFenix — Delete",
		wxYES_NO | wxICON_EXCLAMATION);
	if (confirm != wxYES)
		return;

	wxBusyCursor wait;
	wxArrayString args;
	if (entry.type == "dir")
		args.Add("-r");
	args.Add(remotePath);

	wxArrayString output;
	int rc = RunEfsCommand("efsrm", args, &output);

	if (rc == 0) {
		m_statusText->SetLabel("Deleted: " + entry.name);
		RefreshListing();
	} else {
		wxString errMsg;
		for (const auto &line : output)
			errMsg += line + "\n";
		wxMessageBox("Delete failed:\n" + errMsg, "QFenix",
			     wxOK | wxICON_ERROR);
	}
}

void NVBrowserPanel::OnNewFolder(wxCommandEvent &event)
{
	wxTextEntryDialog dlg(this, "Folder name:", "New Folder");
	if (dlg.ShowModal() != wxID_OK || dlg.GetValue().IsEmpty())
		return;

	wxString remotePath = m_currentPath + dlg.GetValue();

	wxBusyCursor wait;
	wxArrayString args;
	args.Add(remotePath);

	wxArrayString output;
	int rc = RunEfsCommand("efsmkdir", args, &output);

	if (rc == 0) {
		m_statusText->SetLabel("Created: " + dlg.GetValue());
		RefreshListing();
	} else {
		wxString errMsg;
		for (const auto &line : output)
			errMsg += line + "\n";
		wxMessageBox("mkdir failed:\n" + errMsg, "QFenix",
			     wxOK | wxICON_ERROR);
	}
}

void NVBrowserPanel::OnProperties(wxCommandEvent &event)
{
	long sel = m_fileList->GetNextItem(-1, wxLIST_NEXT_ALL,
					   wxLIST_STATE_SELECTED);
	if (sel < 0 || sel >= (long)m_entries.size())
		return;

	const auto &entry = m_entries[sel];
	wxString remotePath = m_currentPath + entry.name;

	wxBusyCursor wait;
	wxArrayString args;
	args.Add(remotePath);

	wxArrayString output;
	int rc = RunEfsCommand("efsstat", args, &output);

	wxString info;
	if (rc == 0) {
		for (const auto &line : output)
			info += line + "\n";
	} else {
		info = "Failed to get properties for " + remotePath;
	}

	wxDialog dlg(this, wxID_ANY, "Properties: " + entry.name,
		     wxDefaultPosition, wxSize(500, 350));
	auto *sizer = new wxBoxSizer(wxVERTICAL);
	auto *text = new wxTextCtrl(&dlg, wxID_ANY, info,
				    wxDefaultPosition, wxDefaultSize,
				    wxTE_MULTILINE | wxTE_READONLY |
				    wxTE_DONTWRAP);
	text->SetFont(wxFont(12, wxFONTFAMILY_TELETYPE,
			     wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
	sizer->Add(text, 1, wxEXPAND | wxALL, 8);

	auto *closeBtn = new wxButton(&dlg, wxID_OK, "Close");
	sizer->Add(closeBtn, 0, wxALIGN_RIGHT | wxALL, 8);

	dlg.SetSizer(sizer);
	dlg.ShowModal();
}
