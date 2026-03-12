#include "OpsPanel.h"
#include "MainFrame.h"
#include "HomePanel.h"
#include <wx/textdlg.h>
#include <wx/filedlg.h>
#include <wx/filename.h>
#include <wx/tokenzr.h>

/* Helper to create a labeled section with buttons */
static wxStaticBoxSizer *MakeGroup(wxWindow *parent, const wxString &label)
{
	return new wxStaticBoxSizer(wxVERTICAL, parent, label);
}

/* Helper to add a button to a row */
#define ADD_BTN(row, scroll, label, handler) \
	do { \
		auto *btn = new wxButton(scroll, wxID_ANY, label); \
		btn->Bind(wxEVT_BUTTON, &OpsPanel::handler, this); \
		row->Add(btn, 1, wxALL, 4); \
		m_buttons.push_back(btn); \
	} while (0)

OpsPanel::OpsPanel(wxWindow *parent, MainFrame *frame)
	: wxPanel(parent), m_frame(frame)
{
	auto *scroll = new wxScrolledWindow(this, wxID_ANY);
	scroll->SetScrollRate(0, 10);

	auto *mainSizer = new wxBoxSizer(wxVERTICAL);

	/* --- Firmware Flashing --- */
	auto *flashBox = MakeGroup(scroll, "Firmware Flashing");
	auto *flashRow = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(flashRow, scroll, "Flash Firmware", OnFlash);
	ADD_BTN(flashRow, scroll, "Flash + Erase All", OnFlashErase);
	flashBox->Add(flashRow, 0, wxEXPAND);
	mainSizer->Add(flashBox, 0, wxEXPAND | wxALL, 6);

	/* --- EDL Partition Ops --- */
	auto *partBox = MakeGroup(scroll, "EDL Partition Operations");

	auto *partRow1 = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(partRow1, scroll, "View Partition Table", OnPrintGPT);
	ADD_BTN(partRow1, scroll, "Storage Info", OnStorageInfo);
	ADD_BTN(partRow1, scroll, "Read Partition", OnReadPartition);
	ADD_BTN(partRow1, scroll, "Read All", OnReadAll);
	partBox->Add(partRow1, 0, wxEXPAND);

	auto *partRow2 = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(partRow2, scroll, "Erase Partition", OnErasePartition);
	ADD_BTN(partRow2, scroll, "Erase All", OnEraseAll);
	ADD_BTN(partRow2, scroll, "Get Slot", OnGetSlot);
	ADD_BTN(partRow2, scroll, "Set Slot A", OnSetSlotA);
	partBox->Add(partRow2, 0, wxEXPAND);

	auto *partRow3 = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(partRow3, scroll, "Set Slot B", OnSetSlotB);
	ADD_BTN(partRow3, scroll, "Device Reset", OnDeviceReset);
	partBox->Add(partRow3, 0, wxEXPAND);

	mainSizer->Add(partBox, 0, wxEXPAND | wxALL, 6);

	/* --- EFS Backup & Restore --- */
	auto *efsBox = MakeGroup(scroll, "EFS Backup && Restore");

	auto *efsRow1 = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(efsRow1, scroll, "XQCN Backup", OnXQCNBackup);
	ADD_BTN(efsRow1, scroll, "XQCN Restore", OnXQCNRestore);
	ADD_BTN(efsRow1, scroll, "TAR Backup", OnEFSBackupTar);
	ADD_BTN(efsRow1, scroll, "TAR Restore", OnEFSRestoreTar);
	efsBox->Add(efsRow1, 0, wxEXPAND);

	mainSizer->Add(efsBox, 0, wxEXPAND | wxALL, 6);

	/* --- DIAG --- */
	auto *diagBox = MakeGroup(scroll, "DIAG Operations");
	auto *diagRow = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(diagRow, scroll, "DIAG to EDL", OnDiag2EDL);
	ADD_BTN(diagRow, scroll, "NV Read", OnNVRead);
	ADD_BTN(diagRow, scroll, "NV Write", OnNVWrite);
	diagBox->Add(diagRow, 0, wxEXPAND);
	mainSizer->Add(diagBox, 0, wxEXPAND | wxALL, 6);

	/* --- AT Commands & SMS --- */
	auto *atBox = MakeGroup(scroll, "AT Commands && SMS");

	auto *atRow1 = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(atRow1, scroll, "AT Console", OnATConsole);
	ADD_BTN(atRow1, scroll, "AT Command", OnATCommand);
	ADD_BTN(atRow1, scroll, "Send SMS", OnSMSSend);
	ADD_BTN(atRow1, scroll, "Read SMS", OnSMSRead);
	atBox->Add(atRow1, 0, wxEXPAND);

	auto *atRow2 = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(atRow2, scroll, "Delete SMS", OnSMSDelete);
	ADD_BTN(atRow2, scroll, "SMS Status", OnSMSStatus);
	ADD_BTN(atRow2, scroll, "USSD", OnUSSD);
	atBox->Add(atRow2, 0, wxEXPAND);

	mainSizer->Add(atBox, 0, wxEXPAND | wxALL, 6);

	/* --- Utilities --- */
	auto *utilBox = MakeGroup(scroll, "Utilities");
	auto *utilRow = new wxBoxSizer(wxHORIZONTAL);
	ADD_BTN(utilRow, scroll, "List Devices", OnDeviceList);
	ADD_BTN(utilRow, scroll, "XQCN to TAR", OnXQCN2TAR);
	ADD_BTN(utilRow, scroll, "TAR to XQCN", OnTAR2XQCN);
	utilBox->Add(utilRow, 0, wxEXPAND);
	mainSizer->Add(utilBox, 0, wxEXPAND | wxALL, 6);

	scroll->SetSizer(mainSizer);

	auto *outerSizer = new wxBoxSizer(wxVERTICAL);
	outerSizer->Add(scroll, 1, wxEXPAND);
	SetSizer(outerSizer);
}

#undef ADD_BTN

void OpsPanel::SetRunning(bool running)
{
	for (auto *btn : m_buttons)
		btn->Enable(!running);
}

wxArrayString OpsPanel::BuildArgs(const wxString &subcommand,
				  const wxArrayString &extraArgs)
{
	wxArrayString args;
	auto *home = m_frame->GetHomePanel();

	args.Add(subcommand);

	/* Add -S serial if EDL device selected */
	wxString serial = home->GetEDLSerial();
	if (!serial.IsEmpty()) {
		args.Add("-S");
		args.Add(serial);
	}

	/* Add -s storage if not default */
	wxString storage = home->GetStorageType();
	if (!storage.IsEmpty()) {
		args.Add("-s");
		args.Add(storage);
	}

	/* Append operation-specific args */
	for (const auto &arg : extraArgs)
		args.Add(arg);

	return args;
}

/* ================================================================
 * Firmware Flashing
 * ================================================================ */

void OpsPanel::OnFlash(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString fwDir = home->GetFirmwareDir();
	if (fwDir.IsEmpty()) {
		wxMessageBox("Set a firmware directory on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	/* -F auto-finds programmer; don't also pass -L */
	wxArrayString extra;
	extra.Add("-F");
	extra.Add(fwDir);

	auto args = BuildArgs("flash", extra);
	m_frame->RunOperation("Flash Firmware", args);
}

void OpsPanel::OnFlashErase(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString fwDir = home->GetFirmwareDir();
	if (fwDir.IsEmpty()) {
		wxMessageBox("Set a firmware directory on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	int confirm = wxMessageBox(
		"This will ERASE ALL partitions before flashing.\n\n"
		"It is strongly recommended to do an XQCN backup\n"
		"and/or Read All backup first.\n\n"
		"This is destructive and cannot be undone. Continue?",
		"QFenix — Erase All + Flash",
		wxYES_NO | wxICON_EXCLAMATION);
	if (confirm != wxYES)
		return;

	/* -F auto-finds programmer; don't also pass -L */
	wxArrayString extra;
	extra.Add("-e");
	extra.Add("-F");
	extra.Add(fwDir);

	auto args = BuildArgs("flash", extra);
	m_frame->RunOperation("Flash + Erase All", args);
}

/* ================================================================
 * EDL Partition Operations
 * ================================================================ */

void OpsPanel::OnPrintGPT(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	auto args = BuildArgs("printgpt", {programmer});
	m_frame->RunOperation("View Partition Table", args);
}

void OpsPanel::OnStorageInfo(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	auto args = BuildArgs("storageinfo", {programmer});
	m_frame->RunOperation("Storage Info", args);
}

void OpsPanel::OnReadPartition(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxTextEntryDialog dlg(this,
		"Enter partition label(s) to read (space-separated):",
		"Read Partition");
	if (dlg.ShowModal() != wxID_OK || dlg.GetValue().IsEmpty())
		return;

	wxArrayString extra;
	extra.Add(programmer);

	/* Split labels by space and add each */
	wxStringTokenizer tok(dlg.GetValue());
	while (tok.HasMoreTokens())
		extra.Add(tok.GetNextToken());

	auto args = BuildArgs("read", extra);
	m_frame->RunOperation("Read Partition", args);
}

void OpsPanel::OnReadAll(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	auto args = BuildArgs("readall", {programmer});
	m_frame->RunOperation("Read All Partitions", args);
}

void OpsPanel::OnErasePartition(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxTextEntryDialog dlg(this,
		"Enter partition label(s) to erase (space-separated):",
		"Erase Partition");
	if (dlg.ShowModal() != wxID_OK || dlg.GetValue().IsEmpty())
		return;

	wxString labels = dlg.GetValue();
	int confirm = wxMessageBox(
		wxString::Format(
			"This will ERASE partition(s): %s\n\n"
			"This is destructive and cannot be undone.\n\n"
			"It is recommended to do a backup first. Continue?",
			labels),
		"QFenix — Erase Partition",
		wxYES_NO | wxICON_EXCLAMATION);
	if (confirm != wxYES)
		return;

	wxArrayString extra;
	extra.Add(programmer);

	wxStringTokenizer tok(labels);
	while (tok.HasMoreTokens())
		extra.Add(tok.GetNextToken());

	auto args = BuildArgs("erase", extra);
	m_frame->RunOperation("Erase Partition", args);
}

void OpsPanel::OnEraseAll(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	int confirm = wxMessageBox(
		"This will ERASE ALL partitions on the device.\n\n"
		"It is strongly recommended to do an XQCN backup\n"
		"and/or Read All backup first.\n\n"
		"This is destructive and cannot be undone. Continue?",
		"QFenix — Erase All",
		wxYES_NO | wxICON_EXCLAMATION);
	if (confirm != wxYES)
		return;

	auto args = BuildArgs("eraseall", {programmer});
	m_frame->RunOperation("Erase All Partitions", args);
}

void OpsPanel::OnGetSlot(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	auto args = BuildArgs("getslot", {programmer});
	m_frame->RunOperation("Get Active Slot", args);
}

void OpsPanel::OnSetSlotA(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxArrayString extra;
	extra.Add(programmer);
	extra.Add("a");
	auto args = BuildArgs("setslot", extra);
	m_frame->RunOperation("Set Slot A", args);
}

void OpsPanel::OnSetSlotB(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxArrayString extra;
	extra.Add(programmer);
	extra.Add("b");
	auto args = BuildArgs("setslot", extra);
	m_frame->RunOperation("Set Slot B", args);
}

void OpsPanel::OnDeviceReset(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	auto args = BuildArgs("reset", {programmer});
	m_frame->RunOperation("Device Reset", args);
}

/* ================================================================
 * EFS Backup & Restore
 * ================================================================ */

void OpsPanel::OnXQCNBackup(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString workDir = home->GetWorkingDir();
	wxString outFile = workDir.IsEmpty()
		? "backup.xqcn"
		: workDir + wxFileName::GetPathSeparator() + "backup.xqcn";

	wxArrayString extra;
	wxString diagPort = home->GetDiagPort();
	if (!diagPort.IsEmpty()) {
		extra.Add("-S");
		extra.Add(diagPort);
	}
	extra.Add("-o");
	extra.Add(outFile);

	wxArrayString args;
	args.Add("efsbackup");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("XQCN Backup", args);
}

void OpsPanel::OnXQCNRestore(wxCommandEvent &event)
{
	wxFileDialog dlg(this, "Select XQCN file", "", "",
			 "XQCN files (*.xqcn)|*.xqcn|All files (*.*)|*.*",
			 wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxArrayString extra;
	wxString diagPort = m_frame->GetHomePanel()->GetDiagPort();
	if (!diagPort.IsEmpty()) {
		extra.Add("-S");
		extra.Add(diagPort);
	}
	extra.Add(dlg.GetPath());

	wxArrayString args;
	args.Add("efsrestore");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("XQCN Restore", args);
}

void OpsPanel::OnEFSBackupTar(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString workDir = home->GetWorkingDir();
	wxString outFile = workDir.IsEmpty()
		? "efs_backup.tar"
		: workDir + wxFileName::GetPathSeparator() + "efs_backup.tar";

	wxArrayString extra;
	wxString diagPort = home->GetDiagPort();
	if (!diagPort.IsEmpty()) {
		extra.Add("-S");
		extra.Add(diagPort);
	}
	extra.Add("-t");
	extra.Add("-o");
	extra.Add(outFile);

	wxArrayString args;
	args.Add("efsbackup");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("EFS Backup (TAR)", args);
}

void OpsPanel::OnEFSRestoreTar(wxCommandEvent &event)
{
	wxFileDialog dlg(this, "Select TAR file", "", "",
			 "TAR files (*.tar)|*.tar|All files (*.*)|*.*",
			 wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxArrayString extra;
	wxString diagPort = m_frame->GetHomePanel()->GetDiagPort();
	if (!diagPort.IsEmpty()) {
		extra.Add("-S");
		extra.Add(diagPort);
	}
	extra.Add(dlg.GetPath());

	wxArrayString args;
	args.Add("efsrestore");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("TAR Restore", args);
}

/* ================================================================
 * DIAG Operations
 * ================================================================ */

void OpsPanel::OnDiag2EDL(wxCommandEvent &event)
{
	wxArrayString extra;
	wxString diagPort = m_frame->GetHomePanel()->GetDiagPort();
	if (!diagPort.IsEmpty()) {
		extra.Add("-S");
		extra.Add(diagPort);
	}

	wxArrayString args;
	args.Add("diag2edl");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("DIAG to EDL", args);
}

void OpsPanel::OnNVRead(wxCommandEvent &event)
{
	wxTextEntryDialog dlg(this, "Enter NV item ID (decimal or 0x hex):",
			      "NV Read");
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxArrayString extra;
	wxString diagPort = m_frame->GetHomePanel()->GetDiagPort();
	if (!diagPort.IsEmpty()) {
		extra.Add("-S");
		extra.Add(diagPort);
	}
	extra.Add(dlg.GetValue());

	wxArrayString args;
	args.Add("nvread");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("NV Read " + dlg.GetValue(), args);
}

void OpsPanel::OnNVWrite(wxCommandEvent &event)
{
	wxTextEntryDialog idDlg(this,
		"Enter NV item ID (decimal or 0x hex):",
		"NV Write — Item ID");
	if (idDlg.ShowModal() != wxID_OK || idDlg.GetValue().IsEmpty())
		return;

	wxTextEntryDialog dataDlg(this,
		"Enter hex data (e.g. 01020304FF):",
		"NV Write — Data");
	if (dataDlg.ShowModal() != wxID_OK || dataDlg.GetValue().IsEmpty())
		return;

	wxArrayString extra;
	wxString diagPort = m_frame->GetHomePanel()->GetDiagPort();
	if (!diagPort.IsEmpty()) {
		extra.Add("-S");
		extra.Add(diagPort);
	}
	extra.Add(idDlg.GetValue());
	extra.Add(dataDlg.GetValue());

	wxArrayString args;
	args.Add("nvwrite");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("NV Write " + idDlg.GetValue(), args);
}

/* ================================================================
 * AT Commands & SMS
 * ================================================================ */

void OpsPanel::OnATConsole(wxCommandEvent &event)
{
	wxArrayString extra;
	wxString atPort = m_frame->GetHomePanel()->GetATPort();
	if (!atPort.IsEmpty()) {
		extra.Add("-p");
		extra.Add(atPort);
	}

	wxArrayString args;
	args.Add("atconsole");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("AT Console", args);
}

void OpsPanel::OnATCommand(wxCommandEvent &event)
{
	wxTextEntryDialog dlg(this, "Enter AT command (e.g. AT+CIMI):",
			      "AT Command");
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxArrayString extra;
	wxString atPort = m_frame->GetHomePanel()->GetATPort();
	if (!atPort.IsEmpty()) {
		extra.Add("-p");
		extra.Add(atPort);
	}
	extra.Add(dlg.GetValue());

	wxArrayString args;
	args.Add("atcmd");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("AT: " + dlg.GetValue(), args);
}

void OpsPanel::OnSMSSend(wxCommandEvent &event)
{
	wxTextEntryDialog phoneDlg(this, "Phone number:", "Send SMS");
	if (phoneDlg.ShowModal() != wxID_OK)
		return;

	wxTextEntryDialog msgDlg(this, "Message:", "Send SMS");
	if (msgDlg.ShowModal() != wxID_OK)
		return;

	wxArrayString extra;
	wxString atPort = m_frame->GetHomePanel()->GetATPort();
	if (!atPort.IsEmpty()) {
		extra.Add("-p");
		extra.Add(atPort);
	}
	extra.Add(phoneDlg.GetValue());
	extra.Add(msgDlg.GetValue());

	wxArrayString args;
	args.Add("smssend");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("Send SMS", args);
}

void OpsPanel::OnSMSRead(wxCommandEvent &event)
{
	wxArrayString extra;
	wxString atPort = m_frame->GetHomePanel()->GetATPort();
	if (!atPort.IsEmpty()) {
		extra.Add("-p");
		extra.Add(atPort);
	}

	wxArrayString args;
	args.Add("smsread");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("Read SMS", args);
}

void OpsPanel::OnSMSDelete(wxCommandEvent &event)
{
	wxTextEntryDialog dlg(this,
		"Enter SMS index to delete, or 'all' to delete all:",
		"Delete SMS");
	if (dlg.ShowModal() != wxID_OK || dlg.GetValue().IsEmpty())
		return;

	wxArrayString extra;
	wxString atPort = m_frame->GetHomePanel()->GetATPort();
	if (!atPort.IsEmpty()) {
		extra.Add("-p");
		extra.Add(atPort);
	}
	extra.Add(dlg.GetValue());

	wxArrayString args;
	args.Add("smsrm");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("Delete SMS", args);
}

void OpsPanel::OnSMSStatus(wxCommandEvent &event)
{
	wxArrayString extra;
	wxString atPort = m_frame->GetHomePanel()->GetATPort();
	if (!atPort.IsEmpty()) {
		extra.Add("-p");
		extra.Add(atPort);
	}

	wxArrayString args;
	args.Add("smsstatus");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("SMS Status", args);
}

void OpsPanel::OnUSSD(wxCommandEvent &event)
{
	wxTextEntryDialog dlg(this, "Enter USSD code (e.g. *#06#):", "USSD");
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxArrayString extra;
	wxString atPort = m_frame->GetHomePanel()->GetATPort();
	if (!atPort.IsEmpty()) {
		extra.Add("-p");
		extra.Add(atPort);
	}
	extra.Add(dlg.GetValue());

	wxArrayString args;
	args.Add("ussd");
	for (const auto &a : extra)
		args.Add(a);

	m_frame->RunOperation("USSD: " + dlg.GetValue(), args);
}

/* ================================================================
 * Utilities
 * ================================================================ */

void OpsPanel::OnDeviceList(wxCommandEvent &event)
{
	wxArrayString args;
	args.Add("list");
	m_frame->RunOperation("List Devices", args);
}

void OpsPanel::OnXQCN2TAR(wxCommandEvent &event)
{
	wxFileDialog inDlg(this, "Select XQCN file to convert", "", "",
			   "XQCN files (*.xqcn)|*.xqcn|All files (*.*)|*.*",
			   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (inDlg.ShowModal() != wxID_OK)
		return;

	wxString inputPath = inDlg.GetPath();
	wxFileName fn(inputPath);
	wxString outFile = fn.GetPath() + wxFileName::GetPathSeparator() +
			   fn.GetName() + ".tar";

	wxArrayString args;
	args.Add("xqcn2tar");
	args.Add(inputPath);
	args.Add(outFile);

	m_frame->RunOperation("XQCN to TAR", args);
}

void OpsPanel::OnTAR2XQCN(wxCommandEvent &event)
{
	wxFileDialog inDlg(this, "Select TAR file to convert", "", "",
			   "TAR files (*.tar)|*.tar|All files (*.*)|*.*",
			   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (inDlg.ShowModal() != wxID_OK)
		return;

	wxString inputPath = inDlg.GetPath();
	wxFileName fn(inputPath);
	wxString outFile = fn.GetPath() + wxFileName::GetPathSeparator() +
			   fn.GetName() + ".xqcn";

	wxArrayString args;
	args.Add("tar2xqcn");
	args.Add(inputPath);
	args.Add(outFile);

	m_frame->RunOperation("TAR to XQCN", args);
}
