#include "OpsPanel.h"
#include "MainFrame.h"
#include "HomePanel.h"
#include <wx/textdlg.h>
#include <wx/filedlg.h>
#include <wx/filename.h>

/* Helper to create a labeled section with buttons */
static wxStaticBoxSizer *MakeGroup(wxWindow *parent, const wxString &label)
{
	return new wxStaticBoxSizer(wxVERTICAL, parent, label);
}

OpsPanel::OpsPanel(wxWindow *parent, MainFrame *frame)
	: wxPanel(parent), m_frame(frame)
{
	auto *scroll = new wxScrolledWindow(this, wxID_ANY);
	scroll->SetScrollRate(0, 10);

	auto *mainSizer = new wxBoxSizer(wxVERTICAL);

	/* --- Flash --- */
	auto *flashBox = MakeGroup(scroll, "Firmware Flashing");
	auto *flashRow = new wxBoxSizer(wxHORIZONTAL);

	auto *btnFlash = new wxButton(scroll, wxID_ANY, "Flash Firmware");
	btnFlash->Bind(wxEVT_BUTTON, &OpsPanel::OnFlash, this);
	flashRow->Add(btnFlash, 1, wxALL, 4);
	m_buttons.push_back(btnFlash);

	auto *btnFlashErase = new wxButton(scroll, wxID_ANY, "Flash + Erase All");
	btnFlashErase->Bind(wxEVT_BUTTON, &OpsPanel::OnFlashErase, this);
	flashRow->Add(btnFlashErase, 1, wxALL, 4);
	m_buttons.push_back(btnFlashErase);

	flashBox->Add(flashRow, 0, wxEXPAND);
	mainSizer->Add(flashBox, 0, wxEXPAND | wxALL, 6);

	/* --- Backup / Restore --- */
	auto *backupBox = MakeGroup(scroll, "Backup && Restore");
	auto *backupRow = new wxBoxSizer(wxHORIZONTAL);

	auto *btnReadAll = new wxButton(scroll, wxID_ANY, "Read All Partitions");
	btnReadAll->Bind(wxEVT_BUTTON, &OpsPanel::OnReadAll, this);
	backupRow->Add(btnReadAll, 1, wxALL, 4);
	m_buttons.push_back(btnReadAll);

	auto *btnXQCNBackup = new wxButton(scroll, wxID_ANY, "XQCN Backup");
	btnXQCNBackup->Bind(wxEVT_BUTTON, &OpsPanel::OnXQCNBackup, this);
	backupRow->Add(btnXQCNBackup, 1, wxALL, 4);
	m_buttons.push_back(btnXQCNBackup);

	auto *btnXQCNRestore = new wxButton(scroll, wxID_ANY, "XQCN Restore");
	btnXQCNRestore->Bind(wxEVT_BUTTON, &OpsPanel::OnXQCNRestore, this);
	backupRow->Add(btnXQCNRestore, 1, wxALL, 4);
	m_buttons.push_back(btnXQCNRestore);

	backupBox->Add(backupRow, 0, wxEXPAND);

	auto *backupRow2 = new wxBoxSizer(wxHORIZONTAL);

	auto *btnEFSBackup = new wxButton(scroll, wxID_ANY, "EFS Backup (TAR)");
	btnEFSBackup->Bind(wxEVT_BUTTON, &OpsPanel::OnEFSBackupTar, this);
	backupRow2->Add(btnEFSBackup, 1, wxALL, 4);
	m_buttons.push_back(btnEFSBackup);

	auto *btnEFSRestore = new wxButton(scroll, wxID_ANY, "EFS Restore");
	btnEFSRestore->Bind(wxEVT_BUTTON, &OpsPanel::OnEFSRestore, this);
	backupRow2->Add(btnEFSRestore, 1, wxALL, 4);
	m_buttons.push_back(btnEFSRestore);

	backupBox->Add(backupRow2, 0, wxEXPAND);
	mainSizer->Add(backupBox, 0, wxEXPAND | wxALL, 6);

	/* --- Partitions --- */
	auto *partBox = MakeGroup(scroll, "Partition Operations");
	auto *partRow = new wxBoxSizer(wxHORIZONTAL);

	auto *btnGPT = new wxButton(scroll, wxID_ANY, "Print GPT");
	btnGPT->Bind(wxEVT_BUTTON, &OpsPanel::OnPrintGPT, this);
	partRow->Add(btnGPT, 1, wxALL, 4);
	m_buttons.push_back(btnGPT);

	auto *btnStorageInfo = new wxButton(scroll, wxID_ANY, "Storage Info");
	btnStorageInfo->Bind(wxEVT_BUTTON, &OpsPanel::OnStorageInfo, this);
	partRow->Add(btnStorageInfo, 1, wxALL, 4);
	m_buttons.push_back(btnStorageInfo);

	auto *btnGetSlot = new wxButton(scroll, wxID_ANY, "Get Slot");
	btnGetSlot->Bind(wxEVT_BUTTON, &OpsPanel::OnGetSlot, this);
	partRow->Add(btnGetSlot, 1, wxALL, 4);
	m_buttons.push_back(btnGetSlot);

	auto *btnSetSlotA = new wxButton(scroll, wxID_ANY, "Set Slot A");
	btnSetSlotA->Bind(wxEVT_BUTTON, &OpsPanel::OnSetSlotA, this);
	partRow->Add(btnSetSlotA, 1, wxALL, 4);
	m_buttons.push_back(btnSetSlotA);

	auto *btnSetSlotB = new wxButton(scroll, wxID_ANY, "Set Slot B");
	btnSetSlotB->Bind(wxEVT_BUTTON, &OpsPanel::OnSetSlotB, this);
	partRow->Add(btnSetSlotB, 1, wxALL, 4);
	m_buttons.push_back(btnSetSlotB);

	partBox->Add(partRow, 0, wxEXPAND);
	mainSizer->Add(partBox, 0, wxEXPAND | wxALL, 6);

	/* --- DIAG --- */
	auto *diagBox = MakeGroup(scroll, "DIAG Operations");
	auto *diagRow = new wxBoxSizer(wxHORIZONTAL);

	auto *btnDiag2EDL = new wxButton(scroll, wxID_ANY, "DIAG to EDL");
	btnDiag2EDL->Bind(wxEVT_BUTTON, &OpsPanel::OnDiag2EDL, this);
	diagRow->Add(btnDiag2EDL, 1, wxALL, 4);
	m_buttons.push_back(btnDiag2EDL);

	auto *btnNVRead = new wxButton(scroll, wxID_ANY, "NV Read");
	btnNVRead->Bind(wxEVT_BUTTON, &OpsPanel::OnNVRead, this);
	diagRow->Add(btnNVRead, 1, wxALL, 4);
	m_buttons.push_back(btnNVRead);

	auto *btnNVWrite = new wxButton(scroll, wxID_ANY, "NV Write");
	btnNVWrite->Bind(wxEVT_BUTTON, &OpsPanel::OnNVWrite, this);
	diagRow->Add(btnNVWrite, 1, wxALL, 4);
	m_buttons.push_back(btnNVWrite);

	auto *btnReset = new wxButton(scroll, wxID_ANY, "Device Reset");
	btnReset->Bind(wxEVT_BUTTON, &OpsPanel::OnDeviceReset, this);
	diagRow->Add(btnReset, 1, wxALL, 4);
	m_buttons.push_back(btnReset);

	diagBox->Add(diagRow, 0, wxEXPAND);
	mainSizer->Add(diagBox, 0, wxEXPAND | wxALL, 6);

	/* --- AT / SMS --- */
	auto *atBox = MakeGroup(scroll, "AT Commands && SMS");
	auto *atRow = new wxBoxSizer(wxHORIZONTAL);

	auto *btnATConsole = new wxButton(scroll, wxID_ANY, "AT Console");
	btnATConsole->Bind(wxEVT_BUTTON, &OpsPanel::OnATConsole, this);
	atRow->Add(btnATConsole, 1, wxALL, 4);
	m_buttons.push_back(btnATConsole);

	auto *btnATCmd = new wxButton(scroll, wxID_ANY, "AT Command");
	btnATCmd->Bind(wxEVT_BUTTON, &OpsPanel::OnATCommand, this);
	atRow->Add(btnATCmd, 1, wxALL, 4);
	m_buttons.push_back(btnATCmd);

	auto *btnSMSSend = new wxButton(scroll, wxID_ANY, "Send SMS");
	btnSMSSend->Bind(wxEVT_BUTTON, &OpsPanel::OnSMSSend, this);
	atRow->Add(btnSMSSend, 1, wxALL, 4);
	m_buttons.push_back(btnSMSSend);

	auto *btnSMSRead = new wxButton(scroll, wxID_ANY, "Read SMS");
	btnSMSRead->Bind(wxEVT_BUTTON, &OpsPanel::OnSMSRead, this);
	atRow->Add(btnSMSRead, 1, wxALL, 4);
	m_buttons.push_back(btnSMSRead);

	auto *btnUSSD = new wxButton(scroll, wxID_ANY, "USSD");
	btnUSSD->Bind(wxEVT_BUTTON, &OpsPanel::OnUSSD, this);
	atRow->Add(btnUSSD, 1, wxALL, 4);
	m_buttons.push_back(btnUSSD);

	atBox->Add(atRow, 0, wxEXPAND);
	mainSizer->Add(atBox, 0, wxEXPAND | wxALL, 6);

	/* --- Utilities --- */
	auto *utilBox = MakeGroup(scroll, "Utilities");
	auto *utilRow = new wxBoxSizer(wxHORIZONTAL);

	auto *btnList = new wxButton(scroll, wxID_ANY, "List Devices");
	btnList->Bind(wxEVT_BUTTON, &OpsPanel::OnDeviceList, this);
	utilRow->Add(btnList, 1, wxALL, 4);
	m_buttons.push_back(btnList);

	utilBox->Add(utilRow, 0, wxEXPAND);
	mainSizer->Add(utilBox, 0, wxEXPAND | wxALL, 6);

	scroll->SetSizer(mainSizer);

	auto *outerSizer = new wxBoxSizer(wxVERTICAL);
	outerSizer->Add(scroll, 1, wxEXPAND);
	SetSizer(outerSizer);
}

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

	/* Add -s storage if not auto */
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

/* --- Operation Handlers --- */

void OpsPanel::OnFlash(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString fwDir = home->GetFirmwareDir();
	if (fwDir.IsEmpty()) {
		wxMessageBox("Set a firmware directory on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxArrayString extra;
	wxString programmer = home->GetProgrammer();
	if (!programmer.IsEmpty()) {
		extra.Add("-L");
		extra.Add(programmer);
	}
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
		"This will ERASE ALL partitions before flashing. Continue?",
		"QFenix - Erase All", wxYES_NO | wxICON_EXCLAMATION);
	if (confirm != wxYES)
		return;

	wxArrayString extra;
	extra.Add("-e");
	wxString programmer = home->GetProgrammer();
	if (!programmer.IsEmpty()) {
		extra.Add("-L");
		extra.Add(programmer);
	}
	extra.Add("-F");
	extra.Add(fwDir);

	auto args = BuildArgs("flash", extra);
	m_frame->RunOperation("Flash + Erase All", args);
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
	wxFileDialog dlg(this, "Select XQCN or TAR file", "", "",
			 "Backup files (*.xqcn;*.tar)|*.xqcn;*.tar|All files (*.*)|*.*",
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

void OpsPanel::OnEFSRestore(wxCommandEvent &event)
{
	/* Reuse the XQCN restore handler - qfenix auto-detects format */
	OnXQCNRestore(event);
}

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
	m_frame->RunOperation("Print GPT", args);
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
	wxMessageBox("NV Write requires item ID and hex data.\n"
		     "Use AT Console for now, or implement a dedicated dialog.",
		     "QFenix", wxOK | wxICON_INFORMATION);
}

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

void OpsPanel::OnDeviceList(wxCommandEvent &event)
{
	wxArrayString args;
	args.Add("list");
	m_frame->RunOperation("List Devices", args);
}

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
