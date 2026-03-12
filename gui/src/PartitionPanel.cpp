#include "PartitionPanel.h"
#include "MainFrame.h"
#include "HomePanel.h"
#include "ProcessRunner.h"
#include <wx/filedlg.h>
#include <wx/tokenzr.h>
#include <wx/busyinfo.h>

PartitionPanel::PartitionPanel(wxWindow *parent, MainFrame *frame)
	: wxPanel(parent), m_frame(frame)
{
	auto *mainSizer = new wxBoxSizer(wxVERTICAL);

	/* --- Top row: device status + scan button --- */
	auto *topRow = new wxBoxSizer(wxHORIZONTAL);
	m_deviceStatus = new wxStaticText(this, wxID_ANY, "Device: --");
	m_deviceStatus->SetFont(m_deviceStatus->GetFont().Bold());
	topRow->Add(m_deviceStatus, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);

	m_scanBtn = new wxButton(this, wxID_ANY, "Scan Device");
	m_scanBtn->Bind(wxEVT_BUTTON, &PartitionPanel::OnScanDevice, this);
	topRow->Add(m_scanBtn, 0);
	m_allButtons.push_back(m_scanBtn);

	mainSizer->Add(topRow, 0, wxEXPAND | wxALL, 8);

	/* --- Storage info summary --- */
	auto *infoBox = new wxStaticBoxSizer(wxVERTICAL, this, "Storage Info");
	m_storageInfoText = new wxStaticText(infoBox->GetStaticBox(), wxID_ANY,
					     "No scan performed yet.");
	infoBox->Add(m_storageInfoText, 0, wxALL, 4);
	mainSizer->Add(infoBox, 0, wxEXPAND | wxLEFT | wxRIGHT, 8);

	/* --- Partition table (wxListCtrl) --- */
	m_partList = new wxListCtrl(this, wxID_ANY, wxDefaultPosition,
				    wxDefaultSize,
				    wxLC_REPORT | wxLC_SINGLE_SEL);
	/* Set up default columns — will be reconfigured after scan */
	m_partList->InsertColumn(0, "#", wxLIST_FORMAT_LEFT, 40);
	m_partList->InsertColumn(1, "Name", wxLIST_FORMAT_LEFT, 200);
	m_partList->InsertColumn(2, "Start", wxLIST_FORMAT_RIGHT, 120);
	m_partList->InsertColumn(3, "End / Length", wxLIST_FORMAT_RIGHT, 120);
	m_partList->InsertColumn(4, "Size", wxLIST_FORMAT_RIGHT, 100);
	m_partList->InsertColumn(5, "Attrs", wxLIST_FORMAT_LEFT, 80);

	m_partList->Bind(wxEVT_LIST_ITEM_SELECTED,
			 &PartitionPanel::OnPartitionSelected, this);
	m_partList->Bind(wxEVT_LIST_ITEM_DESELECTED,
			 &PartitionPanel::OnPartitionDeselected, this);

	mainSizer->Add(m_partList, 1, wxEXPAND | wxALL, 8);

	/* --- Bottom row: action buttons --- */
	auto *btnRow = new wxBoxSizer(wxHORIZONTAL);

	m_backupBtn = new wxButton(this, wxID_ANY, "Backup");
	m_backupBtn->Bind(wxEVT_BUTTON, &PartitionPanel::OnBackup, this);
	m_backupBtn->Enable(false);
	btnRow->Add(m_backupBtn, 1, wxALL, 4);
	m_allButtons.push_back(m_backupBtn);

	m_replaceBtn = new wxButton(this, wxID_ANY, "Replace");
	m_replaceBtn->Bind(wxEVT_BUTTON, &PartitionPanel::OnReplace, this);
	m_replaceBtn->Enable(false);
	btnRow->Add(m_replaceBtn, 1, wxALL, 4);
	m_allButtons.push_back(m_replaceBtn);

	m_eraseBtn = new wxButton(this, wxID_ANY, "Erase");
	m_eraseBtn->Bind(wxEVT_BUTTON, &PartitionPanel::OnErase, this);
	m_eraseBtn->Enable(false);
	btnRow->Add(m_eraseBtn, 1, wxALL, 4);
	m_allButtons.push_back(m_eraseBtn);

	mainSizer->Add(btnRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 4);

	SetSizer(mainSizer);
}

void PartitionPanel::SetRunning(bool running)
{
	for (auto *btn : m_allButtons)
		btn->Enable(!running);

	/* Re-disable action buttons if no partition selected */
	if (!running) {
		long sel = m_partList->GetNextItem(-1, wxLIST_NEXT_ALL,
						   wxLIST_STATE_SELECTED);
		if (sel < 0) {
			m_backupBtn->Enable(false);
			m_replaceBtn->Enable(false);
			m_eraseBtn->Enable(false);
		}
	}
}

void PartitionPanel::UpdateDeviceStatus()
{
	auto *home = m_frame->GetHomePanel();
	wxString edl = home->GetEDLSerial();
	wxString diag = home->GetDiagPort();

	if (!edl.IsEmpty())
		m_deviceStatus->SetLabel("Device: EDL (" + edl + ")");
	else if (!diag.IsEmpty())
		m_deviceStatus->SetLabel("Device: DIAG (" + diag + ")");
	else
		m_deviceStatus->SetLabel("Device: No modem");
}

wxArrayString PartitionPanel::BuildEDLArgs(const wxString &subcommand,
					   const wxArrayString &extraArgs)
{
	wxArrayString args;
	auto *home = m_frame->GetHomePanel();

	args.Add(subcommand);

	wxString serial = home->GetEDLSerial();
	if (!serial.IsEmpty()) {
		args.Add("-S");
		args.Add(serial);
	}

	wxString storage = home->GetStorageType();
	if (!storage.IsEmpty()) {
		args.Add("-s");
		args.Add(storage);
	}

	for (const auto &arg : extraArgs)
		args.Add(arg);

	return args;
}

void PartitionPanel::OnScanDevice(wxCommandEvent &event)
{
	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	m_storageInfoText->SetLabel("Scanning...");
	wxBusyCursor wait;

	/* Build partinfo command */
	wxString qfenix = ProcessRunner::FindQfenixBinary();
	wxString cmd = qfenix + " partinfo " + programmer;

	wxString serial = home->GetEDLSerial();
	if (!serial.IsEmpty())
		cmd += " -S " + serial;

	wxString storage = home->GetStorageType();
	if (!storage.IsEmpty())
		cmd += " -s " + storage;

	auto *runner = m_frame->GetProcessRunner();
	wxArrayString output;

	if (runner->IsAuthenticated()) {
		runner->RunSudoSync(cmd, &output);
	} else {
		wxArrayString errors;
		wxExecute(cmd, output, errors, wxEXEC_SYNC);
	}

	wxString fullOutput;
	for (const auto &line : output)
		fullOutput += line + "\n";

	ParsePartInfo(fullOutput);
}

void PartitionPanel::ParsePartInfo(const wxString &output)
{
	m_storageInfo = {};
	m_partitions.clear();
	m_partFormat = PART_NONE;

	enum { ST_INIT, ST_STORAGE, ST_NAND_TABLE, ST_GPT_META, ST_GPT_TABLE }
		state = ST_INIT;

	wxStringTokenizer lines(output, "\n");
	while (lines.HasMoreTokens()) {
		wxString line = lines.GetNextToken();
		wxString trimmed = line.Strip(wxString::both);

		if (trimmed.IsEmpty())
			continue;

		/* Storage info section */
		if (trimmed == "Storage Information:") {
			state = ST_STORAGE;
			continue;
		}

		if (state == ST_STORAGE) {
			if (trimmed.StartsWith("Memory type:"))
				m_storageInfo.memType = trimmed.Mid(12).Strip(wxString::both);
			else if (trimmed.StartsWith("Product name:"))
				m_storageInfo.prodName = trimmed.Mid(13).Strip(wxString::both);
			else if (trimmed.StartsWith("Total blocks:"))
				trimmed.Mid(13).Strip(wxString::both).ToULong(&m_storageInfo.totalBlocks);
			else if (trimmed.StartsWith("Block size:")) {
				unsigned long v;
				trimmed.Mid(11).Strip(wxString::both).ToULong(&v);
				m_storageInfo.blockSize = (unsigned int)v;
			} else if (trimmed.StartsWith("Page size:") && state == ST_STORAGE) {
				unsigned long v;
				trimmed.Mid(10).Strip(wxString::both).ToULong(&v);
				m_storageInfo.pageSize = (unsigned int)v;
			} else if (trimmed.StartsWith("Sector size:")) {
				unsigned long v;
				trimmed.Mid(12).Strip(wxString::both).ToULong(&v);
				m_storageInfo.sectorSize = (unsigned int)v;
			} else if (trimmed.StartsWith("Physical parts:")) {
				unsigned long v;
				trimmed.Mid(15).Strip(wxString::both).ToULong(&v);
				m_storageInfo.numPhysical = (unsigned int)v;
			}
			/* Fall through to section detection below */
		}

		/* NAND partition table */
		if (trimmed.StartsWith("=== NAND Partition Table")) {
			m_partFormat = PART_NAND;
			state = ST_NAND_TABLE;
			continue;
		}

		/* GPT partition table */
		if (trimmed.StartsWith("=== Physical Partition")) {
			m_partFormat = PART_GPT;
			state = ST_GPT_META;
			continue;
		}

		/* Skip headers and separators */
		if (trimmed.StartsWith("#") || trimmed.StartsWith("---") ||
		    trimmed.StartsWith("Note:") ||
		    trimmed.StartsWith("Page size:") ||
		    trimmed.StartsWith("Partitions:"))
			continue;

		/* NAND data rows: "0    sbl1        0       8  0x00" */
		if (state == ST_NAND_TABLE) {
			if (!trimmed[0].IsAscii() || !wxIsdigit(trimmed[0]))
				continue;

			wxStringTokenizer tok(trimmed);
			if (tok.CountTokens() >= 4) {
				PartitionEntry pe;
				long idx;
				tok.GetNextToken().ToLong(&idx);
				pe.index = (int)idx;
				pe.name = tok.GetNextToken();
				pe.startStr = tok.GetNextToken();
				pe.sizeStr = tok.GetNextToken();
				if (tok.HasMoreTokens())
					pe.attrs = tok.GetNextToken();
				m_partitions.push_back(pe);
			}
			continue;
		}

		/* GPT metadata lines (Disk GUID:, First usable LBA:, etc.) */
		if (state == ST_GPT_META) {
			/* Data rows start with a digit */
			if (wxIsdigit(trimmed[0]))
				state = ST_GPT_TABLE;
			else
				continue;
		}

		/* GPT data rows: "0  sbl1  2048  3071  512.0K  guid  0x00" */
		if (state == ST_GPT_TABLE) {
			if (!wxIsdigit(trimmed[0]))
				continue;

			wxStringTokenizer tok(trimmed);
			if (tok.CountTokens() >= 6) {
				PartitionEntry pe;
				long idx;
				tok.GetNextToken().ToLong(&idx);
				pe.index = (int)idx;
				pe.name = tok.GetNextToken();
				pe.startStr = tok.GetNextToken();
				pe.endStr = tok.GetNextToken();
				pe.sizeStr = tok.GetNextToken();
				pe.typeGuid = tok.GetNextToken();
				if (tok.HasMoreTokens())
					pe.attrs = tok.GetNextToken();
				m_partitions.push_back(pe);
			}
			continue;
		}
	}

	PopulateListCtrl();
	UpdateStorageInfoDisplay();
}

void PartitionPanel::PopulateListCtrl()
{
	m_partList->ClearAll();

	if (m_partFormat == PART_NAND) {
		m_partList->InsertColumn(0, "#", wxLIST_FORMAT_LEFT, 40);
		m_partList->InsertColumn(1, "Name", wxLIST_FORMAT_LEFT, 200);
		m_partList->InsertColumn(2, "Offset (blk)", wxLIST_FORMAT_RIGHT, 120);
		m_partList->InsertColumn(3, "Length (blk)", wxLIST_FORMAT_RIGHT, 120);
		m_partList->InsertColumn(4, "Attr", wxLIST_FORMAT_LEFT, 80);
	} else if (m_partFormat == PART_GPT) {
		m_partList->InsertColumn(0, "#", wxLIST_FORMAT_LEFT, 40);
		m_partList->InsertColumn(1, "Name", wxLIST_FORMAT_LEFT, 200);
		m_partList->InsertColumn(2, "Start LBA", wxLIST_FORMAT_RIGHT, 110);
		m_partList->InsertColumn(3, "End LBA", wxLIST_FORMAT_RIGHT, 110);
		m_partList->InsertColumn(4, "Size", wxLIST_FORMAT_RIGHT, 90);
		m_partList->InsertColumn(5, "Attrs", wxLIST_FORMAT_LEFT, 80);
	} else {
		m_partList->InsertColumn(0, "#", wxLIST_FORMAT_LEFT, 40);
		m_partList->InsertColumn(1, "Name", wxLIST_FORMAT_LEFT, 200);
		m_partList->InsertColumn(2, "Start", wxLIST_FORMAT_RIGHT, 120);
		m_partList->InsertColumn(3, "End / Length", wxLIST_FORMAT_RIGHT, 120);
		m_partList->InsertColumn(4, "Size", wxLIST_FORMAT_RIGHT, 100);
		m_partList->InsertColumn(5, "Attrs", wxLIST_FORMAT_LEFT, 80);
	}

	for (size_t i = 0; i < m_partitions.size(); i++) {
		const auto &pe = m_partitions[i];
		long row = m_partList->InsertItem(i, wxString::Format("%d", pe.index));

		m_partList->SetItem(row, 1, pe.name);
		m_partList->SetItem(row, 2, pe.startStr);

		if (m_partFormat == PART_NAND) {
			m_partList->SetItem(row, 3, pe.sizeStr);
			m_partList->SetItem(row, 4, pe.attrs);
		} else {
			m_partList->SetItem(row, 3, pe.endStr);
			m_partList->SetItem(row, 4, pe.sizeStr);
			if (m_partList->GetColumnCount() > 5)
				m_partList->SetItem(row, 5, pe.attrs);
		}
	}

	/* Disable action buttons — no selection yet */
	m_backupBtn->Enable(false);
	m_replaceBtn->Enable(false);
	m_eraseBtn->Enable(false);
}

void PartitionPanel::UpdateStorageInfoDisplay()
{
	if (m_partFormat == PART_NONE) {
		m_storageInfoText->SetLabel("No scan performed yet.");
		return;
	}

	wxString info;
	if (!m_storageInfo.memType.IsEmpty())
		info += "Type: " + m_storageInfo.memType;
	if (!m_storageInfo.prodName.IsEmpty()) {
		if (!info.IsEmpty()) info += "  |  ";
		info += "Product: " + m_storageInfo.prodName;
	}
	if (m_storageInfo.totalBlocks) {
		if (!info.IsEmpty()) info += "  |  ";
		info += wxString::Format("Blocks: %lu", m_storageInfo.totalBlocks);
	}
	if (m_storageInfo.blockSize) {
		if (!info.IsEmpty()) info += "  |  ";
		info += wxString::Format("Block: %u", m_storageInfo.blockSize);
	}
	if (m_storageInfo.pageSize) {
		if (!info.IsEmpty()) info += "  |  ";
		info += wxString::Format("Page: %u", m_storageInfo.pageSize);
	}
	if (m_storageInfo.numPhysical) {
		if (!info.IsEmpty()) info += "  |  ";
		info += wxString::Format("Physical: %u", m_storageInfo.numPhysical);
	}

	if (info.IsEmpty())
		info = "Storage info not available";

	info += wxString::Format("\nPartitions: %zu", m_partitions.size());

	m_storageInfoText->SetLabel(info);
	m_storageInfoText->GetParent()->Layout();
}

void PartitionPanel::OnPartitionSelected(wxListEvent &event)
{
	m_backupBtn->Enable(true);
	m_replaceBtn->Enable(true);
	m_eraseBtn->Enable(true);
}

void PartitionPanel::OnPartitionDeselected(wxListEvent &event)
{
	m_backupBtn->Enable(false);
	m_replaceBtn->Enable(false);
	m_eraseBtn->Enable(false);
}

void PartitionPanel::OnBackup(wxCommandEvent &event)
{
	long sel = m_partList->GetNextItem(-1, wxLIST_NEXT_ALL,
					   wxLIST_STATE_SELECTED);
	if (sel < 0 || sel >= (long)m_partitions.size())
		return;

	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxString label = m_partitions[sel].name;
	wxFileDialog dlg(this, "Save partition backup as", "", label + ".bin",
			 "Binary files (*.bin)|*.bin|All files (*.*)|*.*",
			 wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
	if (dlg.ShowModal() != wxID_OK)
		return;

	wxArrayString extra;
	extra.Add(programmer);
	extra.Add(label);
	extra.Add("-o");
	extra.Add(dlg.GetPath());

	auto args = BuildEDLArgs("read", extra);
	m_frame->RunOperation("Read: " + label, args);
}

void PartitionPanel::OnReplace(wxCommandEvent &event)
{
	long sel = m_partList->GetNextItem(-1, wxLIST_NEXT_ALL,
					   wxLIST_STATE_SELECTED);
	if (sel < 0 || sel >= (long)m_partitions.size())
		return;

	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxString label = m_partitions[sel].name;

	wxFileDialog dlg(this, "Select image file for " + label, "", "",
			 "Binary files (*.bin;*.mbn;*.elf)|*.bin;*.mbn;*.elf|"
			 "All files (*.*)|*.*",
			 wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (dlg.ShowModal() != wxID_OK)
		return;

	int confirm = wxMessageBox(
		wxString::Format(
			"This will ERASE partition '%s' and write:\n%s\n\n"
			"Continue?", label, dlg.GetPath()),
		"QFenix — Replace Partition",
		wxYES_NO | wxICON_EXCLAMATION);
	if (confirm != wxYES)
		return;

	wxArrayString extra;
	extra.Add(label);
	extra.Add(dlg.GetPath());
	extra.Add(programmer);

	auto args = BuildEDLArgs("write", extra);
	m_frame->RunOperation("Write: " + label, args);
}

void PartitionPanel::OnErase(wxCommandEvent &event)
{
	long sel = m_partList->GetNextItem(-1, wxLIST_NEXT_ALL,
					   wxLIST_STATE_SELECTED);
	if (sel < 0 || sel >= (long)m_partitions.size())
		return;

	auto *home = m_frame->GetHomePanel();
	wxString programmer = home->GetProgrammer();
	if (programmer.IsEmpty()) {
		wxMessageBox("Set a programmer/loader on the Home tab first.",
			     "QFenix", wxOK | wxICON_WARNING);
		return;
	}

	wxString label = m_partitions[sel].name;

	int confirm = wxMessageBox(
		wxString::Format(
			"This will ERASE partition '%s'.\n\n"
			"This is destructive and cannot be undone. Continue?",
			label),
		"QFenix — Erase Partition",
		wxYES_NO | wxICON_EXCLAMATION);
	if (confirm != wxYES)
		return;

	wxArrayString extra;
	extra.Add(programmer);
	extra.Add(label);

	auto args = BuildEDLArgs("erase", extra);
	m_frame->RunOperation("Erase: " + label, args);
}
