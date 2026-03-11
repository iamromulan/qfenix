#include "HomePanel.h"
#include "MainFrame.h"
#include "ProcessRunner.h"
#include <wx/filename.h>
#include <wx/tokenzr.h>

HomePanel::HomePanel(wxWindow *parent, MainFrame *frame)
	: wxPanel(parent), m_frame(frame)
{
	auto *mainSizer = new wxBoxSizer(wxVERTICAL);

	/* --- Device / Port Selection --- */
	auto *devBox = new wxStaticBoxSizer(wxVERTICAL, this,
					    "Device && Port Selection");

	auto *devGrid = new wxFlexGridSizer(3, 2, 8, 12);
	devGrid->AddGrowableCol(1, 1);

	devGrid->Add(new wxStaticText(this, wxID_ANY, "DIAG Port:"),
		     0, wxALIGN_CENTER_VERTICAL);
	m_diagPort = new wxComboBox(this, wxID_ANY);
	devGrid->Add(m_diagPort, 1, wxEXPAND);

	devGrid->Add(new wxStaticText(this, wxID_ANY, "AT Port:"),
		     0, wxALIGN_CENTER_VERTICAL);
	m_atPort = new wxComboBox(this, wxID_ANY);
	devGrid->Add(m_atPort, 1, wxEXPAND);

	devGrid->Add(new wxStaticText(this, wxID_ANY, "EDL Device:"),
		     0, wxALIGN_CENTER_VERTICAL);
	m_edlSerial = new wxComboBox(this, wxID_ANY);
	devGrid->Add(m_edlSerial, 1, wxEXPAND);

	devBox->Add(devGrid, 0, wxEXPAND | wxALL, 8);

	auto *refreshBtn = new wxButton(this, wxID_ANY, "Refresh Devices");
	refreshBtn->Bind(wxEVT_BUTTON, &HomePanel::OnRefresh, this);
	devBox->Add(refreshBtn, 0, wxALL, 8);

	mainSizer->Add(devBox, 0, wxEXPAND | wxALL, 10);

	/* --- Paths --- */
	auto *pathBox = new wxStaticBoxSizer(wxVERTICAL, this, "Paths");
	auto *pathGrid = new wxFlexGridSizer(3, 3, 8, 8);
	pathGrid->AddGrowableCol(1, 1);

	/* Firmware directory */
	pathGrid->Add(new wxStaticText(this, wxID_ANY, "Firmware Dir:"),
		      0, wxALIGN_CENTER_VERTICAL);
	m_firmwareDir = new wxTextCtrl(this, wxID_ANY);
	pathGrid->Add(m_firmwareDir, 1, wxEXPAND);
	auto *fwBtn = new wxButton(this, wxID_ANY, "Browse...");
	fwBtn->Bind(wxEVT_BUTTON, &HomePanel::OnBrowseFirmware, this);
	pathGrid->Add(fwBtn);

	/* Working directory */
	pathGrid->Add(new wxStaticText(this, wxID_ANY, "Working Dir:"),
		      0, wxALIGN_CENTER_VERTICAL);
	m_workingDir = new wxTextCtrl(this, wxID_ANY);
	pathGrid->Add(m_workingDir, 1, wxEXPAND);
	auto *wdBtn = new wxButton(this, wxID_ANY, "Browse...");
	wdBtn->Bind(wxEVT_BUTTON, &HomePanel::OnBrowseWorkDir, this);
	pathGrid->Add(wdBtn);

	/* Programmer / loader */
	pathGrid->Add(new wxStaticText(this, wxID_ANY, "Programmer:"),
		      0, wxALIGN_CENTER_VERTICAL);
	m_programmer = new wxTextCtrl(this, wxID_ANY);
	pathGrid->Add(m_programmer, 1, wxEXPAND);
	auto *progBtn = new wxButton(this, wxID_ANY, "Browse...");
	progBtn->Bind(wxEVT_BUTTON, &HomePanel::OnBrowseProgrammer, this);
	pathGrid->Add(progBtn);

	pathBox->Add(pathGrid, 0, wxEXPAND | wxALL, 8);
	mainSizer->Add(pathBox, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);

	/* --- Options --- */
	auto *optBox = new wxStaticBoxSizer(wxHORIZONTAL, this, "Options");

	optBox->Add(new wxStaticText(this, wxID_ANY, "Storage Type:"),
		    0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);

	wxArrayString storageChoices;
	storageChoices.Add("auto");
	storageChoices.Add("emmc");
	storageChoices.Add("ufs");
	storageChoices.Add("nand");
	storageChoices.Add("nvme");
	storageChoices.Add("spinor");
	m_storageType = new wxChoice(this, wxID_ANY, wxDefaultPosition,
				     wxDefaultSize, storageChoices);
	m_storageType->SetSelection(0);
	optBox->Add(m_storageType, 0, wxALIGN_CENTER_VERTICAL);

	mainSizer->Add(optBox, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);

	/* --- Status --- */
	auto *statusBox = new wxStaticBoxSizer(wxVERTICAL, this, "Status");
	m_statusText = new wxStaticText(this, wxID_ANY,
					"Click 'Refresh Devices' to scan.");
	statusBox->Add(m_statusText, 1, wxEXPAND | wxALL, 8);
	mainSizer->Add(statusBox, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);

	SetSizer(mainSizer);

	/*
	 * Auto-refresh is handled by MainFrame::OnStartupInit() which
	 * first authenticates and starts qcseriald, then calls
	 * RefreshDevices() so the device list includes qcseriald ports.
	 */
}

wxString HomePanel::GetDiagPort() const
{
	return m_diagPort->GetValue();
}

wxString HomePanel::GetATPort() const
{
	return m_atPort->GetValue();
}

wxString HomePanel::GetEDLSerial() const
{
	return m_edlSerial->GetValue();
}

wxString HomePanel::GetFirmwareDir() const
{
	return m_firmwareDir->GetValue();
}

wxString HomePanel::GetWorkingDir() const
{
	return m_workingDir->GetValue();
}

wxString HomePanel::GetProgrammer() const
{
	return m_programmer->GetValue();
}

wxString HomePanel::GetStorageType() const
{
	int sel = m_storageType->GetSelection();
	if (sel <= 0)
		return wxEmptyString; /* auto = don't pass -s */
	return m_storageType->GetString(sel);
}

void HomePanel::OnRefresh(wxCommandEvent &event)
{
	RefreshDevices();
}

void HomePanel::RefreshDevices()
{
	m_statusText->SetLabel("Scanning for devices...");

	/*
	 * qfenix list needs root on macOS to access qcseriald's
	 * /var/run/ status file and USB devices. Run through sudo.
	 */
	auto *runner = m_frame->GetProcessRunner();
	wxArrayString output;

	if (runner->IsAuthenticated()) {
		runner->RunSudoSync(
			ProcessRunner::FindQfenixBinary() + " list", &output);
	} else {
		wxArrayString errors;
		wxExecute(ProcessRunner::FindQfenixBinary() + " list",
			  output, errors, wxEXEC_SYNC);
	}

	wxString fullOutput;
	for (const auto &line : output)
		fullOutput += line + "\n";

	ParseDeviceList(fullOutput);

	/* Append qcseriald daemon status to the status line */
	UpdateDaemonStatus();
}

void HomePanel::UpdateDaemonStatus()
{
#ifdef __APPLE__
	auto *runner = m_frame->GetProcessRunner();
	if (!runner->IsAuthenticated())
		return;

	/*
	 * Read the qcseriald status file via sudo (root writes to
	 * /var/run/, so we need root to read it reliably).
	 */
	wxArrayString out;
	int rc = runner->RunSudoSync("cat /var/run/qcseriald.status", &out);

	if (rc != 0) {
		/* Daemon not running or no status file */
		wxString cur = m_statusText->GetLabel();
		m_statusText->SetLabel(cur + "\nqcseriald: not running");
		return;
	}

	/* Parse key=value status file */
	wxString state, edl;
	int bridges = 0;
	wxArrayString ports;

	for (const auto &line : out) {
		if (line.StartsWith("state="))
			state = line.Mid(6);
		else if (line.StartsWith("bridges="))
			bridges = wxAtoi(line.Mid(8));
		else if (line.StartsWith("edl="))
			edl = line.Mid(4);
		else if (line.StartsWith("port.")) {
			/* port.diag=/dev/tty.qcserial-diag healthy */
			wxString portInfo = line.Mid(5);
			wxString name = portInfo.BeforeFirst('=');
			ports.Add(name);
		}
	}

	/* Build a human-readable status string */
	wxString daemonStatus = "qcseriald: ";

	if (state == "running") {
		daemonStatus += wxString::Format("modem connected (%d bridge%s)",
			bridges, bridges == 1 ? "" : "s");
		if (!ports.IsEmpty()) {
			daemonStatus += " — ports: ";
			for (size_t i = 0; i < ports.size(); i++) {
				if (i > 0)
					daemonStatus += ", ";
				daemonStatus += ports[i];
			}
		}
	} else if (state == "waiting") {
		daemonStatus += "waiting for modem (no modem connected)";
	} else if (state == "starting") {
		daemonStatus += "starting up...";
	} else {
		daemonStatus += state;
	}

	if (!edl.IsEmpty())
		daemonStatus += "\nEDL device: " + edl;

	wxString cur = m_statusText->GetLabel();
	m_statusText->SetLabel(cur + "\n" + daemonStatus);
#endif
}

void HomePanel::ParseDeviceList(const wxString &output)
{
	/*
	 * Parse the qfenix list output. The format uses section headers
	 * followed by indented device lines:
	 *
	 *   DIAG devices (qcseriald):
	 *     /dev/tty.qcserial-diag
	 *
	 *   AT/serial devices (qcseriald):
	 *     /dev/tty.qcserial-nmea            (nmea)
	 *     /dev/tty.qcserial-at0             (at0)
	 *     /dev/tty.qcserial-at1             (at1)
	 *
	 *   EDL devices:
	 *     05c6:9008  serial=ABC123
	 *
	 *   ADB devices:
	 *     2c7c:0122  iface 5
	 *
	 * Linux also has:
	 *   DIAG /dev/ttyUSB0
	 *   AT   /dev/ttyUSB2
	 */
	m_diagPort->Clear();
	m_atPort->Clear();
	m_edlSerial->Clear();

	int edlCount = 0, diagCount = 0, atCount = 0, adbCount = 0;

	enum { SEC_NONE, SEC_DIAG, SEC_AT, SEC_EDL, SEC_ADB } section = SEC_NONE;

	wxStringTokenizer lines(output, "\n");
	while (lines.HasMoreTokens()) {
		wxString line = lines.GetNextToken();
		wxString trimmed = line.Strip(wxString::both);
		wxString upper = trimmed.Upper();

		if (trimmed.IsEmpty())
			continue;

		/* Detect section headers */
		if (upper.StartsWith("DIAG DEVICES") ||
		    upper.StartsWith("DIAG:")) {
			section = SEC_DIAG;
			continue;
		} else if (upper.StartsWith("AT/SERIAL") ||
			   upper.StartsWith("AT DEVICES") ||
			   upper.StartsWith("AT:")) {
			section = SEC_AT;
			continue;
		} else if (upper.StartsWith("EDL DEVICES") ||
			   upper.StartsWith("EDL:")) {
			section = SEC_EDL;
			continue;
		} else if (upper.StartsWith("ADB")) {
			section = SEC_ADB;
			continue;
		}

		/* Indented lines belong to the current section */
		bool indented = line.StartsWith("  ") || line.StartsWith("\t");

		if (indented && section == SEC_DIAG) {
			wxString port = trimmed.BeforeFirst(' ');
			if (port.IsEmpty())
				port = trimmed;
			if (port.StartsWith("/dev/") || port.StartsWith("COM")) {
				m_diagPort->Append(port);
				diagCount++;
			}
		} else if (indented && section == SEC_AT) {
			wxString port = trimmed.BeforeFirst(' ');
			if (port.IsEmpty())
				port = trimmed;
			if (port.StartsWith("/dev/") || port.StartsWith("COM")) {
				/* Classify: nmea ports are not AT ports */
				bool isNmea = trimmed.Contains("(nmea)") ||
					      port.Contains("nmea");
				if (!isNmea) {
					m_atPort->Append(port);
					atCount++;
				}
			}
		} else if (indented && section == SEC_EDL) {
			/*
			 * Extract serial from list format:
			 *   05c6:9008  SN:03038256
			 *   05c6:9008  serial=ABC123
			 * CLI's -S flag expects just the serial number.
			 */
			wxString sn;
			int pos = trimmed.Find("SN:");
			if (pos != wxNOT_FOUND)
				sn = trimmed.Mid(pos + 3).BeforeFirst(' ');
			else if ((pos = trimmed.Find("serial=")) != wxNOT_FOUND)
				sn = trimmed.Mid(pos + 7).BeforeFirst(' ');
			else
				sn = trimmed;
			m_edlSerial->Append(sn);
			edlCount++;
		} else if (indented && section == SEC_ADB) {
			adbCount++;
		} else if (!indented) {
			/*
			 * Flat format (Linux): "DIAG /dev/ttyUSB0"
			 */
			if (upper.StartsWith("DIAG ")) {
				wxString port = trimmed.Mid(5).Strip(wxString::leading);
				if (port.StartsWith("/dev/") ||
				    port.StartsWith("COM")) {
					m_diagPort->Append(port);
					diagCount++;
				}
			} else if (upper.StartsWith("AT ")) {
				wxString port = trimmed.Mid(3).Strip(wxString::leading);
				if (port.StartsWith("/dev/") ||
				    port.StartsWith("COM")) {
					m_atPort->Append(port);
					atCount++;
				}
			} else if (upper.StartsWith("EDL ")) {
				m_edlSerial->Append(trimmed.Mid(4).Strip(wxString::leading));
				edlCount++;
			}
			section = SEC_NONE;
		}
	}

	/* Auto-select first entry */
	if (m_diagPort->GetCount() > 0)
		m_diagPort->SetSelection(0);
	if (m_atPort->GetCount() > 0)
		m_atPort->SetSelection(0);
	if (m_edlSerial->GetCount() > 0)
		m_edlSerial->SetSelection(0);

	m_statusText->SetLabel(wxString::Format(
		"Found: %d EDL, %d DIAG, %d AT, %d ADB device(s)",
		edlCount, diagCount, atCount, adbCount));
}

void HomePanel::OnBrowseFirmware(wxCommandEvent &event)
{
	wxDirDialog dlg(this, "Select Firmware Directory", m_firmwareDir->GetValue());
	if (dlg.ShowModal() == wxID_OK)
		m_firmwareDir->SetValue(dlg.GetPath());
}

void HomePanel::OnBrowseWorkDir(wxCommandEvent &event)
{
	wxDirDialog dlg(this, "Select Working Directory", m_workingDir->GetValue());
	if (dlg.ShowModal() == wxID_OK)
		m_workingDir->SetValue(dlg.GetPath());
}

void HomePanel::OnBrowseProgrammer(wxCommandEvent &event)
{
	wxFileDialog dlg(this, "Select Programmer/Loader", "", "",
			 "ELF/MBN files (*.elf;*.mbn)|*.elf;*.mbn|All files (*.*)|*.*",
			 wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (dlg.ShowModal() == wxID_OK)
		m_programmer->SetValue(dlg.GetPath());
}
