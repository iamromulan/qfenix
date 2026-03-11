#include "MainFrame.h"
#include "HomePanel.h"
#include "OpsPanel.h"
#include "ConsolePanel.h"
#include "ProcessRunner.h"
#include "version.h"

MainFrame::MainFrame()
	: wxFrame(nullptr, wxID_ANY, "QFenix", wxDefaultPosition,
		  wxSize(900, 650))
{
	/* Process runner (not a visible widget) */
	m_runner = new ProcessRunner(this);

	/* Menu bar */
	CreateMenuBar();

	/* Tab notebook */
	m_notebook = new wxNotebook(this, wxID_ANY);

	m_home = new HomePanel(m_notebook, this);
	m_ops = new OpsPanel(m_notebook, this);
	m_console = new ConsolePanel(m_notebook, this);

	m_notebook->AddPage(m_home, "Home");
	m_notebook->AddPage(m_ops, "Operations");
	m_notebook->AddPage(m_console, "Console");

	/* Layout */
	auto *sizer = new wxBoxSizer(wxVERTICAL);
	sizer->Add(m_notebook, 1, wxEXPAND);
	SetSizer(sizer);

	Centre();
	Bind(wxEVT_CLOSE_WINDOW, &MainFrame::OnClose, this);

	/*
	 * Deferred startup sequence:
	 * 1. Prompt for admin password (one-time for the session)
	 * 2. Start qcseriald daemon if not already running
	 * 3. Refresh device list
	 *
	 * CallAfter ensures the window is fully shown before dialogs appear.
	 */
	CallAfter(&MainFrame::OnStartupInit);
}

void MainFrame::CreateMenuBar()
{
	auto *menuBar = new wxMenuBar();

	/* File menu */
	auto *fileMenu = new wxMenu();
	fileMenu->Append(wxID_EXIT, "Quit QFenix\tCtrl+Q");
	menuBar->Append(fileMenu, "File");

	/* View menu */
	auto *viewMenu = new wxMenu();
	viewMenu->Append(ID_VIEW_LOGS, "Application Log\tCtrl+L",
			 "Show internal application log");
	viewMenu->Append(ID_VIEW_DAEMON_LOG, "qcseriald Daemon Log",
			 "Show qcseriald daemon log file");
	menuBar->Append(viewMenu, "View");

	/* Help menu */
	auto *helpMenu = new wxMenu();
	helpMenu->Append(wxID_ABOUT, "About QFenix");
	menuBar->Append(helpMenu, "Help");

	SetMenuBar(menuBar);

	Bind(wxEVT_MENU, [this](wxCommandEvent &) { Close(); }, wxID_EXIT);
	Bind(wxEVT_MENU, &MainFrame::OnAbout, this, wxID_ABOUT);
	Bind(wxEVT_MENU, &MainFrame::OnViewLogs, this, ID_VIEW_LOGS);
	Bind(wxEVT_MENU, &MainFrame::OnViewDaemonLog, this, ID_VIEW_DAEMON_LOG);
}

void MainFrame::Log(const wxString &msg)
{
	wxDateTime now = wxDateTime::Now();
	wxString entry = now.FormatISOCombined(' ') + " " + msg;
	m_logBuffer.Add(entry);

	/* Also echo to console panel if it exists */
	if (m_console)
		m_console->AppendLine("[LOG] " + msg + "\r\n");
}

void MainFrame::RunOperation(const wxString &label, const wxArrayString &args)
{
	SwitchToTab(2); /* Console tab */
	m_console->AppendLine("\n--- " + label + " ---\n");
	m_ops->SetRunning(true);
	m_runner->Run(args, m_home->GetWorkingDir());
}

void MainFrame::SwitchToTab(int index)
{
	m_notebook->SetSelection(index);
}

void MainFrame::OnStartupInit()
{
#ifdef __APPLE__
	/*
	 * macOS startup sequence:
	 * 1. Authenticate once (password cached for the session)
	 * 2. Start qcseriald if not running (needs root for USB access)
	 * 3. Refresh device list (now has ports from qcseriald)
	 */
	Log("Prompting for admin authentication...");
	if (!m_runner->Authenticate()) {
		Log("Authentication declined or failed");
		m_console->AppendLine(
			"[WARNING] Not authenticated — operations will "
			"prompt for password.\r\n");
	} else {
		Log("Authentication successful");
	}

	if (m_runner->IsAuthenticated()) {
		m_console->AppendLine("[Checking qcseriald daemon...]\r\n");
		Log("Checking qcseriald daemon status...");
		bool ok = m_runner->EnsureQcseriald();
		Log(ok ? "qcseriald daemon is running"
		       : "qcseriald daemon failed to start");
	}
#endif

	Log("Refreshing device list...");
	m_home->RefreshDevices();
	Log("Startup complete");
}

void MainFrame::OnAbout(wxCommandEvent &event)
{
	wxString msg = wxString::Format(
		"QFenix — Qualcomm Modem Multi-Tool\n\n"
		"Version: %s\n"
		"GUI built with wxWidgets %d.%d.%d\n\n"
		"USB-to-serial daemon, firmware flashing, DIAG protocol,\n"
		"EFS management, AT commands, and more.\n\n"
		"https://github.com/iamromulan/qfenix",
		VERSION,
		wxMAJOR_VERSION, wxMINOR_VERSION, wxRELEASE_NUMBER);

	wxMessageBox(msg, "About QFenix", wxOK | wxICON_INFORMATION, this);
}

void MainFrame::OnViewLogs(wxCommandEvent &event)
{
	wxString log;
	for (const auto &line : m_logBuffer)
		log += line + "\n";

	if (log.IsEmpty())
		log = "(No log entries yet)";

	wxDialog dlg(this, wxID_ANY, "QFenix Application Log",
		     wxDefaultPosition, wxSize(700, 500));
	auto *sizer = new wxBoxSizer(wxVERTICAL);
	auto *text = new wxTextCtrl(&dlg, wxID_ANY, log,
				    wxDefaultPosition, wxDefaultSize,
				    wxTE_MULTILINE | wxTE_READONLY |
				    wxTE_DONTWRAP | wxHSCROLL);
	text->SetFont(wxFont(12, wxFONTFAMILY_TELETYPE,
			     wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
	sizer->Add(text, 1, wxEXPAND | wxALL, 8);

	auto *closeBtn = new wxButton(&dlg, wxID_OK, "Close");
	sizer->Add(closeBtn, 0, wxALIGN_RIGHT | wxALL, 8);

	dlg.SetSizer(sizer);
	dlg.ShowModal();
}

void MainFrame::OnViewDaemonLog(wxCommandEvent &event)
{
#ifdef __APPLE__
	if (!m_runner->IsAuthenticated()) {
		wxMessageBox("Authenticate first to view daemon logs.",
			     "QFenix", wxOK | wxICON_WARNING, this);
		return;
	}

	wxArrayString output;
	int rc = m_runner->RunSudoSync(
		"cat /var/log/qcseriald.log 2>/dev/null || "
		"cat /tmp/qcseriald.log 2>/dev/null || "
		"echo '(No daemon log found)'", &output);

	wxString log;
	for (const auto &line : output)
		log += line + "\n";

	wxDialog dlg(this, wxID_ANY, "qcseriald Daemon Log",
		     wxDefaultPosition, wxSize(800, 600));
	auto *sizer = new wxBoxSizer(wxVERTICAL);
	auto *text = new wxTextCtrl(&dlg, wxID_ANY, log,
				    wxDefaultPosition, wxDefaultSize,
				    wxTE_MULTILINE | wxTE_READONLY |
				    wxTE_DONTWRAP | wxHSCROLL);
	text->SetFont(wxFont(12, wxFONTFAMILY_TELETYPE,
			     wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
	sizer->Add(text, 1, wxEXPAND | wxALL, 8);

	/* Scroll to bottom */
	text->SetInsertionPointEnd();

	auto *closeBtn = new wxButton(&dlg, wxID_OK, "Close");
	sizer->Add(closeBtn, 0, wxALIGN_RIGHT | wxALL, 8);

	dlg.SetSizer(sizer);
	dlg.ShowModal();
#else
	wxMessageBox("Daemon log is only available on macOS.",
		     "QFenix", wxOK | wxICON_INFORMATION, this);
#endif
}

void MainFrame::OnClose(wxCloseEvent &event)
{
	if (m_runner->IsRunning()) {
		int answer = wxMessageBox(
			"An operation is still running. Stop it and quit?",
			"QFenix", wxYES_NO | wxICON_WARNING, this);
		if (answer != wxYES) {
			event.Veto();
			return;
		}
		m_runner->Stop();
	}
	Destroy();
}
