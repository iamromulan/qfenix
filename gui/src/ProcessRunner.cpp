#include "ProcessRunner.h"
#include "MainFrame.h"
#include "ConsolePanel.h"
#include "OpsPanel.h"
#include <wx/txtstrm.h>
#include <wx/stdpaths.h>
#include <wx/filename.h>
#include <wx/tokenzr.h>
#include <vector>
#include <string>

ProcessRunner::ProcessRunner(MainFrame *frame)
	: m_frame(frame), m_timer(this)
{
	Bind(wxEVT_TIMER, &ProcessRunner::OnTimer, this);
}

ProcessRunner::~ProcessRunner()
{
	if (m_running)
		Stop();
}

wxString ProcessRunner::FindQfenixBinary()
{
	/*
	 * Combined binary: the GUI IS the CLI. The running executable
	 * handles both modes based on argv. When spawning a CLI operation,
	 * we just re-invoke ourselves with the appropriate subcommand args.
	 */
	return wxStandardPaths::Get().GetExecutablePath();
}

wxString ProcessRunner::ShellEscapeSQ(const wxString &s)
{
	/*
	 * Escape for use inside single quotes in shell.
	 * The only character that needs escaping is single-quote itself:
	 *   ' → '\''  (end quote, escaped quote, start quote)
	 */
	wxString result = s;
	result.Replace("'", "'\\''");
	return "'" + result + "'";
}

/*
 * Build a command string that wxExecute will tokenize correctly for
 * /bin/sh -c "<shell script>".
 *
 * wxExecute does NOT invoke a shell — it tokenizes the command string
 * using wxCmdLineParser::ConvertStringToArgs() and calls execvp().
 * Shell features (pipes, redirects) are NOT interpreted.
 *
 * To use shell features, we must explicitly call /bin/sh -c "script".
 * The script is wrapped in double quotes so wxExecute treats it as a
 * single argv element. Inside double quotes, wxExecute's tokenizer
 * interprets \\ and \" as escapes, so those must be escaped in the
 * script content.
 */
static wxString WrapShellCmd(const wxString &script)
{
	wxString escaped = script;
	escaped.Replace("\\", "\\\\");
	escaped.Replace("\"", "\\\"");
	return "/bin/sh -c \"" + escaped + "\"";
}

int ProcessRunner::RunSudoSync(const wxString &cmd, wxArrayString *output,
			       wxArrayString *errors)
{
#ifdef __APPLE__
	if (!m_authenticated)
		return -1;

	/*
	 * Build a shell pipeline that pipes the password into sudo.
	 * printf outputs the password + newline to sudo's stdin.
	 * sudo -S reads the password from stdin.
	 * sudo -p '' suppresses the password prompt text.
	 */
	wxString script = wxString::Format(
		"printf '%%s\\n' %s | sudo -k -S -p '' %s 2>&1",
		ShellEscapeSQ(m_sudoPassword), cmd);

	wxArrayString out, err;
	long rc = wxExecute(WrapShellCmd(script), out, err, wxEXEC_SYNC);

	if (output)
		*output = out;
	if (errors)
		*errors = err;
	return static_cast<int>(rc);
#elif defined(__linux__)
	wxArrayString out, err;
	long rc = wxExecute("pkexec " + cmd, out, err, wxEXEC_SYNC);
	if (output)
		*output = out;
	if (errors)
		*errors = err;
	return static_cast<int>(rc);
#else
	wxArrayString out, err;
	long rc = wxExecute(cmd, out, err, wxEXEC_SYNC);
	if (output)
		*output = out;
	if (errors)
		*errors = err;
	return static_cast<int>(rc);
#endif
}

bool ProcessRunner::Authenticate()
{
#ifdef __APPLE__
	wxPasswordEntryDialog dlg(m_frame,
		"QFenix needs administrator privileges for USB device\n"
		"access and the qcseriald daemon.\n\n"
		"Enter your password to authenticate for this session:",
		"QFenix — Administrator Access");

	if (dlg.ShowModal() != wxID_OK)
		return false;

	wxString password = dlg.GetValue();
	if (password.IsEmpty())
		return false;

	/*
	 * Validate the password by running a no-op command with sudo.
	 * Uses WrapShellCmd() to properly pass the pipe through /bin/sh.
	 */
	wxString script = wxString::Format(
		"printf '%%s\\n' %s | sudo -k -S -p '' /usr/bin/true 2>/dev/null",
		ShellEscapeSQ(password));

	wxArrayString out, err;
	long rc = wxExecute(WrapShellCmd(script), out, err, wxEXEC_SYNC);

	if (rc != 0) {
		wxMessageBox("Incorrect password. Please try again.",
			     "QFenix", wxOK | wxICON_ERROR);
		return false;
	}

	m_sudoPassword = password;
	m_authenticated = true;
	return true;
#elif defined(__linux__)
	/* Linux uses pkexec which handles its own auth dialogs */
	m_authenticated = true;
	return true;
#else
	/* Windows: no elevation needed */
	m_authenticated = true;
	return true;
#endif
}

bool ProcessRunner::EnsureQcseriald()
{
#ifdef __APPLE__
	wxString qfenix = FindQfenixBinary();

	/*
	 * Check if qcseriald is already running.
	 *
	 * The daemon writes its PID file to /var/run/ when running as
	 * root, but /tmp/ when running as non-root. Since we start it
	 * with sudo (root), we must also check status with sudo so
	 * init_runtime_paths() resolves to the same /var/run/ paths.
	 */
	if (m_authenticated) {
		int rc = RunSudoSync(qfenix + " qcseriald status");
		if (rc == 0)
			return true; /* Already running */
	} else {
		wxArrayString out, err;
		long rc = wxExecute(qfenix + " qcseriald status", out, err,
				    wxEXEC_SYNC);
		if (rc == 0)
			return true;
	}

	if (!m_authenticated)
		return false;

	/* Start the daemon with sudo */
	int startRc = RunSudoSync(qfenix + " qcseriald start");

	if (startRc != 0) {
		m_frame->GetConsolePanel()->AppendLine(
			"\r\n[WARNING] Failed to start qcseriald daemon.\r\n");
		return false;
	}

	/*
	 * Wait briefly for the daemon to initialize and create ports.
	 * The daemon forks and the parent exits quickly, but port
	 * probing takes a moment.
	 */
	for (int i = 0; i < 10; i++) {
		wxMilliSleep(500);
		wxYield(); /* Keep UI responsive */

		int rc = RunSudoSync(qfenix + " qcseriald status");
		if (rc == 0) {
			m_frame->GetConsolePanel()->AppendLine(
				"[qcseriald] Daemon started successfully.\r\n");
			return true;
		}
	}

	m_frame->GetConsolePanel()->AppendLine(
		"[WARNING] qcseriald started but may still be initializing.\r\n");
	return true; /* Started but might still be probing */
#else
	return true; /* Not applicable on other platforms */
#endif
}

void ProcessRunner::Run(const wxArrayString &args, const wxString &workDir)
{
	if (m_running) {
		m_frame->GetConsolePanel()->AppendLine(
			"\r\n[ERROR] Another operation is already running.\r\n");
		return;
	}

#ifdef __APPLE__
	if (!m_authenticated) {
		if (!Authenticate()) {
			m_frame->GetConsolePanel()->AppendLine(
				"\r\n[ERROR] Authentication required.\r\n");
			return;
		}
	}
#endif

	wxString qfenix = FindQfenixBinary();

	/* Build command string for display */
	wxString displayCmd = qfenix;
	for (const auto &arg : args)
		displayCmd += " " + arg;

	/*
	 * Build an argv array for wxExecute's char** overload.
	 *
	 * This bypasses wxExecute's string tokenizer, which strips
	 * quotes from arguments — breaking AT commands like
	 * AT+QCFG="usbcfg". Using char** preserves arguments exactly.
	 *
	 * macOS: sudo -S -p '' <binary> <args...>
	 *   Password is written to stdin immediately after process start.
	 * Linux: pkexec <binary> <args...>
	 * Windows: <binary> <args...>
	 */
	std::vector<std::string> argStrs;

#ifdef __APPLE__
	argStrs.push_back("sudo");
	argStrs.push_back("-k");  /* Invalidate cached credentials so sudo always reads password from stdin */
	argStrs.push_back("-S");
	argStrs.push_back("-p");
	argStrs.push_back("");
#elif defined(__linux__)
	argStrs.push_back("pkexec");
#endif

	argStrs.push_back(std::string(qfenix.utf8_str()));
	for (const auto &arg : args)
		argStrs.push_back(std::string(arg.utf8_str()));

	std::vector<const char *> argv;
	for (const auto &s : argStrs)
		argv.push_back(s.c_str());
	argv.push_back(nullptr);

	m_process = new wxProcess(this);
	m_process->Redirect();
	Bind(wxEVT_END_PROCESS, &ProcessRunner::OnProcessTerminated, this);

	m_frame->GetConsolePanel()->AppendLine("$ " + displayCmd + "\r\n");

	/*
	 * Set the subprocess working directory so output files land
	 * in the user's chosen directory instead of next to the .app.
	 */
	wxString savedCwd;
	if (!workDir.IsEmpty() && wxDirExists(workDir)) {
		savedCwd = wxGetCwd();
		wxSetWorkingDirectory(workDir);
	}

	m_pid = wxExecute(const_cast<char **>(argv.data()),
			  wxEXEC_ASYNC, m_process);

	if (!savedCwd.IsEmpty())
		wxSetWorkingDirectory(savedCwd);
	if (m_pid <= 0) {
		m_frame->GetConsolePanel()->AppendLine(
			"[ERROR] Failed to start qfenix process.\r\n");
		delete m_process;
		m_process = nullptr;
		return;
	}

#ifdef __APPLE__
	/*
	 * Write password to stdin for sudo -S.
	 * sudo reads exactly one line (password + newline) then passes
	 * remaining stdin to the child process.
	 */
	if (m_authenticated) {
		auto *out = m_process->GetOutputStream();
		if (out) {
			wxString pw = m_sudoPassword + "\n";
			out->Write(pw.utf8_str(), pw.utf8_str().length());
		}
	}
#endif

	m_running = true;
	m_timer.Start(50); /* Poll output every 50ms */
}

void ProcessRunner::WriteStdin(const wxString &data)
{
	if (!m_running || !m_process)
		return;

	auto *out = m_process->GetOutputStream();
	if (out) {
		wxString d = data;
		out->Write(d.utf8_str(), d.utf8_str().length());
	}
}

void ProcessRunner::Stop()
{
	if (!m_running || m_pid <= 0)
		return;

	wxKill(m_pid, wxSIGTERM);
	m_frame->GetConsolePanel()->AppendLine(
		"\r\n[Stopped by user]\r\n");
}

void ProcessRunner::OnTimer(wxTimerEvent &event)
{
	PollOutput();
}

void ProcessRunner::PollOutput()
{
	/*
	 * Guard against reentrant destruction: AppendData() calls
	 * wxWebView::RunScript() which can pump the event loop. If
	 * wxEVT_END_PROCESS arrives during that pump, OnProcessTerminated()
	 * deletes m_process while we still hold stream pointers.
	 *
	 * Fix: re-check m_process on every loop iteration, and re-fetch
	 * stream pointers from m_process each time (never cache them
	 * across an AppendData call).
	 */
	char buf[4096];

	while (m_process) {
		auto *in = m_process->GetInputStream();
		if (!in || !in->CanRead())
			break;
		in->Read(buf, sizeof(buf) - 1);
		size_t n = in->LastRead();
		if (n > 0) {
			buf[n] = '\0';
			m_frame->GetConsolePanel()->AppendData(buf, n);
		}
	}

	while (m_process) {
		auto *err = m_process->GetErrorStream();
		if (!err || !err->CanRead())
			break;
		err->Read(buf, sizeof(buf) - 1);
		size_t n = err->LastRead();
		if (n > 0) {
			buf[n] = '\0';
			m_frame->GetConsolePanel()->AppendData(buf, n);
		}
	}
}

void ProcessRunner::OnProcessTerminated(wxProcessEvent &event)
{
	/* Drain any remaining output */
	PollOutput();

	int exitCode = event.GetExitCode();

	wxString status = (exitCode == 0)
		? "\r\n[Done - Success]\r\n"
		: wxString::Format("\r\n[Done - Exit code: %d]\r\n", exitCode);

	m_frame->GetConsolePanel()->AppendLine(status);
	m_frame->GetConsolePanel()->SetStatus(exitCode == 0);

	m_running = false;
	m_timer.Stop();

	delete m_process;
	m_process = nullptr;
	m_pid = 0;

	/* Unlock operations panel */
	m_frame->GetOpsPanel()->SetRunning(false);
}
