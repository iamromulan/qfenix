#ifndef QFENIX_GUI_PROCESSRUNNER_H
#define QFENIX_GUI_PROCESSRUNNER_H

#include <wx/wx.h>
#include <wx/process.h>

class MainFrame;

/*
 * Manages spawning qfenix as a subprocess with privilege escalation.
 * Reads stdout/stderr asynchronously and pushes data to the console panel.
 * Handles stdin forwarding for interactive commands (atconsole).
 *
 * macOS privilege model: prompts for admin password once at startup
 * via wxPasswordEntryDialog, validates with sudo -S, then reuses the
 * cached password for all subprocess invocations. Eliminates osascript
 * to avoid I/O interference with piped stdout/stderr.
 */
class ProcessRunner : public wxEvtHandler {
public:
	explicit ProcessRunner(MainFrame *frame);
	~ProcessRunner() override;

	/* Find the qfenix binary (bundled or PATH) */
	static wxString FindQfenixBinary();

	/*
	 * Prompt the user for admin password and validate it.
	 * Shows a native password dialog, tests with sudo -S -v.
	 * Returns true if authentication succeeded.
	 */
	bool Authenticate();

	/* Check if we have a cached admin password */
	bool IsAuthenticated() const { return m_authenticated; }

	/*
	 * Ensure qcseriald daemon is running (macOS only).
	 * Checks status, starts with sudo if needed.
	 * Returns true if running or started successfully.
	 */
	bool EnsureQcseriald();

	/*
	 * Start a qfenix operation.
	 * args[0] should be the subcommand, args[1..] are flags.
	 * The qfenix binary path and privilege escalation are handled internally.
	 * If workDir is non-empty, the subprocess starts in that directory.
	 */
	void Run(const wxArrayString &args, const wxString &workDir = wxEmptyString);

	/* Send data to the process stdin (for atconsole) */
	void WriteStdin(const wxString &data);

	/* Kill the running process */
	void Stop();

	bool IsRunning() const { return m_running; }

	/*
	 * Run a command synchronously with sudo, piping the cached
	 * password via stdin. Returns the process exit code.
	 * stdout/stderr are captured in the output/errors arrays.
	 */
	int RunSudoSync(const wxString &cmd, wxArrayString *output = nullptr,
			wxArrayString *errors = nullptr);

private:
	void OnTimer(wxTimerEvent &event);
	void OnProcessTerminated(wxProcessEvent &event);
	void PollOutput();

	/*
	 * Shell-escape a string for safe use inside single quotes.
	 * Used for passing password to sudo via printf pipe.
	 */
	static wxString ShellEscapeSQ(const wxString &s);

	MainFrame *m_frame;
	wxProcess *m_process = nullptr;
	wxTimer m_timer;
	long m_pid = 0;
	bool m_running = false;
	bool m_authenticated = false;
	wxString m_sudoPassword;
};

#endif
