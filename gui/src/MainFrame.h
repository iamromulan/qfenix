#ifndef QFENIX_GUI_MAINFRAME_H
#define QFENIX_GUI_MAINFRAME_H

#include <wx/wx.h>
#include <wx/notebook.h>

class HomePanel;
class OpsPanel;
class PartitionPanel;
class NVBrowserPanel;
class ConsolePanel;
class ProcessRunner;

/* Menu IDs */
enum {
	ID_VIEW_LOGS = wxID_HIGHEST + 1,
	ID_VIEW_DAEMON_LOG,
};

/* Tab indices */
enum TabIndex {
	TAB_HOME = 0,
	TAB_OPS,
	TAB_PARTITION,
	TAB_NVBROWSER,
	TAB_CONSOLE,
};

class MainFrame : public wxFrame {
public:
	MainFrame();

	/* Called by OpsPanel when user starts an operation */
	void RunOperation(const wxString &label, const wxArrayString &args);

	/* Accessors for panels to communicate */
	HomePanel *GetHomePanel() const { return m_home; }
	OpsPanel *GetOpsPanel() const { return m_ops; }
	PartitionPanel *GetPartitionPanel() const { return m_partition; }
	NVBrowserPanel *GetNVBrowserPanel() const { return m_nvBrowser; }
	ConsolePanel *GetConsolePanel() const { return m_console; }
	ProcessRunner *GetProcessRunner() const { return m_runner; }

	/* Switch to a specific tab */
	void SwitchToTab(int index);

	/* Append a log message to the internal log buffer and console */
	void Log(const wxString &msg);

private:
	void OnStartupInit();
	void OnClose(wxCloseEvent &event);
	void OnAbout(wxCommandEvent &event);
	void OnViewLogs(wxCommandEvent &event);
	void OnViewDaemonLog(wxCommandEvent &event);

	void CreateMenuBar();

	wxNotebook *m_notebook;
	HomePanel *m_home;
	OpsPanel *m_ops;
	PartitionPanel *m_partition;
	NVBrowserPanel *m_nvBrowser;
	ConsolePanel *m_console;
	ProcessRunner *m_runner;

	/* Internal log buffer */
	wxArrayString m_logBuffer;
};

#endif
