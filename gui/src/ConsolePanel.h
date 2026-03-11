#ifndef QFENIX_GUI_CONSOLEPANEL_H
#define QFENIX_GUI_CONSOLEPANEL_H

#include <wx/wx.h>
#include <wx/webview.h>

class MainFrame;

class ConsolePanel : public wxPanel {
public:
	ConsolePanel(wxWindow *parent, MainFrame *frame);

	/* Append raw bytes (may contain ANSI escapes) to the terminal */
	void AppendData(const char *data, size_t len);

	/* Append a plain text line (auto-escaped for JS) */
	void AppendLine(const wxString &text);

	/* Set status indicator after operation completes */
	void SetStatus(bool success);

	/* Clear terminal history */
	void Clear();

private:
	void OnWebViewLoaded(wxWebViewEvent &event);
	void OnWebViewNavigating(wxWebViewEvent &event);
	void OnClear(wxCommandEvent &event);
	void OnStop(wxCommandEvent &event);

	/* Escape a string for safe embedding in a JS string literal */
	static wxString JSEscape(const char *data, size_t len);

	MainFrame *m_frame;
	wxWebView *m_webView;
	wxStaticText *m_statusLabel;
	bool m_webViewReady = false;

	/* Buffer data received before webview is ready */
	wxString m_pendingData;
};

#endif
