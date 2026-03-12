#include "ConsolePanel.h"
#include "MainFrame.h"
#include "ProcessRunner.h"
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/base64.h>

ConsolePanel::ConsolePanel(wxWindow *parent, MainFrame *frame)
	: wxPanel(parent), m_frame(frame)
{
	auto *sizer = new wxBoxSizer(wxVERTICAL);

	/* Toolbar row */
	auto *toolbar = new wxBoxSizer(wxHORIZONTAL);

	m_statusLabel = new wxStaticText(this, wxID_ANY, "Idle");
	toolbar->Add(m_statusLabel, 1, wxALIGN_CENTER_VERTICAL | wxLEFT, 8);

	auto *clearBtn = new wxButton(this, wxID_ANY, "Clear");
	clearBtn->Bind(wxEVT_BUTTON, &ConsolePanel::OnClear, this);
	toolbar->Add(clearBtn, 0, wxALL, 4);

	auto *stopBtn = new wxButton(this, wxID_ANY, "Stop");
	stopBtn->Bind(wxEVT_BUTTON, &ConsolePanel::OnStop, this);
	toolbar->Add(stopBtn, 0, wxALL, 4);

	sizer->Add(toolbar, 0, wxEXPAND);

	/* WebView for xterm.js */
	wxString resDir = QFENIX_RESOURCES_DIR;

	/*
	 * Also check the build directory and bundle resources for the HTML.
	 * At runtime the resources might be copied next to the executable.
	 */
	wxString htmlPath = resDir + "/console.html";

	if (!wxFileExists(htmlPath)) {
		/* Try relative to executable */
		wxFileName exePath(wxStandardPaths::Get().GetExecutablePath());
		wxString altPath = exePath.GetPath() + "/resources/console.html";
		if (wxFileExists(altPath))
			htmlPath = altPath;
#ifdef __APPLE__
		/* macOS bundle: .app/Contents/Resources/ */
		wxString bundlePath = exePath.GetPath() +
				      "/../Resources/resources/console.html";
		if (wxFileExists(bundlePath))
			htmlPath = bundlePath;
#endif
	}

	wxString url = "file://" + htmlPath;

	m_webView = wxWebView::New(this, wxID_ANY, url);
	m_webView->Bind(wxEVT_WEBVIEW_LOADED,
			&ConsolePanel::OnWebViewLoaded, this);
	m_webView->Bind(wxEVT_WEBVIEW_NAVIGATING,
			&ConsolePanel::OnWebViewNavigating, this);

	sizer->Add(m_webView, 1, wxEXPAND);

	SetSizer(sizer);
}

wxString ConsolePanel::JSEscape(const char *data, size_t len)
{
	wxString result;
	result.Alloc(len * 2);

	for (size_t i = 0; i < len; i++) {
		unsigned char c = static_cast<unsigned char>(data[i]);
		switch (c) {
		case '\\': result += "\\\\"; break;
		case '\'': result += "\\'";  break;
		case '\n': result += "\\n";  break;
		case '\r': result += "\\r";  break;
		case '\t': result += "\\t";  break;
		case '\0': result += "\\x00"; break;
		default:
			if (c < 0x20) {
				/* Control char — hex-escape for JS string safety.
				 * ESC (0x1b) becomes \x1b which JS interprets as
				 * the actual ESC byte for xterm.js ANSI parsing. */
				result += wxString::Format("\\x%02x", c);
			} else {
				result += static_cast<char>(c);
			}
			break;
		}
	}

	return result;
}

void ConsolePanel::AppendData(const char *data, size_t len)
{
	if (!m_webViewReady) {
		m_pendingData += JSEscape(data, len);
		return;
	}

	wxString escaped = JSEscape(data, len);
	wxString js = "term.write('" + escaped + "');";
	m_webView->RunScript(js);
}

void ConsolePanel::AppendLine(const wxString &text)
{
	wxCharBuffer utf8 = text.utf8_str();
	AppendData(utf8.data(), utf8.length());
}

void ConsolePanel::SetStatus(bool success)
{
	if (success) {
		m_statusLabel->SetLabel("Done");
		m_statusLabel->SetForegroundColour(wxColour(0, 160, 0));
	} else {
		m_statusLabel->SetLabel("Failed");
		m_statusLabel->SetForegroundColour(wxColour(200, 0, 0));
	}
}

void ConsolePanel::Clear()
{
	if (m_webViewReady)
		m_webView->RunScript("term.clear();");
	m_statusLabel->SetLabel("Idle");
	m_statusLabel->SetForegroundColour(
		wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT));
}

void ConsolePanel::OnWebViewLoaded(wxWebViewEvent &event)
{
	m_webViewReady = true;

	/* Flush any data that arrived before the webview was ready */
	if (!m_pendingData.IsEmpty()) {
		wxString js = "term.write('" + m_pendingData + "');";
		m_webView->RunScript(js);
		m_pendingData.Clear();
	}
}

void ConsolePanel::OnWebViewNavigating(wxWebViewEvent &event)
{
	/*
	 * Intercept navigation to our custom scheme for stdin forwarding.
	 * xterm.js onData posts: qfenix-stdin://base64data
	 */
	wxString url = event.GetURL();
	if (url.StartsWith("qfenix-stdin://")) {
		event.Veto(); /* Don't actually navigate */

		wxString b64 = url.Mid(15);
		/* Decode base64 and forward to process stdin */
		wxMemoryBuffer decoded = wxBase64Decode(b64);
		if (decoded.GetDataLen() > 0) {
			wxString data = wxString::FromUTF8(
				static_cast<const char *>(decoded.GetData()),
				decoded.GetDataLen());
			m_frame->GetProcessRunner()->WriteStdin(data);
		}
	}
}

void ConsolePanel::OnClear(wxCommandEvent &event)
{
	Clear();
}

void ConsolePanel::OnStop(wxCommandEvent &event)
{
	m_frame->GetProcessRunner()->Stop();
}
