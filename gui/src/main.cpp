#include <cstring>
#include <wx/wx.h>
#include "MainFrame.h"

/*
 * qfenix_cli_main() is the original main() from qdl.c, renamed at compile
 * time via -Dmain=qfenix_cli_main. This lets us have a single binary that
 * acts as both CLI and GUI.
 */
extern "C" int qfenix_cli_main(int argc, char **argv);

class QFenixApp : public wxApp {
public:
	bool OnInit() override
	{
		auto *frame = new MainFrame();
		frame->Show(true);
		return true;
	}
};

/*
 * Use wxIMPLEMENT_APP_NO_MAIN so we can define our own main()
 * that dispatches between CLI and GUI mode.
 */
wxIMPLEMENT_APP_NO_MAIN(QFenixApp);

/*
 * Decide whether to run in GUI mode.
 *
 * GUI mode when:
 *   - No arguments (double-click, desktop launcher)
 *   - First argument is "gui"
 *
 * CLI mode for everything else (subcommands, flags, files).
 */
static bool is_gui_mode(int argc, char **argv)
{
	if (argc <= 1)
		return true;
	if (strcmp(argv[1], "gui") == 0)
		return true;
	return false;
}

int main(int argc, char **argv)
{
	if (is_gui_mode(argc, argv))
		return wxEntry(argc, argv);
	return qfenix_cli_main(argc, argv);
}
