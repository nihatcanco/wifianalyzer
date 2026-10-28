/*
 * Main executable of the Wi-Fi Analyzer.app bundle that bundle.py builds.
 *
 * It runs Python inside this process instead of starting a python binary, so macOS sees the
 * bundle, and the Location usage description in its Info.plist, as the program asking for
 * Location access. With no arguments it opens the desktop app. With arguments it behaves like
 * the python command, so debuggers can run the app inside the bundle too.
 */
#include <Python.h>
#include <string.h>

int main(int argc, char **argv)
{
    PyConfig config;
    PyConfig_InitPythonConfig(&config);

    /* Find the standard library and site-packages the way the virtualenv's python does. */
    PyStatus status = PyConfig_SetBytesString(&config, &config.executable, WIFIANALYZER_PYTHON);
    if (PyStatus_Exception(status)) goto fail;

    /* Finder passes no arguments (older macOS versions pass a process serial number). */
    if (argc < 2 || strncmp(argv[1], "-psn_", 5) == 0) {
        char *gui[] = {argv[0], "-m", "wifianalyzer.gui"};
        status = PyConfig_SetBytesArgv(&config, 3, gui);
    } else {
        status = PyConfig_SetBytesArgv(&config, argc, argv);
    }
    if (PyStatus_Exception(status)) goto fail;

    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) goto fail;
    PyConfig_Clear(&config);
    return Py_RunMain();

fail:
    PyConfig_Clear(&config);
    Py_ExitStatusException(status);
}
