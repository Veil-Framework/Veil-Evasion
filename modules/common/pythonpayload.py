"""

Abstract class to regroup all common options from python payloads

"""

class PythonPayload:
    def __init__(self):
        self.language = "python"
        self.extension = "py"
        self.required_python_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"],
                                    "ARCHITECTURE"   : ["32", "Select the final binary architecture (32, 64)"]
                                }

    def _validateArchitecture(self):
        if not self.required_options["ARCHITECTURE"][0] in ("32", "64"):
            print helpers.color("\n [!] ARCHITECTURE must either be set to 32 or 64.\n", warning=True)
            return ""
        self.architecture = self.required_options["ARCHITECTURE"][0]
