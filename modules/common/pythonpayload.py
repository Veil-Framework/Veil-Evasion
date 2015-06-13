"""

Abstract class to regroup all common options from python payloads

"""

class PythonPayload:
    def __init__(self):
        self.language = "python"
        self.extension = "py"
        self.required_options = {"compile_to_exe" : ["Y", "Compile to an executable"],
                                 "use_pyherion"   : ["N", "Use the pyherion encrypter"],
                                 "architecture"   : ["32", "Select the final binary architecture"]
                                }

    def _validateArchitecture(self):
        if not self.required_options["architecture"][0] in ("32", "64"):
            print helpers.color("\n [!] architecture must either be set to 32 or 64.\n", warning=True)
            return ""
        self.architecture = self.required_options["architecture"][0]
