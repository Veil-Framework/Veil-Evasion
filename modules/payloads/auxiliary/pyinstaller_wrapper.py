"""

Simple auxiliary module that will take a specified python source
file and compile it to an executable using Pyinstaller.

by @harmj0y

"""

from modules.common import helpers
from modules.common import encryption
from modules.common.pythonpayload import PythonPayload
import settings

class Payload(PythonPayload):

    def __init__(self):
        # pull in shared options
        PythonPayload.__init__(self)

        # required options
        self.description = "Auxiliary pyinstaller wrapper for python source files"
        self.language = "python"
        self.rating = "Normal"
        self.extension = "py"

        self.required_options = {
                                    "PYTHON_SOURCE" : ["", "A Python source file to compile with pyinstaller"]   # /path/to/any/python/file.py
                                }
        self.required_options.update(self.required_python_options)

    def generate(self):
        self._validateArchitecture()

        PYTHON_SOURCE = self.required_options["PYTHON_SOURCE"][0]

        try:
            # read in the python source
            f = open(PYTHON_SOURCE, 'r')
            PayloadCode = f.read()
            f.close()
        except IOError:
            print helpers.color("\n [!] PYTHON_SOURCE file \""+PYTHON_SOURCE+"\" not found\n", warning=True)
            return ""

        # example of how to check the internal options
        if self.required_options["USE_PYHERION"][0].lower() == "y":
            PayloadCode = encryption.pyherion(PayloadCode)

        # return everything
        return PayloadCode
