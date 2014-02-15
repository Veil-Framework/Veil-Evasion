"""

Simple auxiliary module that will take a specified python source
file and compile it to an executable using Pyinstaller.

by @harmj0y

"""

from modules.common import helpers
import settings

class Payload:
    
    def __init__(self):
        # required options
        self.description = "Auxiliary pyinstaller wrapper for python source files"
        self.language = "python"
        self.rating = "Normal"
        self.extension = "py"
        
        self.required_options = {   "python_source"  :  ["", "Python source file to compile with pyinstaller"],
                                    "compile_to_exe" :  ["Y", "Compile to an executable"],
                                    "use_pyherion"   :  ["N", "Use the pyherion encrypter"] }


    def generate(self):

        python_source = self.required_options["python_source"][0]
        
        try:
            # read in the python source
            f = open(python_source, 'r')
            PayloadCode = f.read()
            f.close()
        except IOError:
            print helpers.color("\n [!] python_source file \""+python_source+"\" not found\n", warning=True)
            return ""
        
        
        # example of how to check the internal options
        if self.required_options["use_pyherion"][0].lower() == "y":
            PayloadCode = encryption.pyherion(PayloadCode)

        # return everything
        return PayloadCode
