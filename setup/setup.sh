#!/bin/bash


# Global Variables
runuser="$(whoami)"
rootdir=$(cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd)
silent=false
os="$(awk -F '=' '/^ID=/ {print $2}' /etc/os-release 2>&-)"
version=$(awk -F '=' '/^VERSION_ID=/ {print $2}' /etc/os-release 2>&-)
arg=""
outputfolder="/usr/share/veil-output/"
BOLD="\033[01;01m"     # Highlight
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
RESET="\033[00m"       # Normal


########################################################################


# Title Function
func_title(){
  # Echo Title
  echo '=========================================================================='
  echo ' Veil-Evasion (Setup Script) | [Updated]: 2016-01-20'
  echo '=========================================================================='
  echo ' [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework'
  echo '=========================================================================='
  echo -e '\n'
}

# Environment Checks
func_check_env(){
  # Check Sudo Dependency
  which sudo >/dev/null 2>&-
  if [ "$?" -ne "0" ]; then
    echo ''
    echo -e ${RED}' [ERROR]: This Setup Script Requires sudo!'${RESET}
    echo '          Please Install and Configure sudo Then Run This Setup Again.'
    echo '          Example: For Debian/Ubuntu: apt-get -y install sudo'
    echo '                   For Fedora 22+: dnf -y install sudo'
    echo ''
    exit 1
  fi

  # Double Check Install
  if [ "${silent}" != "true" ]; then
    echo -e ${BOLD}'\n [?] Are you sure you wish to install Veil-Evasion?\n'${RESET}
    read -p ' Continue With Installation? ([y]es/[s]ilent/[N]o): ' installveil
    if [ "${installveil}" == 's' ]; then
      silent=true
    elif [ "${installveil}" != 'y' ]; then
      echo -e ${RED}'\n [ERROR]: Installation Aborted By User.\n'${RESET}
      exit 1
    fi
  fi

  func_package_deps

  # Check Capstone Dependency (Required For Backdoor Factory)
  if [ -f "/etc/ld.so.conf.d/capstone.conf" ]; then
    echo -e ${YELLOW}'\n\n [*] Capstone Is Already Installed... Skipping...'${RESET}
  else
    func_capstone_deps
  fi

  # Check If (Wine) Python Is Already Installed
  if [ -f ~/.wine/drive_c/Python27/python27.dll ] && [ -f ~/.wine/drive_c/Python27/python.exe ] && [ -f ~/.wine/drive_c/Python27/Lib/site-packages/win32/win32api.pyd ]; then
    echo -e ${YELLOW}'\n\n [*] (Wine) Python Already Installed... Skipping...'${RESET}
  else
    func_python_deps
  fi

  # Check If (Wine) Ruby Is Already Installed
  if [ -f ~/.wine/drive_c/Ruby187/bin/ruby.exe ] && [ -d ~/.wine/drive_c/Ruby187/lib/ruby/gems/1.8/gems/win32-api-1.4.8-x86-mingw32/lib/win32/ ]; then
    echo -e ${YELLOW}'\n\n [*] (Wine) Ruby Already Installed... Skipping...'${RESET}
  else
    func_ruby_deps
  fi

  # Check If Go Is Installed
  if [ -f "/usr/src/go/bin/windows_386/go.exe" ]; then
    echo -e ${YELLOW}'\n\n [*] Go is already installed... Skipping...'${RESET}
  else
    func_go_deps
  fi

  # Finally, Update The Config
  if [ -f "/etc/veil/settings.py" ] && [ -d "${outputfolder}" ]; then
    echo -e ${YELLOW}'\n\n [*] Setttings already detected... Skipping...'${RESET}
  else
    func_update_config
  fi
}

# Install Architecture Dependent Dependencies
func_package_deps(){
  echo -e ${YELLOW}'\n\n [*] Initializing Package Installation'${RESET}

  # Update Repository For Debian based OSs, yum/dnf doesn't need this step
  if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ]; then
    sudo apt-get -q update
    if [ "${silent}" == "true" ]; then
      echo -e ${YELLOW}'\n\n [*] Silent Mode: Enabled'${RESET}
      arg="DEBIAN_FRONTEND=noninteractive"
    fi
  fi

  # Check For 64-bit Kernel
  if [ $(uname -m) == 'x86_64' ]; then
    if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ]; then
      echo -e ${YELLOW}'\n\n [*] Adding i386 Architecture To x86_64 System'${RESET}
      sudo dpkg --add-architecture i386
      sudo apt-get -q update

      echo -e ${YELLOW}'\n\n [*] Installing (Wine) i386 Binaries'${RESET}
      sudo ${arg} apt-get -y install wine32   #wine-bin:i386
      tmp="$?"
      [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Wine x86_64... Exit Code: ${tmp}.${RESET}\n" && exit 1
    else
      echo -e '\n\n [*] Installing Wine 32-bit on x86_64 System'
      sudo dnf install -y wine.i686
      tmp="$?"
      [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Wine x86_64... Exit Code: ${tmp}.${RESET}\n" && exit 1
    fi
  fi

  # Start Dependency Install
  echo -e ${YELLOW}'\n\n [*] Installing Dependencies'${RESET}
  if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ]; then
    sudo ${arg} apt-get -y install mingw-w64 monodoc-browser monodevelop mono-mcs wine unzip ruby golang wget git \
                                   python python-crypto python-pefile python-pip ca-certificates ttf-mscorefonts-installer
  elif [ "${os}" == "fedora" ] || [ "${os}" == "rhel" ] || [ "${os}" == "centos" ]; then
    sudo ${arg} dnf -y install mingw64-binutils mingw64-cpp mingw64-gcc mingw64-gcc-c++ mono-tools-monodoc monodoc \
                               monodevelop mono-tools mono-core wine unzip ruby golang wget git python python-crypto python-pefile \
                               python-pip ca-certificates msttcore-fonts-installer
  fi
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Dependencies... Exit Code: ${tmp}.${RESET}\n" && exit 1

  if [ "${os}" == "kali" ]; then
    sudo ${arg} apt-get -y install metasploit-framework
    tmp="$?"
    [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Dependencies (Metasploit-Framework)... Exit Code: ${tmp}.${RESET}\n" && exit 1
  fi
}

# Install Capstone Dependencies (Needed for Backdoor Factory. https://github.com/secretsquirrel/the-backdoor-factory/blob/master/install.sh)
func_capstone_deps(){
  echo -e ${YELLOW}'\n\n [*] Installing Capstone Dependencies...'${RESET}
  if [ "${os}" == "kali" ]; then
    [[ "${silent}" == "true" ]] && arg="DEBIAN_FRONTEND=noninteractive"
    sudo ${arg} apt-get -y install python-capstone
  else
    which pip >/dev/null 2>&-
    if [ "$?" -eq 0 ]; then
      echo -e ${BOLD}' [*] Installing Capstone (via PIP)'${RESET}
      sudo pip install capstone
    else    # In theory, we should never end up here
      echo -e ${BOLD}' [*] Installing Capstone (via Source)'${RESET}
      git clone https://github.com/aquynh/capstone "${rootdir}/setup/capstone/"
      cd "${rootdir}/setup/capstone/"
      git checkout b53a59af53ffbd5dbe8dbcefba41a00cf4fc7469
      ./make.sh
      sudo ./make.sh install
      cd bindings/python/
      sudo make install
      cd "${rootdir}/setup/"
      sudo rm -rf "capstone/"
      echo -e ${YELLOW}'\n\n [*] Adding Capstone Library Path To /etc/ls.so.conf.d/capstone.conf'${RESET}
      sudo sh -c "echo '# Capstone Shared Libs' > /etc/ld.so.conf.d/capstone.conf"
      sudo sh -c "echo '/usr/lib64' >> /etc/ld.so.conf.d/capstone.conf"
      sudo ldconfig
    fi
  fi
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Capstone... Exit Code: ${tmp}.${RESET}\n" && exit 1
}

# Install Python Dependencies
func_python_deps(){
  echo -e ${YELLOW}'\n\n [*] Initializing (Wine) Python Dependencies Installation...'${RESET}

  # Check If SymmetricJSONRPC Is Already Installed
  if [ -d /usr/local/lib/python2.7/dist-packages/symmetricjsonrpc/ ]; then
    echo -e ${YELLOW}'\n\n [*] SymmetricJSONRPC Already Installed... Skipping...'${RESET}
  elif [ "${os}" == "kali" ]; then
    echo -e ${YELLOW}'\n\n [*] Installing SymmetricJSONRPC Dependency (via Repository)'${RESET}
    [[ "${silent}" == "true" ]] && arg="DEBIAN_FRONTEND=noninteractive"
    sudo ${arg} apt-get -y install python-symmetric-jsonrpc
  else
    echo -e ${YELLOW}'\n\n [*] Installing SymmetricJSONRPC Dependency (via PIP)...'${RESET}
    sudo pip install symmetricjsonrpc
    echo ''
  fi
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install SymmetricJSONRPC... Exit Code: ${tmp}.${RESET}\n" && exit 1

  # Incase Its 'First Time Run' for WINE (More information: http://wiki.winehq.org/Mono)
  [[ "${silent}" == "true" ]] && bash "${rootdir}/setup/install-addons.sh"   #wget -qO - "http://winezeug.googlecode.com/svn/trunk/install-addons.sh"
  wine cmd.exe /c ipconfig >/dev/null

  # Prepare (Wine) Directories - Required Before Python
  echo -e ${YELLOW}'\n\n [*] Preparing (Wine) Directories...'${RESET}
  mkdir -p ~/.wine/drive_c/Python27/Lib/site-packages/ ~/.wine/drive_c/Python27/Scripts/
  unzip -q -o -d ~/.wine/drive_c/Python27/Lib/ "${rootdir}/setup/python-distutils.zip"
  unzip -q -o -d ~/.wine/drive_c/Python27/ "${rootdir}/setup/python-tcl.zip"
  unzip -q -o -d ~/.wine/drive_c/Python27/ "${rootdir}/setup/python-Tools.zip"

  # Install Setup Files
  echo -e ${YELLOW}'\n\n [*] Installing (Wine) Python...'${RESET}
  echo -e ${BOLD}' [*] Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values.'${RESET}
  [ "${silent}" == "true" ] && arg="TARGETDIR=C:\Python27 ALLUSERS=1 /q"
  wine msiexec /i "${rootdir}/setup/python-2.7.5.msi" ${arg}
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install (Wine) Python 2.7.5... Exit Code: ${tmp}.${RESET}\n" && exit 1

  sleep 3s

  echo -e ${YELLOW}'\n\n [*] Installing (Wine) Python Dependencies...'${RESET}
  pushd "${rootdir}/setup/" >/dev/null
  for FILE in pywin32-219.win32-py2.7.exe pycrypto-2.6.win32-py2.7.exe; do
    echo -e "\n\n${YELLOW} [*] Installing Python's ${FILE}...${RESET}"
    if [ "${silent}" == "true" ]; then
      unzip -q -o "${FILE}"
      cp -rf PLATLIB/* ~/.wine/drive_c/Python27/Lib/site-packages/
      [ -e "SCRIPTS" ] && cp -rf SCRIPTS/* ~/.wine/drive_c/Python27/Scripts/
      rm -rf "PLATLIB/" "SCRIPTS/"
    else
      echo -e ${BOLD}' [*] Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values.'${RESET}
      wine "${FILE}"
      tmp="$?"
      [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install ${FILE}... Exit Code: ${tmp}.${RESET}\n" && exit 1
    fi
  done

  echo -e ${YELLOW}'\n\n [*] Installing (Wine) Python Dependencies - pywin32...'${RESET}
  echo -e ${BOLD}' [*] Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values.'${RESET}
  wine C://Python27//python.exe C://Python27//Scripts//pywin32_postinstall.py -install

  popd >/dev/null

  if [ "${os}" == "kali" ]; then
    echo -e ${YELLOW}'\n\n [*] Installing PyInstaller (via Repository)...'${RESET}
    [[ "${silent}" == "true" ]] && arg="DEBIAN_FRONTEND=noninteractive"
    sudo ${arg} apt-get -y install pyinstaller
    tmp="$?"
    [ "${tmp}" -ne "0" ] && echo -e " [ERROR] Failed To Install PyInstaller... Exit Code: ${tmp}.\n" && exit 1
  else
    if [ -d "/opt/pyinstaller-2.0/" ]; then
      echo -e ${YELLOW}'\n\n [*] PyInstaller Already Installed... Skipping...'${RESET}${RESET}
    else
      echo -e ${YELLOW}'\n\n [*] Installing PyInstaller (via ZIP)...'${RESET}
      sudo unzip -q -o -d /opt "${rootdir}/setup/pyinstaller-2.0.zip"
      sudo chmod -R 0755 /opt/pyinstaller-2.0/
    fi
  fi
}

# Install Go Dependencies (Requires v1.2 or higher)
func_go_deps(){
  # Download Go from source, cd into it, build it, and prep it for making windows payloads
  # help for this setup came from:
  # http://www.limitlessfx.com/cross-compile-golang-app-for-windows-from-linux.html

  echo -e ${YELLOW}'\n\n [*] Initializing Go Dependencies Installation...'${RESET}
  pushd "/tmp/" >/dev/null

  sudo mkdir -p /usr/src/go/

  if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ]; then
    goversion="$(apt-cache show golang-src | awk -F '[:-.]' '/Version/ {print $3$4}')"
    if [[ ! $(grep "#*deb-src" /etc/apt/sources.list) ]] && [ "${goversion}" -gt "12" ]; then
      # Download source via Repository
      echo -e "${BOLD} [*] Installing Go (v${goversion} via Repository)${RESET}"
      sudo apt-get source golang-go  #golang
      tmp="$?"
      [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Download Go... Exit Code: ${tmp}.${RESET}\n" && exit 1

      # Put Everything In One Place
      sudo cp -rn /tmp/golang-*/* /usr/src/go/
    fi
    [[ "${silent}" == "true" ]] && arg="DEBIAN_FRONTEND=noninteractive"
    sudo ${arg} apt-get -y install gccgo-5
    sudo update-alternatives --set go /usr/bin/go-5
  fi

  if [ ! -f "/usr/src/go/bin/windows_386/go.exe" ]; then
    echo -e "${BOLD} [*] Installing Go (via TAR)${RESET}"
    wget https://storage.googleapis.com/golang/go1.5.3.linux-amd64.tar.gz
    tar -C /usr/local -xvf go1.5.3.linux-amd64.tar.gz
    export GOROOT=/usr/local/go
    rm /usr/bin/go
    ln -s /usr/local/go/bin/go /usr/bin/go
  fi

  # Done
  popd >/dev/null
}

# Install (Wine) Ruby Dependencies
func_ruby_deps(){
  echo -e ${YELLOW}'\n\n [*] Initializing (Wine) Ruby Dependencies Installation...'${RESET}

  pushd "${rootdir}/setup/" >/dev/null

  # Install Ruby Under Wine
  echo -e ${YELLOW}'\n\n [*] Installing (Wine) Ruby & Dependencies'${RESET}
  echo -e ${BOLD}' [*] Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values.'${RESET}
  mkdir -p ~/.wine/drive_c/Ruby187/lib/ruby/gems/1.8/

  [ "${silent}" == "true" ] && arg="/silent"
  wine "${rootdir}/setup/rubyinstaller-1.8.7-p371.exe" "${arg}"
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install (Wine) Ruby.exe... Exit Code: ${tmp}.${RESET}\n" && exit 1

  # Install the OCRA Gem Under Wine
  wine ~/.wine/drive_c/Ruby187/bin/ruby.exe ~/.wine/drive_c/Ruby187/bin/gem install ocra-1.3.0.gem
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install (Wine) OCRA Gem... Exit Code: ${tmp}.${RESET}\n" && exit 1

  # Unzip the Ruby Dependencies
  unzip -q -o -d ~/.wine/drive_c/Ruby187/lib/ruby/gems/1.8/ "${rootdir}/setup/ruby_gems-1.8.zip"

  popd >/dev/null
}

# Update Veil Config
func_update_config(){
  # ./config/update.py
  echo -e ${YELLOW}'\n\n [*] Updating Veil-Framework Configuration...'${RESET}
  cd "${rootdir}/config/"
  sudo python update.py

  mkdir -p "${outputfolder}"

  # Chown Output Directory
  if [ -d "${outputfolder}" ]; then
    echo -e "\n\n [*] Ensuring this account (${runuser}) owns veil output directory (${outputfolder})..."
    sudo chown -R "${runuser}" "${outputfolder}"
  else
    echo -e " ${RED}[ERROR] Internal Issue. Couldn't create output folder...${RESET}\n"
  fi
}


########################################################################


# Print Banner
func_title


# Check OS
if [ -z "${os}" ] || [ -z "${version}" ]; then
  echo -e " ${RED}[ERROR] Internal Issue. Couldn't Detect OS Information...${RESET}\n"
  exit 1
elif [ "${os}" == "kali" ]; then
  echo " [i] Kali Linux ${version} $(uname -m) Detected..."
elif [ "${os}" == "ubuntu" ]; then
  version=$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)
  echo " [i] Ubuntu ${version} $(uname -m) Detected..."
  if [[ "${version}" -lt "14" ]]; then
    echo -e " [ERROR]: Veil-Evasion Only Supported On Ubuntu 14+.\n"
    exit 1
  fi
elif [ "${os}" == "debian" ]; then
  echo " [i] Debian ${version} $(uname -m) Detected..."
  if [ "${version}" -lt "7" ]; then
    echo -e " [ERROR]: Veil-Evasion Only Supported On Debian 7+.\n"
    exit 1
  fi
elif [ "${os}" == "fedora" ]; then
  if [[ "${version}" -lt "22" ]]; then
    echo -e " [ERROR]: Veil-Evasion only supported on Fedora 22+.\n"
    exit 1
  fi
fi


# Menu Case Statement
case $1 in
  # Make Sure Not To Nag The User
  -s|--silent)
    silent=true
    func_check_env
    ;;

  # Force Clean Install Of (Wine) Python Dependencies
  # Bypass Environment Checks (func_check_env) To Force Install Dependencies
  -c|--clean)
    func_package_deps
    func_capstone_deps
    func_python_deps
    func_ruby_deps
    func_go_deps
    func_update_config
    ;;

  # Print Help Menu
  -h|--help)
    echo ''
    echo "  [Usage]....: ${0} [OPTIONAL]"
    echo '  [Optional].:'
    echo '               -c|--clean    = Force Clean Install Of Any Dependencies'
    echo '               -s|--silent   = Automates the installation'
    echo '               -h|--help     = Show This Help Menu'
    echo ''
    exit 0
    ;;

  # Run Standard Setup
  "")
    func_check_env
  ;;

  *)
    echo -e "\n\n [ERROR] Unknown Option: $1"
    exit 1
    ;;
esac

file=$(dirname "$(readlink -f "$0")")"/setup.sh"
echo -e '\n\n [i] If you have any errors running Veil-Evasion, delete your WINE profile (rm -rf ~/.wine/) and re-run: '${file}
echo -e '\n\n [i] Done!'
exit 0
