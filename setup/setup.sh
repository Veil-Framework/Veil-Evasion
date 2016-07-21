#!/bin/bash


# Global Variables
arch="$(uname -m)"
# Edge cases... urgh. There *was* a reason it's like this. It'll get tested further
# later and get cleaned up as required in a later patch.
nukewinedir=""
silent=false
os="$(awk -F '=' '/^ID=/ {print $2}' /etc/os-release 2>&-)"
version=$(awk -F '=' '/^VERSION_ID=/ {print $2}' /etc/os-release 2>&-)
arg=""
outputfolder="/usr/share/veil-output/"
runuser="$(whoami)"
if [ "${os}" == "ubuntu" ] || [ "${os}" == "arch" ]; then
  trueuser="$(who | tr -d '\n' | awk '{print $1}')"
else
  trueuser="$(who am i | awk '{print $1}')" # if this is blank, we're actually root (kali)
fi
if [ "$runuser" == "root" ] && [ "$trueuser" == "" ]; then
  trueuser="root"
fi
if [ "$trueuser" != "root" ]; then
  userhomedir=$(echo /home/${trueuser})
else
  userhomedir=$HOME
fi
userprimarygroup="$(id -Gn "${trueuser}" | awk '{print $1}')"
rootdir=$(cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd)
winedir="${userhomedir}/.config/wine/veil"
winedrive="${userhomedir}/.config/wine/veil/drive_c"
WINEPREFIX="${userhomedir}/.config/wine/veil"
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
  echo ' Veil-Evasion (Setup Script) | [Updated]: 2016-02-23'
  echo '=========================================================================='
  echo ' [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework'
  echo '=========================================================================='
  echo -e '\n'
  #echo -e "Debug:       WINEPREFIX = ${WINEPREFIX}"
  #echo -e "Debug:          winedir = ${winedir}"
  #echo -e "Debug:        winedrive = ${winedrive}"
  #echo -e "Debug:      userhomedir = ${HOME}"
  #echo -e "Debug:          rootdir = ${rootdir}"
  #echo -e "Debug:         trueuser = ${trueuser}"
  #echo -e "Debug: userprimarygroup = ${userprimarygroup}"
  #echo -e "Debug:               os = ${os}"
  #echo -e "Debug:          version = ${version}"
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
    exit 1
  fi

  # Double Check Install
  if [ "${silent}" != "true" ]; then
    if [ ${os} != "kali" ] || [ "${os}" == "parrot" ]; then
      echo -e "${BOLD} [!] NON-KALI Users: Before you begin the install, make sure that you have"
      echo -e "     the metasploit framework installed before you proceed!\n${RESET}"
    fi
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
  if [ -f ${winedrive}/Python27/python27.dll ] && [ -f ${winedrive}/Python27/python.exe ] && [ -f ${winedrive}/Python27/Lib/site-packages/win32/win32api.pyd ]; then
    echo -e ${YELLOW}'\n\n [*] (Wine) Python Already Installed... Skipping...'${RESET}
  else
    func_python_deps
  fi

  # Check If (Wine) Ruby Is Already Installed
  if [ -f ${winedrive}/Ruby187/bin/ruby.exe ] && [ -d ${winedrive}/Ruby187/lib/ruby/gems/1.8/gems/win32-api-1.4.8-x86-mingw32/lib/win32/ ]; then
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
  echo -e "\n\n [*] ${YELLOW}Initializing Package Installation${RESET}"

  # Begin Wine install for multiple architectures
  # Always install 32bit support for 64bit architectures

  # Debian based distributions
  if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ] || [ "${os}" == "parrot" ]; then

    if [ "${silent}" == "true" ]; then
      echo -e "\n\n [*]${YELLOW} Silent Mode: Enabled ${RESET}"
      arg="DEBIAN_FRONTEND=noninteractive"
    fi

    if [ "${arch}" == "x86_64" ]; then
      echo -e "\n [*] ${YELLOW}Adding x86 Architecture To x86_64 System for Wine${RESET}"
      sudo dpkg --add-architecture i386
      sudo apt-get -qq update
      echo -e " [*] ${YELLOW}Installing Wine 32bit and 64bit Binaries${RESET}"
      if [ "${os}" != "ubuntu" ]; then
        sudo ${arg} apt-get -y -qq install wine wine64 wine32
      else # Special snowflakes... urghbuntu
        sudo ${arg} apt-get -y -qq install wine wine1.6 wine1.6-i386
      fi
      tmp="$?"
      [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed to install Wine... Exit Code: ${tmp}.${RESET}\n" && exit 1
    elif [ "${arch}" == "x86" ] || [ "${arch}" == "i686" ]; then
      sudo apt-get -qq update
      sudo ${arg} apt-get -y -qq install wine32
      tmp="$?"
      [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Wine... Exit Code: ${tmp}.${RESET}\n" && exit 1
    else # Dead code. We really shouldn't end up here, but, you never know...
      "${RED} [!] CRITICAL ERROR: Architecture ${arch} is not supported!"
      exit 1
    fi
    # Red Hat based distributions
  elif [ "${os}" == "fedora" ] || [ "${os}" == "rhel" ] || [ "${os}" == "centos" ]; then
    echo -e "${YELLOW}\n\n [*] Installing Wine 32-bit on x86_64 System${RESET}\n"
    sudo dnf install -y wine.i686 wine
    tmp="$?"
    [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Wine x86_64... Exit Code: ${tmp}.${RESET}\n" && exit 1
  elif [ "$os" == "arch" ]; then
    if grep -Fxq "#[multilib]" /etc/pacman.conf; then
      echo "[multilib]\nInclude = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
    fi
    sudo pacman -Syu ${args} --needed --noconfirm wine wine-mono wine_gecko git
    tmp="$?"
    [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Wine x86_64... Exit Code: ${tmp}.${RESET}\n" && exit 1
  fi

  # Setup Wine prefices
  # Because Veil currently only supports Win32 binaries, we have to set the WINEARCH PREFIX
  # to use Win32. This is a potential issue for the future when Veil has windows 64bit 
  # binary support. To get around this in setup and somewhat future proof for that eventuality, 
  # we're already going to look for an existing veil wine setup (~/.config/veil/) and nuke it 
  # making it easy for a user to rerun the setup and have a new wine environment.
  if [ -d "${winedir}" ]; then
    echo -e "\n\n [*]${RED} ALERT: Existing Veil Wine environment detected at ${winedir}${RESET}\n"
    read -p "            Do you want to nuke it? (recommended) [Y/n]: " nukewinedir
    if [ "${nukewinedir}" == 'y' ] || [ "${nukewinedir}" == 'Y' ]; then
      echo -e "\n\n [*]${YELLOW} Deleting existing Veil Wine environment...${RESET}\n"
      rm -rf "${winedir}"
    else
      echo -e " [*] ${YELLOW} Maintaining current Veil Wine environment...${RESET}"
    fi
  fi

  # For creating wine environment on newer distros
  if [ -f "/usr/bin/wineboot" ]; then
    winebootexists=true
  else
    winebootexists=false
  fi

  if [ "${nukewinedir}" == 'y' ] || [ ! -d "${winedir}" ] || [ "${nukewinedir}" == 'Y' ]; then
    echo -e " [*]${YELLOW} Creating new Veil Wine environment in ${winedir} ${RESET}"
    if [ "${arch}" == "x86_64" ]; then
      echo -e " [*]${YELLOW} Initializing Veil's Wine environment...${RESET}"
      if [ $winebootexists == true ]; then
        sudo -u ${trueuser} mkdir -p "${winedrive}"
        sudo -u ${trueuser} WINEARCH=win32 WINEPREFIX="${WINEPREFIX}" wineboot -u
      else
        sudo -u ${trueuser} WINEARCH=win32 WINEPREFIX="${WINEPREFIX}" wine cmd.exe /c ipconfig >/dev/null
      fi
      # Sorta-kinda check for the existence of the wine drive
      if [ -d "${winedrive}" ]; then
        echo -e " [*]${GREEN} Veil Wine environment successfully created!\n${RESET}"
      else
        echo -e " [ERROR]${RED} Veil Wine environment could not be found!\n${RESET}"
        echo -e "${RED}         Check for existence of ${winedrive}\n${RESET}"
        exit 1
      fi
    elif [ "${arch}" == "x86" ] || [ "${arch}" == "i686" ]; then
      echo -e "${YELLOW} [*] Initializing Veil's Wine environment...${RESET}\n"
      sudo -u ${trueuser} WINEPREFIX=${winedir} wineboot -u
      if [ -d "${winedrive}" ]; then
        echo -e "${GREEN} Veil Wine environment successfully created!\n${RESET}"
      else
        echo -e "${RED} [ERROR] Veil Wine environment could not be found!"
        echo -e "${RED}         Check for existence of ${winedrive}\n${RESET}"
      fi
    fi
  fi

  # Start Dependency Install
  echo -e ${YELLOW}'\n\n [*] Installing Dependencies'${RESET}
  if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ] || [ "${os}" == "parrot" ]; then
    sudo ${arg} apt-get -y install mingw-w64 monodoc-browser monodevelop mono-mcs wine unzip ruby golang wget git \
      python python-crypto python-pefile python-pip ca-certificates #ttf-mscorefonts-installer
  elif [ "${os}" == "fedora" ] || [ "${os}" == "rhel" ] || [ "${os}" == "centos" ]; then
    sudo ${arg} dnf -y install mingw64-binutils mingw64-cpp mingw64-gcc mingw64-gcc-c++ mono-tools-monodoc monodoc \
      monodevelop mono-tools mono-core wine unzip ruby golang wget git python python-crypto python-pefile \
      python-pip ca-certificates msttcore-fonts-installer
  elif [ "${os}" ==  "arch" ]; then
    sudo pacman -Sy ${arg} --needed mingw-w64-binutils mingw-w64-crt mingw-w64-gcc mingw-w64-headers mingw-w64-mingw-w64-winpthreads \
      mono mono-tools mono-addins python2-pip wget unzip ruby python python2 python-crypto gcc-go ca-certificates base-devel
    # Install pefile for python2 using pip, rather than via AUR as the package is currently broken.
    sudo pip2 install pefile
  fi
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Dependencies... Exit Code: ${tmp}.${RESET}\n" && exit 1

  if [ "${os}" == "kali" ] || [ "${os}" == "parrot" ]; then
    sudo ${arg} apt-get -y install metasploit-framework
    tmp="$?"
    [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install Dependencies (Metasploit-Framework)... Exit Code: ${tmp}.${RESET}\n" && exit 1
  fi
}

# Install Capstone Dependencies (Needed for Backdoor Factory. https://github.com/secretsquirrel/the-backdoor-factory/blob/master/install.sh)
func_capstone_deps(){
  echo -e "\n [*] ${YELLOW}Installing Capstone Dependencies...${RESET}"
  if [ "${os}" == "kali" ] || [ "${os}" == "parrot" ]; then
    [[ "${silent}" == "true" ]] && arg="DEBIAN_FRONTEND=noninteractive"
    sudo ${arg} apt-get -y install python-capstone
  else
    which pip2 >/dev/null 2>&-
    if [ "$?" -eq 0 ]; then
      echo -e ${BOLD}' [*] Installing Capstone (via PIP)'${RESET}
      sudo pip2 install capstone
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
      echo -e "\n [*] ${YELLOW}Adding Capstone Library Path To /etc/ld.so.conf.d/capstone.conf${RESET}"
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
  echo -e "\n [*] ${YELLOW}Initializing (Wine) Python Dependencies Installation...${RESET}"

  # Check If SymmetricJSONRPC Is Already Installd - If not, install it.
  pythonversion=$(python -c "import sys;t='{v[0]}.{v[1]}'.format(v=list(sys.version_info[:2]));sys.stdout.write(t)")
  pypkgdir=("/usr/local/lib/python${pythonversion}/dist-packages/symmetricjsonrpc/"
  "/usr/local/lib/python${pythonversion}/site-packages/symmetricjsonrpc/"
  "/usr/lib/python${pythonversion}/dist-packages/symmetricjsonrpc/"
  "/usr/lib/python${pythonversion}/site-packages/symmetricjsonrpc/")

  for ((i = 0; i < ${#pypkgdir[@]}; i++)); do
    if [ -d ${pypkgdir[$i]} ]; then
      echo "[I] Found SymmetricJSONRPC already installed in ${pypkgdir[$i]}"
      break
    else
      if [ ${os} == "kali" ] || [ "${os}" == "parrot" ]; then
        echo -e "\n [*] ${YELLOW}Installing SymmetricJSONRPC Dependency (via repository)${RESET}"
        [[ "${silent}" == "true" ]] && arg="DEBIAN_FRONTEND=noninteractive"
        sudo ${arg} apt-get install -y python-symmetric-jsonrpc
      else
        echo -e "\n [*] ${YELLOW}Installing SymmetricJSONRPC Dependency (via PIP)...${RESET}"
        sudo pip2 install symmetricjsonrpc
      fi
    fi
  done
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " [ERROR]${RED} Failed To Install SymmetricJSONRPC... Exit Code: ${tmp}.${RESET}\n" && exit 1

  # Incase Its 'First Time Run' for WINE (More information: http://wiki.winehq.org/Mono)
  [[ "${silent}" == "true" ]] && bash "${rootdir}/setup/install-addons.sh"   #wget -qO - "http://winezeug.googlecode.com/svn/trunk/install-addons.sh"

  # Prepare (Wine) Directories - Required Before Python
  echo -e "${YELLOW}\n [*] Preparing Wine Python Directories...${RESET}"
  sudo -u ${trueuser} mkdir -p "${winedrive}/Python27/Lib/site-packages/" "${winedrive}/Python27/Scripts/"
  sudo -u ${trueuser} unzip -q -o -d "${winedrive}/Python27/Lib/" "${rootdir}/setup/python-distutils.zip"
  sudo -u ${trueuser} unzip -q -o -d "${winedrive}/Python27/" "${rootdir}/setup/python-tcl.zip"
  sudo -u ${trueuser} unzip -q -o -d "${winedrive}/Python27/" "${rootdir}/setup/python-Tools.zip"

  # Install Setup Files
  echo -e "\n [*]${YELLOW} Installing (Wine) Python...${RESET}"
  echo -e "${BOLD} [*] Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values.${RESET}\n"
  [ "${silent}" == "true" ] && arg="TARGETDIR=C:\Python27 ALLUSERS=1 /q"
  sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine msiexec /i "${rootdir}/setup/python-2.7.5.msi ${arg}"
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " [ERROR] ${RED}Failed To Install (Wine) Python 2.7.5... Exit Code: ${tmp}.${RESET}\n" && exit 1

  sleep 3s

  echo -e "\n [*] ${YELLOW}Installing (Wine) Python Dependencies...${RESET}"
  pushd "${rootdir}/setup/" >/dev/null
  for FILE in pywin32-219.win32-py2.7.exe pycrypto-2.6.win32-py2.7.exe; do
    echo -e "\n\n${YELLOW} [*] Installing Python's ${FILE}...${RESET}"
    if [ "${silent}" == "true" ]; then
      sudo -u ${trueuser} unzip -q -o "${FILE}"
      sudo -u ${trueuser} cp -rf PLATLIB/* ${winedrive}/Python27/Lib/site-packages/
      [ -e "SCRIPTS" ] && sudo -u ${trueuser} cp -rf SCRIPTS/* ${winedrive}/Python27/Scripts/
      rm -rf "PLATLIB/" "SCRIPTS/"
    else
      echo -e "[*] ${BOLD} Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values.\n${RESET}"
      sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine "${FILE}"
      tmp="$?"
      [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install ${FILE}... Exit Code: ${tmp}.${RESET}\n" && exit 1
    fi
  done

  echo -e " [*]${YELLOW} Installing (Wine) Python Dependencies - pywin32...${RESET}"
  echo -e " [*] ${BOLD} Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values. ${RESET}\n"
  sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine "${WINEPREFIX}//Python27//python.exe" "pefile-2016.3.28/setup.py -install"

  popd >/dev/null

  # Start the pyinstaller processpip
  echo -e '\n\n [*] Installing PyInstaller (via Repos)'
  [[ "${silent}" == "true" ]] && arg="DEBIAN_FRONTEND=noninteractive"
  if [ -f "/usr/share/pyinstaller/PKG-INFO" ]; then
    pyinstversion=`sed -n '3{p;q;}' /usr/share/pyinstaller/PKG-INFO | cut -d' ' -f2`
    if [ "$pyinstversion" == "3.2" ]; then
      echo "PyInstaller version 3.2 is already installed, skipping!"
    else
      # Install pyinstaller now
      wget https://www.veil-framework.com/InstallMe/PyInstaller-3.2.tar.gz
      shasum3=`openssl dgst -sha256 PyInstaller-3.2.tar.gz | cut -d' ' -f2`
      if [ "$shasum3" == "7598d4c9f5712ba78beb46a857a493b1b93a584ca59944b8e7b6be00bb89cabc" ]; then
        sudo rm -rf /usr/share/pyinstaller
        tar -xvf PyInstaller-3.2.tar.gz
        sudo mv PyInstaller-3.2 /usr/share/pyinstaller
      else
        echo "Bad hash for PyInstaller!  Please try again for inform the developer!"
      fi
    fi
  else
    # Install pyinstaller now
    wget https://www.veil-framework.com/InstallMe/PyInstaller-3.2.tar.gz
    shasum3=`openssl dgst -sha256 PyInstaller-3.2.tar.gz | cut -d' ' -f2`
    if [ "$shasum3" == "7598d4c9f5712ba78beb46a857a493b1b93a584ca59944b8e7b6be00bb89cabc" ]; then
      sudo rm -rf /usr/share/pyinstaller
      tar -xvf PyInstaller-3.2.tar.gz
      sudo mv PyInstaller-3.2 /usr/share/pyinstaller
    else
      echo "Bad hash for PyInstaller!  Please try again for inform the developer!"
    fi
  fi

  # Install PEFile for PyInstaller
  wget https://www.veil-framework.com/InstallMe/pefile-2016.3.28.tar.gz
  shasum4=`openssl dgst -sha256 pefile-2016.3.28.tar.gz | cut -d' ' -f2`
  if [ "$shasum4" == "f24021085b5c3ef7b0898bb1f1d93eecd3839e03512769e22b0c5a10d9095f7b" ]; then
    tar -xvf pefile-2016.3.28.tar.gz
    sudo chown -R $trueuser pefile-2016.3.28
    cd pefile-2016.3.28
    sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine ${winedrive}/Python27/python.exe $rootdir/setup/pefile-2016.3.28/setup.py install
    cd ..
  else
    echo "Bad hash for PEFile!  Please try again for inform the developer!"
  fi

  # Install Futures for PyInstaller
  wget https://www.veil-framework.com/InstallMe/future-0.15.2.tar.gz
  shasum5=`openssl dgst -sha256 future-0.15.2.tar.gz | cut -d' ' -f2`
  if [ "$shasum5" == "3d3b193f20ca62ba7d8782589922878820d0a023b885882deec830adbf639b97" ]; then
    tar -xvf future-0.15.2.tar.gz
    sudo chown -R $trueuser future-0.15.2
    cd future-0.15.2
    sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine ${winedrive}/Python27/python.exe $rootdir/setup/future-0.15.2/setup.py install
    cd ..
  else
    echo "Bad hash for Futures!  Please try again for inform the developer!"
  fi

  # Check to see if setup tools is available, if not, install it.
  if [ ! -f "${winedrive}/Python27/Lib/site-packages/setuptools-0.6c11-py2.7.egg-info" ]; then
    wget https://www.veil-framework.com/InstallMe/distribute_setup.py
    sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine ${winedrive}/Python27/python.exe distribute_setup.py
    rm distribute_setup.py
  fi
}

# Install Go Dependencies (Requires v1.2 or higher)
func_go_deps(){
  # Download Go from source, cd into it, build it, and prep it for making windows payloads
  # help for this setup came from:
  # http://www.limitlessfx.com/cross-compile-golang-app-for-windows-from-linux.html

  echo -e " [*]${YELLOW} Initializing Go Dependencies Installation...${RESET}"
  pushd "/tmp/" >/dev/null

  sudo mkdir -p /usr/src/go/

  if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ] || [ "${os}" == "parrot" ]; then
    goversion="$(apt-cache show golang-src | awk -F '[:-.]' '/Version/ {print $3$4}')"
    if [[ ! $(grep "#*deb-src" /etc/apt/sources.list) ]] && [ "${goversion}" -gt "12" ]; then
      # Download source via Repository
      echo -e " [*]${BOLD} Installing Go (v${goversion} via Repository)${RESET}"
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
    echo -e " [*]${BOLD} Installing Go (via TAR)${RESET}"
    if [ ${arch} == 'x86_64' ]; then
      wget https://www.veil-framework.com/InstallMe/go153x64.tar.gz
      shasum1=`openssl dgst -sha256 go153x64.tar.gz | cut -d' ' -f2`
      if [ "$shasum1" == "43afe0c5017e502630b1aea4d44b8a7f059bf60d7f29dfd58db454d4e4e0ae53" ]; then
        sudo tar -C /usr/local -xvf go153x64.tar.gz
        sudo rm go153x64.tar.gz
      else
        echo "${RED}HASH MISMATCH!  Run again, or alert developer!!!!${RESET}"
        exit
      fi
    fi
    if [ "${arch}" == "x86" ] || [ "${arch}" == "i686" ]; then
      wget https://www.veil-framework.com/InstallMe/go153x86.tar.gz
      shasum2=`openssl dgst -sha256 go153x86.tar.gz | cut -d' ' -f2`
      if [ "$shasum2" == "c1ce206b7296db1b10ff7896044d9ca50e87efa5bc3477e8fd8c2fb149bfca8f" ]; then
        sudo tar -C /usr/local -xvf go153x86.tar.gz
        sudo rm go153x86.tar.gz
      else
        echo "${RED}HASH MISMATCH!  Run again, or alert developer!!!!${RESET}"
        exit
      fi
    fi
    export GOROOT=/usr/local/go
    sudo rm /usr/bin/go
    sudo ln -s /usr/local/go/bin/go /usr/bin/go
  fi

  # Done
  popd >/dev/null
}

# Install (Wine) Ruby Dependencies
func_ruby_deps(){
  echo -e "\n [*] ${YELLOW}Initializing (Wine) Ruby Dependencies Installation...${RESET}"

  pushd "${rootdir}/setup/" >/dev/null

  # Install Ruby Under Wine
  echo -e "\n [*] ${YELLOW}Installing (Wine) Ruby & Dependencies${RESET}"
  echo -e ${BOLD}' [*] Next -> Next -> Next -> Finished! ...Overwrite if prompt. Use default values.'${RESET}
  sudo -u ${trueuser} mkdir -p "${winedrive}/Ruby187/lib/ruby/gems/1.8/"

  [ "${silent}" == "true" ] && arg="/silent"
  sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine "${rootdir}/setup/rubyinstaller-1.8.7-p371.exe ${arg}"
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install (Wine) Ruby.exe... Exit Code: ${tmp}.${RESET}\n" && exit 1

  # Install the OCRA Gem Under Wine
  echo -e " [*]${YELLOW} Installing Wine Ruby OCRA gem...${RESET}"
  sudo -u ${trueuser} WINEPREFIX=${WINEPREFIX} wine "${winedrive}/Ruby187/bin/ruby.exe" "${winedrive}/Ruby187/bin/gem" install ocra-1.3.0.gem 
  tmp="$?"
  [ "${tmp}" -ne "0" ] && echo -e " ${RED}[ERROR] Failed To Install (Wine) OCRA Gem... Exit Code: ${tmp}.${RESET}\n" && exit 1

  # Unzip the Ruby Dependencies
  echo -e " [*]${YELLOW} Extracting Wine Ruby dependencies...${RESET}"
  sudo -u ${trueuser} unzip -q -o -d "${winedrive}/Ruby187/lib/ruby/gems/1.8/" "${rootdir}/setup/ruby_gems-1.8.zip"

  popd >/dev/null
}

# Update Veil Config
func_update_config(){
  echo -e "\n [*] ${YELLOW}Updating Veil-Framework Configuration...${RESET}"
  cd "${rootdir}/config/"

  # SUDOINCEPTION! (There is method behind the, at first glance, madness)
  # The SUDO_USER environment variable of the actual user doesn't get passed on to the python interpreter properly,
  # so when we call "sudo python update.py", it thinks the user calling it, it's interpretation of SUDO_USER is root,
  # and that's not what we want. Look at this fake process tree with what the env variables would be...
  #    - |_ sudo setup.sh ($USER=root $SUDO_USER=yourname)
  #      - | sudo -u yourname sudo python update.py ($USER=root $SUDO_USER=yourname)
  # snip 8<-  -  -  -  -  -  -  -  -  -  -  -  -  - The alternative below without "sudo -u username"...
  #      - | sudo python update.py ($USER=root $SUDO_USER=root)
  # snip 8<-  -  -  -  -  -  -  -  -  -  -  -  -  - And thus it would have screwed up the $WINEPREFIX dir for the user.
  if [ -f /etc/veil/settings.py ]; then
    echo -e " [*] ${YELLOW}Detected current Veil Framework settings file. Removing...${RESET}"
    rm /etc/veil/settings.py
  fi
  sudo -u ${trueuser} sudo python2 update.py
  

  mkdir -p "${outputfolder}"

  # Chown Output Directory
  if [ -d "${outputfolder}" ]; then
    echo -e "\n [*] ${YELLOW}Ensuring this account (${trueuser}) owns veil output directory (${outputfolder})...${RESET}"
    sudo chown -R "${trueuser}" "${outputfolder}"
  else
    echo -e " ${RED}[ERROR] Internal Issue. Couldn't create output folder...${RESET}\n"
  fi

  # Ensure that user completely owns the wine directory
  echo -e " [*] ${YELLOW}Ensuring this account (${trueuser}) has correct ownership of ${winedir}${RESET}"
  chown -R ${trueuser}:${userprimarygroup} ${winedir}
}

########################################################################


# Print Banner
func_title

# Check Architecture
if [ "${arch}" != "x86" ] && [ "${arch}" != "i686" ] && [ "${arch}" != "x86_64" ]; then
  echo -e "${RED} [ERROR] Your architecture ${arch} is not supported!\n\n${RESET}"
  exit 1
fi

# Check OS
if [ "${os}" == "kali" ]; then
  echo -e " [I]${YELLOW} Kali Linux ${version} ${arch} Detected...${RESET}\n"
elif [ "${os}" == "parrot" ]; then
  echo -e " [I]${YELLOW} Parrot Security ${version} ${arch} Detected...${RESET}\n"
elif [ "${os}" == "ubuntu" ]; then
  version=$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)
  echo -e " [I] ${YELLOW}Ubuntu ${version} ${arch} Detected...${RESET}\n"
  if [[ "${version}" -lt "15" ]]; then
    echo -e "${RED} [ERROR]: Veil-Evasion Only Supported On Ubuntu 15.10+.\n${RESET}"
    exit 1
  fi
elif [ "${os}" == "debian" ]; then
  version=$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)
  if [ ${version} -lt 8 ]; then
    echo -e " [ERROR]${red} Only Debian 8 (Jessie) and above are supported!\n"
    exit 1
  fi
elif [ "${os}" == "fedora" ]; then
  echo "${YELLOW} [I] Fedora ${version} ${arch} detected...\n${RESET}"
  if [[ "${version}" -lt "22" ]]; then
    echo -e "${RED} [ERROR]: Veil-Evasion only supported on Fedora 22+.\n${RESET}"
    exit 1
  fi
else
  os=$(awk -F '["=]' '/^ID=/ {print $2}' /etc/os-release 2>&- | cut -d'.' -f1)
  if [ ${os} == "arch" ]; then
    echo -e " [I] ${YELLOW}Arch Linux ${arch} detected...\n${RESET}"
  elif [ ${os} == "debian" ]; then
    echo -e " [!] ${RED}Debian Linux sid/TESTING ${arch} *possibly* detected..."
    echo - "      If you are not currently running Debian Testing, you should exit this installer!\n${RESET}"
  else
    echo -e " [!] ${RED}Unable to determine OS information. Exiting...\n${RESET}"
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
echo -e "\n [I] If you have any errors running Veil-Evasion, delete the Veil Wine profile (rm -rf '${winedir}') and re-run: '${file}"
echo -e "\n [I] ${GREEN}Done!${RESET}"
exit 0
