#!/bin/bash

# Global Variables
runuser="$(whoami)"
rootdir=$(cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd)
silent=false
os=""
version=""
arg=""

# Title Function
func_title(){
  # Clear (For Prettyness)
  echo -e '\n\n\n'

  # Echo Title
  echo '=========================================================================='
  echo ' Veil-Evasion Setup Script | [Updated]: 2015-06-27'
  echo '=========================================================================='
  echo ' [Web]: https://www.veil-framework.com | [Twitter]: @VeilFramework'
  echo '=========================================================================='
}

# Environment Checks
func_check_env(){
  # Check Sudo Dependency
  which sudo >/dev/null 2>&-
  if [ "$?" -ne "0" ]; then
    echo ''
    echo ' [ERROR]: This Setup Script Requires sudo!'
    echo '          Please Install and Configure sudo Then Run This Setup Again.'
    echo '          Hint: apt-get -y -q install sudo'
    echo ''
    exit 1
  fi

  # Check Running User ???
  if [[ "${silent}" != "true" ]]; then
    echo -e '\n [?] Are you sure you wish to install Veil-Evasion?\n'
    read -p ' Continue With Installation? (y/N): ' rootonly
    if [[ "${rootonly}" != 'y' ]]; then
      echo -e '\n [ERROR]: Installation Aborted By User.\n'
      exit 1
    fi
  fi

  # Check OS & Version
  os="$(awk -F '=' '/^ID=/ {print $2}' /etc/os-release 2>&-)"
  version=$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&-)
  echo ''
  if [ -z "${os}" ] || [ -z "${version}" ]; then
    echo -e " [ERROR] Internal Issue. Couldn't Detect OS Information...\n"
    exit 1
  elif [ "${os}" == "kali" ]; then
    echo " [i] Kali Linux ${version} Detected..."
  elif [ "${os}" == "ubuntu" ]; then
    echo " [i] Ubuntu ${version} Detected..."
    if [[ "${version}" -lt "14" ]]; then
      echo -e " [ERROR]: Veil-Evasion Only Supported On Ubuntu 14+.\n"
      exit 1
    fi
  elif [ "${os}" == "debian" ]; then
    echo " [i] Debian ${version} Detected..."
    if [[ "${version}" -lt "7" ]]; then
      echo -e " [ERROR]: Veil-Evasion Only Supported On Debian 7+.\n"
      exit 1
    fi
  fi

  echo -e '\n\n [*] Initializing APT Package Installation'
  func_apt_deps

  # Check Capstone Dependency (Required For Backdoor Factory)
  if [ -f "/etc/ld.so.conf.d/capstone.conf" ]; then
    echo -e '\n\n [*] Capstone Is Already Installed... Skipping.'
  else
    func_capstone_deps
  fi

  # Check If (Wine) Python Is Already Installed
  if [ -f ~/.wine/drive_c/Python27/python27.dll ] && [ -f ~/.wine/drive_c/Python27/python.exe ]; then
    echo -e '\n\n [*] (Wine) Python Already Installed... Skipping.'
  else
    func_python_deps
  fi

  # Check If (Wine) Ruby Is Already Installed
  if [ -f ~/.wine/drive_c/Ruby187/bin/ruby.exe ]; then
    echo -e '\n\n [*] (Wine) Ruby Already Installed... Skipping.'
  else
    func_ruby_deps
  fi

  # Check if go is installed
  if [ -f "/usr/src/go/bin/windows_386/go.exe" ]; then
    echo -e '\n\n [*] Go is already installed... Skipping...'
  else
    func_go_deps
  fi

  # Finally, update the config
  func_update_config
}

# Install Architecture Dependent Dependencies
func_apt_deps(){
  # Update repo check
  sudo apt-get -q update

  [[ "$silent" ]] && arg="DEBIAN_FRONTEND=noninteractive"

  # Check For 64-bit Kernel
  if [ $(uname -m) == 'x86_64' ]; then
    echo -e '\n\n [*] Adding i386 Architecture To x86_64 System'
    sudo dpkg --add-architecture i386
    echo -e '\n\n [*] Updating APT Package Lists'
    sudo apt-get -q update
    echo -e '\n\n [*] Installing (Wine) i386 Binaries'
    sudo ${arg} apt-get -y -q install wine-bin:i386
    [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install Wine... Exit Code: $?.\n" && exit 1
  fi

  # Start APT Dependency Install
  echo -e '\n\n [*] Installing APT Dependencies'
  sudo ${arg} apt-get -y -q install mingw-w64 monodoc-browser monodevelop mono-mcs wine unzip ruby golang wget git \
                          python python-crypto python-pefile python-pip ca-certificates ttf-mscorefonts-installer
  [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install APT Dependencies... Exit Code: $?.\n" && exit 1

  if [ "${os}" == "kali" ]; then
    sudo ${arg} apt-get -y -q install metasploit
    [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install APT Dependencies (Metasploit)... Exit Code: $?.\n" && exit 1
  fi
}

# Install Capstone Dependencies - Needed for Backdoor Factory. https://github.com/secretsquirrel/the-backdoor-factory/blob/master/install.sh
func_capstone_deps(){
  echo -e '\n\n [*] Installing Capstone Dependencies...'
  if [ "${os}" == "kali" ]; then
    sudo apt-get -y -q install python-capstone
  else
    which pip >/dev/null 2>&-
    if [ "$?" -eq 0 ]; then
      echo -e ' [*] Installing via PIP'
      sudo pip install capstone
    else    # In theory, we should never end up here
      echo -e ' [*] Installing from source'
      git clone https://github.com/aquynh/capstone "${rootdir}/setup/capstone/"
      cd "${rootdir}/setup/capstone/"
      git checkout b53a59af53ffbd5dbe8dbcefba41a00cf4fc7469
      ./make.sh
      sudo ./make.sh install
      cd bindings/python/
      sudo make install
      cd "${rootdir}/setup/"
      sudo rm -rf "capstone/"
      echo -e '\n\n [*] Adding Capstone Library Path To /etc/ls.so.conf.d/capstone.conf'
      sudo sh -c "echo '# Capstone Shared Libs' > /etc/ld.so.conf.d/capstone.conf"
      sudo sh -c "echo '/usr/lib64' >> /etc/ld.so.conf.d/capstone.conf"
      sudo ldconfig
    fi
  fi
  [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install Capstone... Exit Code: $?.\n" && exit 1
}

# Install Python Dependencies
func_python_deps(){
  echo -e '\n\n [*] Initializing (Wine) Python Dependencies Installation...'

  # Check If symmetricjsonrpc Is Already Installed
  if [ -d /usr/local/lib/python2.7/dist-packages/symmetricjsonrpc/ ]; then
    echo -e '\n\n [*] SymmetricJSONRPC Already Installed... Skipping.'
  else
    echo -e '\n\n [*] Installing SymmetricJSONRPC Dependency'
    sudo pip install symmetricjsonrpc
    echo ''
    [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install SymmetricJSONRPC... Exit Code: $?.\n" && exit 1
  fi

  # Prepare (Wine) Directories
  echo -e '\n\n [*] Preparing (Wine) Directories '
  mkdir -p ~/.wine/drive_c/Python27/Lib/site-packages/
  unzip -q -o -d ~/.wine/drive_c/Python27/Lib/ "${rootdir}/setup/distutils.zip"
  unzip -q -o -d ~/.wine/drive_c/Python27/ "${rootdir}/setup/tcl.zip"
  unzip -q -o -d ~/.wine/drive_c/Python27/ "${rootdir}/setup/tcl.zip"

  # Install Setup Files
  echo -e '\n\n [*] Installing (Wine) Python & Dependencies'

  [[ "$silent" ]] && arg="/q"
  wine msiexec /i "${rootdir}/setup/python-2.7.5.msi" $arg
  [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install (Wine) Python 2.7.5... Exit Code: $?.\n" && exit 1

  pushd "${rootdir}/setup/" >/dev/null
  for FILE in pywin32-218.win32-py2.7.exe pycrypto-2.6.win32-py2.7.exe; do
    if [[ "$silent" ]]; then
      unzip -q -o "${FILE}"
      cp -rf PLATLIB/* ~/.wine/drive_c/Python27/Lib/site-packages/
      rm -rf "PLATLIB/" "SCRIPTS/"
    else
      wine "${FILE}"
      [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install ${FILE}... Exit Code: $?.\n" && exit 1
    fi
  done
  popd >/dev/null

  if [ "${os}" == "kali" ]; then
    echo -e ' [*] Installing PyInstaller via repos'
    sudo apt-get -y -q install pyinstaller
  else
    if [ -d "/opt/pyinstaller-2.0/" ]; then
      echo -e '\n\n [*] PyInstaller Already Installed... Skipping.'
    else
      echo -e ' [*] Installing PyInstaller via ZIP'
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

  echo -e '\n\n [*] Initializing Go Dependencies Installation...'
  pushd "/tmp/" >/dev/null

  sudo mkdir -p /usr/src/go/

  version="$(apt-cache show golang-src | awk -F '[:-.]' '/Version/ {print $3$4}')"
  if [[ "${version}" -lt "12" ]]; then
    echo -e ' [*] Installing Go via TAR'
    sudo tar -xf "${rootdir}/setup/go1.4.2.src.tar.gz" -C /usr/src/
  else
    # Download source via repos
    echo -e " [*] Installing Go via repos (v${version})"
    sudo apt-get source golang-go
    [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Download Go... Exit Code: $?.\n" && exit 1

    # Put everything in one place
    sudo cp -rn /tmp/golang-*/* /usr/src/go/
  fi

  # Compile
  cd /usr/src/go/src/
  sudo ./make.bash
  [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Compile Go... Exit Code: $?.\n" && exit 1

  # Cross-Compile
  sudo env GOOS=windows GOARCH=386 ./make.bash --no-clean
  sudo env CGO_ENABLED=1 GOOS=windows GOARCH=386 CC_FOR_TARGET="i686-w64-mingw32-gcc -fno-stack-protector -D_FORTIFY_SOURCE=0 -lssp" ./make.bash --no-clean

  # Done
  popd >/dev/null
}

# Install (Wine) Ruby Dependencies
func_ruby_deps(){
  echo -e '\n\n [*] Initializing (Wine) Ruby Dependencies Installation...'

  pushd "${rootdir}/setup/" >/dev/null

  # Install Ruby Under Wine
  echo -e '\n\n [*] Installing (Wine) Ruby & Dependencies'

  [[ "${silent}" ]] && arg="/silent"
  wine "${rootdir}/setup/rubyinstaller-1.8.7-p371.exe" "${arg}"
  [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install (Wine) Ruby.exe...\n"

  # Install the OCRA Gem Under Wine
  wine ~/.wine/drive_c/Ruby187/bin/ruby.exe ~/.wine/drive_c/Ruby187/bin/gem install gems/ocra-1.3.0.gem
  [ "$?" -ne "0" ] && echo -e " [ERROR] Failed To Install (Wine) OCRA Gem... Exit Code: $?.\n" && exit 1

  # Unzip the Ruby Dependencies
  unzip -q -o -d ~/.wine/drive_c/Ruby187/lib/ruby/gems/ "${rootdir}/setup/gems/1.8.zip"

  popd >/dev/null
}

# Update Veil Config
func_update_config(){
  # ./config/update.py
  echo -e '\n\n [*] Updating Veil-Framework Configuration...'
  cd "${rootdir}/config/"
  sudo python update.py

  mkdir -p /usr/share/veil-output/

  # Chown Output Directory
  if [ -d "/usr/share/veil-output/" ]; then
    echo -e "\n\n [*] Ensuring this account (${runuser}) owns veil output directory (/usr/share/veil-output/)..."
    sudo chown -R "${runuser}" /usr/share/veil-output/
  else
    echo -e " [ERROR] Internal Issue. Create output folder...\n"
  fi
}

func_title

# Menu Case Statement
case $1 in
  # Make Sure Not To Nag The User
  -s|-silent)
    silent=true
    func_check_env
    ;;
  # Force Clean Install Of (Wine) Python Dependencies
  -c|--clean)
    # Bypass Environment Checks (func_check_env) To Force Install Dependencies
    func_apt_deps
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
    echo '               -c|--clean    = Force Clean Install Of Python Dependencies'
    echo '               -s|--silent   = Automates the installation'
    echo '               -h|--help     = Show This Help Menu'
    echo ''
    exit 0
    ;;
  # Run Standard Setup
  *)
    func_check_env
    ;;
esac

echo -e '\n\n [i] Done!'
exit 0
