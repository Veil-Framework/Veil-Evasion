#!/bin/bash

# Global Variables
runuser=$(whoami)
tempdir=$(pwd)

# Title Function
func_title(){
  # Clear (For Prettyness)
  clear

  # Echo Title
  echo '=========================================================================='
  echo ' Veil-Evasion Setup Script | [Updated]: 09.09.2014'
  echo '=========================================================================='
  echo ' [Web]: https://www.veil-framework.com | [Twitter]: @VeilFramework'
  echo '=========================================================================='
}

# Environment Checks
func_check_env(){
  # Check Sudo Dependency
  if [ $(which sudo|wc -l) -eq '0' ]; then
    echo
    echo ' [ERROR]: This Setup Script Requires sudo!'
    echo '          Please Install sudo Then Run This Setup Again.'
    echo
    exit 1
  fi

  # Check Running User
  if [ ${runuser} == 'root' ]; then
    echo
    echo ' [WARNING]: Setup No Longer Requires Constant Root Privileges.'
    echo '            Continuing Will Install Veil Only For The Root User.'
    echo
    read -p ' Continue With Installation? (y/n): ' rootonly
    if [ ${rootonly} != 'y' ]; then
      echo
      echo ' [ERROR]: Installation Aborted By User.'
      echo
      exit 1
    fi
  fi

  # Check OS Versions (Temporary To Ensure A Smooth Transition)
  if [ $(uname -a|grep -i kali|wc -l) == '1' ]; then
    echo
    echo ' Kali linux detected...'
    echo
  elif [ $(uname -a|grep -i ubuntu|wc -l) == '1' ]; then
    if [ $(grep "VERSION_ID" /etc/os-release|cut -d"=" -f2|sed -e 's/"//g' -e 's/\..*//') -lt '14' ]; then
      echo
      echo ' [ERROR]: Veil-Evasion Only Supported On Ubuntu Versions 14+.'
      echo
      exit 1
    fi
  elif [ $(uname -a|grep -i debian|wc -l) == '1' ]; then
    if [ $(grep "VERSION_ID" /etc/os-release|cut -d"=" -f2|sed -e 's/"//g' -e 's/\..*//') -lt '7' ]; then
      echo
      echo ' [ERROR]: Veil-Evasion Only Supported On Debian Versions 7+.'
      echo
      exit 1
    fi
  fi

  # Check Capstone dependency for backdoor factory
  if [ -f /etc/ld.so.conf.d/capstone.conf ]; then
    echo ' [*] Capstone Already Installed... Skipping.'
  else
    echo ' [*] Initializing Git Repo Based Dependencies Installation'
    func_git_deps
  fi

  # Check If Wine Python Is Already Installed
  if [ -f ~/.wine/drive_c/windows/system32/python27.dll ] && [ -f ~/.wine/drive_c/Python27/python.exe ]; then
    echo ' [*] Wine Python Already Installed... Skipping.'
    echo ' [*] Initializing Apt Package Installation'
    func_apt_deps
    # func_update_config
  else
    echo ' [*] Initializing Apt Dependencies Installation'
    func_apt_deps
    echo ' [*] Initializing Wine Python Dependencies Installation'
    func_python_deps
  fi

  # Check If Wine Ruby Is Already Installed
  if [ -f ~/.wine/drive_c/Ruby187/bin/ruby.exe ]; 
    then
    echo ' [*] Wine Ruby Already Installed... Skipping.'
  else
    echo ' [*] Initializing Wine Ruby Dependencies Installation'
    func_ruby_deps
  fi

  # finally, update the config
  func_update_config
}

# Install Architecture Dependent Dependencies
func_apt_deps(){
  # Check For 64-bit Kernel
  if [ $(uname -m) == 'x86_64' ]; then
    echo ' [*] Adding i386 Architecture To x86_64 System'
    sudo dpkg --add-architecture i386
    echo ' [*] Updating Apt Package Lists'
    sudo apt-get update
    echo ' [*] Installing Wine i386 Binaries'
    sudo apt-get install -y wine-bin:i386
  fi

  # Start Apt Dependency Install
  echo ' [*] Installing Microsoft Fonts'
  # Can't Send This to Log File Due to Dumb Needs to Agree with M$ Crap.
  sudo apt-get install -y ttf-mscorefonts-installer
  echo ' [*] Installing Apt Dependencies'
  sudo apt-get install -y mingw-w64 monodoc-browser monodevelop mono-mcs wine python python-crypto \
                          python-pefile python-pip unzip ruby
}

# Install Git Dependencies
func_git_deps(){
    echo ' [*] Installing Git Repo Dependencies'
    cd ${tempdir}
    git clone https://github.com/aquynh/capstone
    cd capstone
    git checkout master
    ./make.sh
    sudo ./make.sh install
    cd bindings/python
    sudo make install
    cd ${tempdir}
    sudo rm -rf capstone
    echo ' [*] Adding Capstone Library Path To /etc/ls.so.conf.d/capstone.conf'
    sudo sh -c "echo '# Capstone Shared Libs' > /etc/ld.so.conf.d/capstone.conf"
    sudo sh -c "echo '/usr/lib64' >> /etc/ld.so.conf.d/capstone.conf"
    sudo ldconfig
}

# Install Wine Python Dependencies
func_python_deps(){
  # Check If symmetricjsonrpc Is Already Installed
  if [ -d /usr/local/lib/python2.7/dist-packages/symmetricjsonrpc/ ]; then
    echo ' [*] SymmetricJSONRPC Already Installed... Skipping.'
  else
    echo ' [*] Installing symmetricjsonrpc Dependency'
    sudo pip install symmetricjsonrpc
    echo
  fi

  # Install Wine Python and Dependencies
  # Download required files, doing no check cert because wget is having an issue with our wildcard cert
  # if you're reading this, and actually concerned you might be mitm, use a browser and just download these
  # files and then just comment these next two lines out :)
  echo ' [*] Downloading Python Setup Files From http://www.veil-framework.com'
  wget -q https://www.veil-framework.com/InstallMe/requiredfiles.zip --no-check-certificate
  wget -q https://www.veil-framework.com/InstallMe/pyinstaller-2.0.zip --no-check-certificate

  # Unzip Setup Files
  echo ' [*] Uncompressing Setup Archive'
  unzip requiredfiles.zip

  # Prepare Wine Directories
  echo ' [*] Preparing Wine Directories'
  mkdir -p ~/.wine/drive_c/Python27/Lib/
  cp distutils -r ~/.wine/drive_c/Python27/Lib/
  cp tcl -r ~/.wine/drive_c/Python27/
  cp Tools -r ~/.wine/drive_c/Python27/

  # Install Setup Files
  echo ' [*] Installing Wine Python Dependencies'
  wine msiexec /i python-2.7.5.msi
  wine pywin32-218.win32-py2.7.exe
  wine pycrypto-2.6.win32-py2.7.exe
  if [ -d "/opt/pyinstaller-2.0/" ]; then
    echo ' [*] PyInstaller Already Installed... Skipping.'
  else
    sudo unzip -d /opt pyinstaller-2.0.zip
    sudo chmod 755 -R /opt/pyinstaller-2.0/
  fi

  # Clean Up Setup Files
  echo ' [*] Cleaning Up Setup Files'
  rm python-2.7.5.msi
  rm pywin32-218.win32-py2.7.exe
  rm pycrypto-2.6.win32-py2.7.exe
  rm pyinstaller-2.0.zip
  rm requiredfiles.zip

  # Remove Temp Directories
  echo ' [*] Removing Temporary Directories'
  rm -rf distutils
  rm -rf tcl
  rm -rf Tools
}


# Install Wine Ruby Dependencies
func_ruby_deps(){

  # Install Wine Ruby and Dependencies
  # Download required files, doing no check cert because wget is having an issue with our wildcard cert
  # if you're reading this, and actually concerned you might be mitm, use a browser and just download these
  # files and then just comment these next two lines out :)
  echo ' [*] Downloading Ruby Setup Files From http://www.veil-framework.com'
  wget -q https://www.veil-framework.com/InstallMe/rubyinstaller-1.8.7-p371.exe --no-check-certificate
  wget -q https://www.veil-framework.com/InstallMe/ruby_required.zip --no-check-certificate

  # install Ruby under Wine
  echo ' [*] Installing Ruby under Wine'
  wine rubyinstaller-1.8.7-p371.exe /silent

  # fetch the OCRA gem
  echo ' [*] Fetching and installing Ruby OCRA gem'
  gem fetch -v 1.3.0 ocra

  # install the OCRA gem under Wine
  wine ~/.wine/drive_c/Ruby187/bin/ruby.exe ~/.wine/drive_c/Ruby187/bin/gem install ocra-1.3.0.gem

  # unzip the Ruby dependencies
  echo ' [*] Uncompressing Ruby Setup Archive'
  unzip -o -d /root/.wine/drive_c/Ruby187/lib/ruby/gems/ ruby_required.zip

  # Clean Up Setup Files
  echo ' [*] Cleaning Up Ruby Setup Files'
  rm rubyinstaller-1.8.7-p371.exe
  rm ruby_required.zip
  rm ocra-1.3.0.gem
}

# Update Veil Config
func_update_config(){
  # ./config/update.py
  echo ' [*] Updating Veil-Framework Configuration'
  cd ../config
  sudo python update.py

  # Chown Output Directory
  sudo chown ${runuser}:${runuser} ~/veil-output
}

# Menu Case Statement
case $1 in
  # Force Clean Install Of Wine Python Dependencies
  --clean)
    # Bypass Environment Checks To Force Install Dependencies
    func_title
    func_apt_deps
    func_git_deps
    func_python_deps
    func_ruby_deps
    ;;
  # Print Help Menu
  -h|--help)
    func_title
    echo
    echo "  [Usage]....: ${0} [OPTIONAL]"
    echo '  [Optional].:'
    echo '               --clean   = Force Clean Install Of Python Dependencies'
    echo '               -h|--help = Show Help Menu'
    echo
    ;;
  # Run Standard Setup
  *)
    func_title
    func_check_env
    ;;
esac
