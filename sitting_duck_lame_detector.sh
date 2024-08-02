#!/bin/bash
########################################### Start of Comment Section ###########################################

#::Licensing
# This work is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License.
# To view a copy of this license, visit https://creativecommons.org/licenses/by-nc/4.0/ or send a letter to
# Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

#::Program Information
# (c) Infoblox July 16
# Author: Infoblox Threat Intelligence [ITI]
# Date Created: 16 July 2024
# Description: This bash script is only compatible with macOS systems. It scans a domain or many domains to determine
#              whether they show lame status (i.e. non-delegated domains). Lame delegations occur when the domain's
#              authoritative name server fails to provide a valid response due to a misconfiguration, or in the case
#              of a DNS service provider, a contractual relationship has been terminated.


#::Installation and Usage Instructions
# When running the script for the very first time, run the following command.
# This will perform system checks and installation.
#########################
# bash lame_detector.sh #
#########################

# All subsequent calls after the above initial setup/installation only require the name of the script.
# The user can be in any directory and will still be able to call the script only by name not entire path.
# help message
########################
# lame_detector.sh -h #
########################

# Scanning a single domain
####################################
# lame_detector.sh -d infoblox.com #
####################################

# Scanning a newly-delimited file with many domains
#######################################
# lame_detector.sh -f <path to file> #
#######################################

########################################### End of Comment Section ###########################################


### configuration ###
name_of_this_script=$(basename "$0")
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
full_path_of_this_script="$script_dir/$name_of_this_script"
lame_detector_local_path="/Users/$USER/lame_detector"
lame_detector_rs_path=$lame_detector_local_path"/results"
lame_detector_new_path="$lame_detector_local_path/lame_detector.sh"
lame_detector_bin_path="/usr/local/bin/$name_of_this_script"
zdns_path="$lame_detector_local_path/zdns/zdns"
zdns_bin_path="/usr/local/bin/zdns"

### long log messages ###
zdns_not_found_msg="Critical programs are missing, checking system compatibility..."
git_warning_install_msg="[WARNING!!] git command line not installed! Installing the program now..."
make_warning_install_msg="[WARNING!!] make command line not installed! Installing the program now..."
brew_warning_install_msg="[WARNING!!] brew command line not installed! Installing the program now..."
zdns_warning_install_msg="[WARNING!!] zdns command line not installed! Installing the program now..."
go_warning_install_msg="[WARNING!!] golang not installed! Installing the program now..."
incompatible_os_msg="Incompatible OS found! This program will only work on a macOS device.
Please purchase a new computer."
cygwin_os_msg="POSIX compatibility layer and Linux environment emulation for Windows"
msys_os_msg="Lightweight shell and GNU utilities compiled for Windows (part of MinGW)"
executable_ok_msg="File '$full_path_of_this_script' is executable, proceeding..."
executable_bad_msg="File '$full_path_of_this_script' is not executable. Updating permissions now..."
program_directory_msg="Program's current directory: $script_dir"
bin_file_check_msg="Lame detector script is already located in user's bin folder"
bin_file_move_msg="Lame detector missing in user's bin folder. Creating symlink now..."
help_msg="The ITI lame detector analyzes the DNS status of a domain or batch of domains to
determine whether they are lame."
help_syntax_msg="Syntax: lame_detector.sh [-h|d|f]"
custom_tab="  "
help_d_msg="The domain (e.g. infoblox.com) for checking lame status."
help_h_msg="A help message that describes available arguments."
help_f_msg="The path to the file (new-line delimited) that contains many domains."
invalid_opt_msg="Error: Invalid option.\n Valid options are -d and -f\n Read the help(-h) section
for more details."
invalid_flag_combo_msg="Simultaneous use of simultaneous d and f flags is not allowed!"
multi_thread_msg="More than 40 items in input file, scanning domains in multi-thread mode"
as_progress_msg="Domain analysis in progress..."
zdns_clone_msg="zdns already cloned, skipping download..."

### DNS settings ###
open_resolver="8.8.8.8"

### ASCII art echo ###
grncde='\033[0;32m'
rdcde='\033[0;31m'
bgcde='\033[1;32m'

echo -e "${bgcde} ███╗██╗████████╗██╗███╗    ██╗      █████╗ ███╗   ███╗███████╗     ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗  ";
echo -e "${bgcde} ██╔╝██║╚══██╔══╝██║╚██║    ██║     ██╔══██╗████╗ ████║██╔════╝     ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗ ";
echo -e "${bgcde} ██║ ██║   ██║   ██║ ██║    ██║     ███████║██╔████╔██║█████╗       ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝ ";
echo -e "${bgcde} ██║ ██║   ██║   ██║ ██║    ██║     ██╔══██║██║╚██╔╝██║██╔══╝       ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗ ";
echo -e "${bgcde} ███╗██║   ██║   ██║███║    ███████╗██║  ██║██║ ╚═╝ ██║███████╗     ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║ ";
echo -e "${bgcde} ╚══╝╚═╝   ╚═╝   ╚═╝╚══╝    ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝     ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ";


lame_status_display() {
  echo -e "${rdcde}███████╗████████╗ █████╗ ████████╗██╗   ██╗███████╗       ██╗      █████╗ ███╗   ███╗███████╗ ";
  echo -e "${rdcde}██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝██╗    ██║     ██╔══██╗████╗ ████║██╔════╝ ";
  echo -e "${rdcde}███████╗   ██║   ███████║   ██║   ██║   ██║███████╗╚═╝    ██║     ███████║██╔████╔██║█████╗   ";
  echo -e "${rdcde}╚════██║   ██║   ██╔══██║   ██║   ██║   ██║╚════██║██╗    ██║     ██╔══██║██║╚██╔╝██║██╔══╝   ";
  echo -e "${rdcde}███████║   ██║   ██║  ██║   ██║   ╚██████╔╝███████║╚═╝    ███████╗██║  ██║██║ ╚═╝ ██║███████╗ ";
  echo -e "${rdcde}╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝       ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ";
}

ok_status_display() {
  echo -e "${grncde}███████╗████████╗ █████╗ ████████╗██╗   ██╗███████╗        ██████╗ ██╗  ██╗";
  echo -e "${grncde}██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝██╗    ██╔═══██╗██║ ██╔╝";
  echo -e "${grncde}███████╗   ██║   ███████║   ██║   ██║   ██║███████╗╚═╝    ██║   ██║█████╔╝ ";
  echo -e "${grncde}╚════██║   ██║   ██╔══██║   ██║   ██║   ██║╚════██║██╗    ██║   ██║██╔═██╗ ";
  echo -e "${grncde}███████║   ██║   ██║  ██║   ██║   ╚██████╔╝███████║╚═╝    ╚██████╔╝██║  ██╗";
  echo -e "${grncde}╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝        ╚═════╝ ╚═╝  ╚═╝";
}

### Help message ###
help() {
  # Display help
  echo -e "$help_msg"
  echo
  echo "$help_syntax_msg"
  echo
  echo "options:"
  echo "$custom_tab" "h $custom_tab $help_h_msg"
  echo "$custom_tab" "d $custom_tab $help_d_msg"
  echo "$custom_tab" "f $custom_tab $help_f_msg"
  echo
}

### Check permissions and make it executable ###
check_program_permissions() {
  if [[ -x "$full_path_of_this_script" ]]
  then
    echo $executable_ok_msg
  else
    echo $executable_bad_msg
    chmod +x $full_path_of_this_script
  fi
}

### Make script executable anywhere ###
bin_script() {
  if [ -e "$lame_detector_bin_path" ]
  then
    echo $bin_file_check_msg
  else
    echo $bin_file_move_msg
    if [ -e $lame_detector_local_path ]
    then
      :
    else
      mkdir $lame_detector_local_path
      mkdir $lame_detector_rs_path
      cp $full_path_of_this_script $lame_detector_local_path
    fi
    sudo ln -s $lame_detector_new_path $lame_detector_bin_path
  fi
}

### Check script location ###
check_program_directory() {
  echo $program_directory_msg
  check_program_permissions
}

### Find name of OS ###
find_os_system() {
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "linux"
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS"
  elif [[ "$OSTYPE" == "cygwin" ]]; then
    echo $cygwin_os_msg
  elif [[ "$OSTYPE" == "msys" ]]; then
    echo $msys_os_msg
  elif [[ "$OSTYPE" == "freebsd"* ]]; then
    echo "freebsd"
  else
    echo "unknown"
  fi
}

### Check if OS is compatible ###
check_os_system() {
  local osname=$(find_os_system)
  printf "Detected Client OS System: $osname\n"
  if [[ "$osname" != "macOS" ]]; then
    echo $incompatible_os_msg
    exit 1
  fi
}

### Check required programs ###
check_programs() {
  cd $lame_detector_local_path
  if ! hash git 2>/dev/null; then
    echo $git_warning_install_msg
    xcode-select --install
  fi
  if ! hash make 2>/dev/null; then
    echo $make_warning_install_msg
    xcode-select --install
  fi
  if ! hash brew 2>/dev/null; then
    echo $brew_warning_install_msg
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
  if ! hash go 2>/dev/null; then
    echo $go_warning_install_msg
    brew install golang
  fi
  if ! hash zdns 2>/dev/null; then
    echo $zdns_warning_install_msg
    if [ -d "zdns" ]
    then
      echo $zdns_clone_msg
    else
      git clone https://github.com/zmap/zdns.git
    fi
    cd zdns
    make zdns
    sudo ln -s $zdns_path $zdns_bin_path
  fi
  if ! hash jq 2>/dev/null; then
    brew install jq
  fi
  if ! hash toilet 2>/dev/null; then
    brew install toilet
  fi
}

### Function for single domain scan ###
lame_scan_single() {
  local dns_resp=$(echo "$1" | zdns A --name-servers=$open_resolver)
  local dns_sts=$(echo $dns_resp | jq 'select(.status=="SERVFAIL")
  | select(.data.additionals[]?.ede[0]?.error_text=="Network Error")
  | select(.data.additionals[]?.ede[-1]?
  | select(.error_text == "No Reachable Authority" and (.extra_text
  | contains("delegation")))) | .name')
  if [[ -n "$dns_sts" ]]
  then
    lame_status_display
    echo "Scanned Domain: ${1}" | toilet -t -f future -F metal
  else
    ok_status_display
    echo "Scanned Domain: ${1}" | toilet -t -f future -F metal
  fi
}

### Progress tracker for bulk lame scans ###
lame_progress() {
  local counter=0
  local out_file="${lame_detector_rs_path}/$1_raw_scans.json"
  touch $out_file
  local ioc_size=$2

  while (( $counter + 2 < $2 ))
  do
    counter=$((counter+$(cat "$out_file" | wc -l)))
    if (( $counter % 10 == 0 )) && (( $counter > 0 ))
    then
      local prg_ratio=$(echo "scale=2; (${counter} / ${ioc_size}) * 100" | bc -l)
      prg_ratio=${prg_ratio%.*}
      echo -e "Current Progress: Processed ${grncde}${counter} domains | ${prg_ratio} percent"
      printf '%*s' "$prg_ratio" | tr ' ' "#"
      printf '\n'
    fi
  done
}

### Multi-threaded method for bulk lame scanning ###
lame_scan_bulk() {
  local timestamp=$2
  local ioc_size=$(cat "$1" | wc -l)
  local out_file="${lame_detector_rs_path}/${timestamp}_raw_scans.json"
  local lame_output="${lame_detector_rs_path}/${timestamp}_lame_domains.txt"
  if (( ioc_size > 40 ))
  then
    echo $multi_thread_msg
    local thread_num=20
  else
    local thread_num=1
  fi
  echo "Scanning domains..."
  zdns A --threads=$thread_num --timeout=10 --name-servers=$open_resolver --input-file="$1" --output-file="$out_file"
  echo "Completed writing lame scan results to ${out_file}"
  echo $as_progress_msg
  cat "$out_file" | jq 'select(.status=="SERVFAIL")
  | select(.data.additionals[]?.ede[0]?.error_text=="Network Error")
  | select(.data.additionals[]?.ede[-1]?
  | select(.error_text == "No Reachable Authority" and (.extra_text
  | contains("delegation")))) | .name' > $lame_output
  echo "Completed writing lame domains to ${lame_output}"
  local lame_count=$(sed '/^$/d' $lame_output | wc -l)
  echo "Lame Scan Summary" | toilet -t -f future -F metal
  echo -e "Total detected lame domains: ${lame_count}" | toilet -t -f future -F border
  echo -e "Total scanned domains: ${ioc_size}" | toilet -t -f future -F border
}

### Check setup completion ###
if ! [ -e $lame_detector_new_path ] && ! hash zdns 2>/dev/null
  then
    echo $zdns_not_found_msg
    check_os_system
    check_program_directory
    bin_script
    check_programs
fi

### Handle input options appropriately ###
while getopts "hd:f:" option; do
  case $option in
  h) # display help
     help
     exit;;
  d) # enter domain
     domain=$OPTARG;;
  f) # enter file path
     file_path=$OPTARG;;
  \?) # invalid option
     echo -e "$invalid_opt_msg"
     exit;;
  esac
done

### Dislloaw illegal flag combinations ###
if ! [ -z $domain ] && ! [ -z $file_path ]
then
  echo $invalid_flag_combo_msg
  exit 1
fi

### Scan domains according to options ###
if ! [ -z $domain ]
then
  lame_scan_single $domain
elif ! [ -z $file_path ]
then
  timestamp=$(date +%Y%m%d_%H%M%S)
  ioc_size=$(cat "$file_path" | wc -l)
  lame_scan_bulk $file_path $timestamp & lame_progress $timestamp $ioc_size & wait
fi
