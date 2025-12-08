################################################################
################################################################
##
##
## Compliance Self Test (CST)
##
## By Dan Seeland
##    
##
################################################################
################################################################

Used to run multiple bash shell scripts to check STIG compliance  
Directories:  
1.	main  
a. runcheck.sh - the main script.  
2.	conf  
   a. cst-rhel7_2023.cfg - a list of RHEL 7 scripts to run.  
   b. cst-rhel8_2024.cfg - a list of RHEL 8 scripts to run.  
   c. cst-rhel9_2025.cfg - a list of RHEL 9 scripts to run.  
   d. exceptions.cfg - a file used to list scripts in any of the above
      config files that you want to skip.
4.	scripts  
   a. cst-rhel7/2023  
   b. cst-rhel8/2024  
   c. cst-rhel9/2025  
6.	reports  
   a. [filename]-full.txt - a detailed text report with colors when viewed in a Linux terminal.  
   b. [filename]-brief.txt - a summary text report with colors when viewed in a Linux terminal.  
   c. [filename]-brief.csv - a comma-separated text report you can import to Excel (no colors).  
   d. [filename]-score.txt - a summary text score report.  
   e. [filename]-xccdf.xml - results you can import to a STIG Viewer checklist.  
7.	tmp  
   a. temporary working files that are deleted after every run.
  
Usage:  
1.	Sudo to root  
2.	Copy the tar file to a network share or a location on the target host where script execution is permitted(i.e., /root)  
3.	Extract the tar file  
4.	CD to main/  
5.	Run 'runcheck.sh'  
   **[your-host main]# ./runcheck.sh**  
   If you find that the script dies before it can finish, it's probably because of the idle-timeout settings on the host. If that's the case, try using the no-hangup switch.  
   **[your-host main]# ./runcheck.sh nohup**  
6.	The menu appears  
   Enter the menu number for the Compliance Self Test of your choice and hit Enter.  
7.	The script names scroll down as they execute.  
8.	View the results in the 'reports' folder  
   (The .csv file is viewable in Excel)  
   (The xccdf file can be imported into a STIGViewer Checklist)  
9.	Offload the reports to an approved share or media.  
10. It's not a good idea to leave vulnerability reports on the host you scan. To leave no trace of this tool or the reports it generates, delete the directory you created in step 2     along with all of the contents within.  
    
Running only select scripts  
  
There a two ways to do this:  
a. You can comment out the script you don't want to run in /cst/conf/ file (i.e., #rhel-8-ac10.sh). When you execute the /main/runcheck.sh script, you'll get the same five reports     containing the results from only the scripts you didn't comment out.  
b. You can list the scripts you want to skip in a '/conf/exceptions.cfg' file.  
  
Running the scripts individually  
  
You can also run any of the scripts individually to get an instant look at specific families (AU-12, CM-6), but they won't generate reports unless you pipe the output to a file.  
  
Viewing the reports  
  
1.	The "runcheck.sh" script generates the five reports listed above. From a Linux terminal session, the "full.txt", "brief.txt", and "score.txt" reports will give you a detailed look at the scan results in text format.  
2.	If you open Excel and import the "brief.csv" report, you'll see a full, filterable, sortable report.  
3.	If you open STIG Viewer and import the "xccdf.xml" report, you can export the results to a STIG checklist, but it will only show the pass/fail results. It won't show you the test result findings. To import the test result findings into the checklist, you can open the "full.txt" report in a Linux terminal session and cut and paste the "RESULT" lines of each test into the "Comments" section of the STIG checklist.  
  
Viewing live output of each script  
  
If you want to watch the live output of each script that "runscript.sh" pulls from the "/conf" directory, open a separate terminal session and cd to the "/cst/tmp" directory before you start "runscript.sh". As soon as you kick off "runscript.sh" in the first terminal session, list the contents of the "/cst/tmp" directory in the second terminal session and then "tail -f runcheck-[random number].tmp". It'll be hard to catch the output from the first few scripts, but you'll be able to watch as most of the scripts run.  
  
Doing a dry run using the "dryrun.sh script"  
  
To view a live run of all scripts without generating all the reports, use the "dryrun.sh" script in the "cst/scripts" directory. If any of the scripts run into problems, you'll be able to see exactly which specific test is causing the problem and give you an idea how to get around it.  
  
What do all those CCI numbers mean?  
  
In each of the reports, all of the tests refer to one or more CCIs that call out a specific requirement. To see what those requirements are, you can either open the stig text file associated with a particular test and search for a specific CCI, or you can run the "getcci.sh" script located in the /cst/files directory, and pass it the associated stig text file. Starting from the /cst/directory;  
  
   **[your-host cst]# cd files**
   **[your-host files]# ./getcci.sh stig/RHEL-9-v2-r5-IA3.txt**  
   What you'll get back are just the CCI numbers and the associated requirements called out in that file, without the rest of the STIG text in the file.  

Practical Search Commands if you're in a Linux terminal session:  
  
* *Get a list of failed CAT I vulnerabilities: (substitue 'CAT II,' 'CAT III', PASSED, N/A, or VERIFY)* *  
**[your-host reports]$ sudo more [filename]-brief.txt | grep 'CAT I,' | grep FAILED | cut -d',' -f1,2,3,5,8**  
  
* *Get a pass/fail list by script* *  
**[your-host reports]$ sudo more [filename]-brief.txt | grep 'AC-10' | cut -d',' -f1,2,3,5,8**  
  
* *Get a sorted list of vulnerabilities checked by vulnerability ID - no duplicates* *  
**[your-host reports]$ sudo more [filename]-brief.txt | cut -d',' -f5 | sort | uniq**  
  




