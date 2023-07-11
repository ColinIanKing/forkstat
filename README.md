# Forkstat

<a href="https://repology.org/project/forkstat/versions">
    <img src="https://repology.org/badge/vertical-allrepos/forkstat.svg" alt="Packaging status" align="right">
</a>

Forkstat is a program that logs process fork(), exec() and exit() activity. It is useful for monitoring system behaviour and to track down rogue processes that are spawning off processes and potentially abusing the system.

Note that forkstat uses the Linux netlink connector to gather process activity and this may miss events if the system is overly busy. Netlink connector also requires root privilege.

forkstat command line options:

* -d strip off the directory path from the process name
* -D specify run duration in seconds.
* -e select which events to monitor.
* -h show brief help summary
* -l set stdout to line-buffered mode
* -r run with real time FIFO scheduler.
* -s show short process name information
* -S show event statistics at end of the run.
* -q run quietly and enable -S option.
* -x show extra process related information. 

## Example Output:

```
sudo forkstat -S -e all
Time     Event  PID  Info  Duration Process
09:42:49 fork  3525 parent          compiz
09:42:49 fork 19257 child           compiz
09:42:49 fork 19257 parent          compiz
09:42:49 fork 19258 child           compiz
09:42:49 exit 19257      0    0.008 compiz
09:42:49 exec 19258                 gnome-terminal
09:42:49 fork  3258 parent          gnome-session --session=ubuntu
09:42:49 fork 19259 child           compiz
09:42:49 comm 19259                 compiz -> pool
09:42:49 fork  3258 parent          gnome-session --session=ubuntu
09:42:49 fork 19260 child           compiz
09:42:49 comm 19260                 compiz -> pool
09:42:49 fork  2990 parent          init --user --state-fd 29 --restart
09:42:49 fork 19261 child           gnome-terminal
09:42:49 comm 19261                 gnome-terminal -> dconf worker
09:42:49 fork  2990 parent          init --user --state-fd 29 --restart
09:42:49 fork 19262 child           gnome-terminal
09:42:49 comm 19262                 gnome-terminal -> gdbus
09:42:49 fork  2990 parent          init --user --state-fd 29 --restart
09:42:49 fork 19263 child           gnome-terminal
09:42:49 comm 19263                 gnome-terminal -> pool
09:42:49 exit 19261      0    0.063 gnome-terminal
09:42:49 exit 19263      0    0.036 gnome-terminal
09:42:49 exit 19258      0    0.092 gnome-terminal
09:42:49 exit 19262      0    0.060 gnome-terminal
Time     Event  PID  Info  Duration Process
09:42:49 fork  4394 parent          gnome-terminal
09:42:49 fork 19264 child           gnome-terminal
09:42:49 exec 19264                 bash
09:42:49 fork 19264 parent          bash
09:42:49 fork 19265 child           bash
09:42:49 fork 19265 parent          bash
09:42:49 fork 19266 child           bash
09:42:49 exec 19266                 groups
09:42:49 exit 19266      0    0.002 groups
09:42:49 exit 19265      0    0.003 bash
09:42:49 fork 19264 parent          bash
09:42:49 fork 19267 child           bash
09:42:49 fork 19267 parent          bash
09:42:49 fork 19268 child           bash
09:42:49 exec 19268                 /bin/sh /usr/bin/lesspipe
09:42:49 fork 19268 parent          /bin/sh /usr/bin/lesspipe
09:42:49 fork 19269 child           /bin/sh /usr/bin/lesspipe
09:42:49 exec 19269                 basename /usr/bin/lesspipe
09:42:49 exit 19269      0    0.004 basename /usr/bin/lesspipe
09:42:49 fork 19268 parent          /bin/sh /usr/bin/lesspipe
09:42:49 fork 19270 child           /bin/sh /usr/bin/lesspipe
09:42:49 fork 19270 parent          /bin/sh /usr/bin/lesspipe
09:42:49 fork 19271 child           /bin/sh /usr/bin/lesspipe
09:42:49 exec 19271                 dirname /usr/bin/lesspipe
Time     Event  PID  Info  Duration Process
09:42:49 exit 19271      0    0.001 dirname /usr/bin/lesspipe
09:42:49 exit 19270      0    0.001 /bin/sh /usr/bin/lesspipe
09:42:49 exit 19268      0    0.014 /bin/sh /usr/bin/lesspipe
09:42:49 exit 19267      0    0.015 bash
09:42:49 fork 19264 parent          bash
09:42:49 fork 19272 child           bash
09:42:49 fork 19272 parent          bash
09:42:49 fork 19273 child           bash
09:42:49 exec 19273                 dircolors -b
09:42:49 exit 19273      0    0.004 dircolors -b
09:42:49 exit 19272      0    0.007 bash
09:42:49 fork 19264 parent          bash
09:42:49 fork 19274 child           bash
09:42:49 fork 19274 parent          bash
09:42:49 fork 19275 child           bash
09:42:49 exec 19275                 ls /etc/bash_completion.d
09:42:49 exit 19275      0    0.002 ls /etc/bash_completion.d
09:42:49 exit 19274      0    0.004 bash
09:42:49 fork 19264 parent          bash
09:42:49 fork 19276 child           bash
09:42:49 fork 19276 parent          bash
09:42:49 fork 19277 child           bash
09:42:49 fork 19277 parent          bash
09:42:49 fork 19278 child           bash
Time     Event  PID  Info  Duration Process
09:42:49 exec 19278                 ubuntu-distro-info --all
09:42:49 exit 19278      0    0.001 ubuntu-distro-info --all
09:42:49 fork 19277 parent          bash
09:42:49 fork 19279 child           bash
09:42:49 exec 19279                 debian-distro-info --all
09:42:49 exit 19279      0    0.001 debian-distro-info --all
09:42:49 exit 19277      0    0.003 bash
09:42:49 exit 19276      0    0.009 bash
09:42:49 fork 19264 parent          bash
09:42:49 fork 19280 child           bash
09:42:49 fork 19280 parent          bash
09:42:49 exit 19280      0    0.002 bash
09:42:49 fork 19264 parent          bash
09:42:49 fork 19282 child           bash
09:42:49 exec 19282                 /usr/bin/python /usr/bin/bzr whoami Colin King 
09:42:49 exit 19282      0    0.102 /usr/bin/python /usr/bin/bzr whoami Colin King 
09:42:49 exit 19259      0    0.501 compiz
09:42:50 fork  2990 parent          init --user --state-fd 29 --restart
09:42:50 fork 19283 child           /usr/lib/x86_64-linux-gnu/indicator-session/indicator-session-service
09:42:50 comm 19283                 /usr/lib/x86_64-linux-gnu/indicator-session/indicator-session-service -> pool
09:42:50 fork  1247 parent          /usr/lib/accountsservice/accounts-daemon
Time     Event  PID  Info  Duration Process
09:42:50 fork 19284 child           /usr/lib/accountsservice/accounts-daemon
09:42:50 exec 19284                 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19284 parent          /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19285 child           /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 exec 19285                 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19285 parent          /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19286 child           /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exec 19286                 sh -c locale -a | grep -F .utf8 
09:42:50 fork 19286 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19287 child           sh -c locale -a | grep -F .utf8 
09:42:50 fork 19286 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19288 child           sh -c locale -a | grep -F .utf8 
09:42:50 exec 19288                 grep -F .utf8
09:42:50 exec 19287                 locale -a
09:42:50 exit 19287      0    0.002 locale -a
09:42:50 exit 19288      0    0.003 grep -F .utf8
09:42:50 exit 19286      0    0.004 sh -c locale -a | grep -F .utf8 
09:42:50 exit 19285      0    0.012 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exit 19284      0    0.015 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork  1247 parent          /usr/lib/accountsservice/accounts-daemon
09:42:50 fork 19289 child           /usr/lib/accountsservice/accounts-daemon
09:42:50 exec 19289                 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19289 parent          /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19290 child           /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
Time     Event  PID  Info  Duration Process
09:42:50 exec 19290                 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19290 parent          /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19291 child           /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exec 19291                 sh -c locale -a | grep -F .utf8 
09:42:50 fork 19291 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19292 child           sh -c locale -a | grep -F .utf8 
09:42:50 fork 19291 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19293 child           grep
09:42:50 exec 19292                 
09:42:50 exec 19293                 
09:42:50 exit 19292      0    0.001 sh -c locale -a | grep -F .utf8 
09:42:50 exit 19293      0    0.000 grep
09:42:50 exit 19291      0    0.002 sh -c locale -a | grep -F .utf8 
09:42:50 exit 19290      0    0.008 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exit 19289      0    0.010 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork  1247 parent          /usr/lib/accountsservice/accounts-daemon
09:42:50 fork 19294 child           /usr/lib/accountsservice/accounts-daemon
09:42:50 exec 19294                 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19294 parent          /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19295 child           /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 exec 19295                 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19295 parent          /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19296 child           /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exec 19296                 sh -c locale -a | grep -F .utf8 
Time     Event  PID  Info  Duration Process
09:42:50 fork 19296 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19297 child           locale
09:42:50 fork 19296 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19298 child           sh -c locale -a | grep -F .utf8 
09:42:50 exec 19297                 locale -a
09:42:50 exit 19297      0    0.001 locale -a
09:42:50 exec 19298                 grep -F .utf8
09:42:50 exit 19298      0    0.001 grep -F .utf8
09:42:50 exit 19296      0    0.002 sh -c locale -a | grep -F .utf8 
09:42:50 exit 19295      0    0.008 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exit 19294      0    0.009 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork  1247 parent          /usr/lib/accountsservice/accounts-daemon
09:42:50 fork 19299 child           /usr/lib/accountsservice/accounts-daemon
09:42:50 exec 19299                 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19299 parent          /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 fork 19300 child           /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:50 exec 19300                 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19300 parent          /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 fork 19301 child           /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exec 19301                 sh -c locale -a | grep -F .utf8 
09:42:50 fork 19301 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19302 child           sh -c locale -a | grep -F .utf8 
09:42:50 fork 19301 parent          sh -c locale -a | grep -F .utf8 
09:42:50 fork 19303 child           sh -c locale -a | grep -F .utf8 
Time     Event  PID  Info  Duration Process
09:42:50 exec 19303                 grep -F .utf8
09:42:50 exec 19302                 locale -a
09:42:50 exit 19302      0    0.001 locale -a
09:42:50 exit 19303      0    0.001 grep -F .utf8
09:42:50 exit 19301      0    0.002 sh -c locale -a | grep -F .utf8 
09:42:50 exit 19300      0    0.007 /usr/bin/perl /usr/share/language-tools/language-options
09:42:50 exit 19299      0    0.009 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
09:42:53 fork 19264 parent          bash
09:42:53 fork 19304 child           bash
09:42:53 exec 19304                 dmesg
09:42:53 exit 19304      0    0.052 dmesg
09:42:54 fork 19264 parent          bash
09:42:54 fork 19305 child           bash
09:42:54 exec 19305                 ps -ef
09:42:54 exit 19305      0    0.024 ps -ef
^C
    Fork     Exec     Exit Coredump     Comm    Total Process
      17       10        7        0        0       34 bash
       8        6        5        0        0       19 sh -c locale -a | grep -F .utf8 
       4        4        4        0        0       12 /usr/bin/perl /usr/share/language-tools/language-options
       4        4        4        0        0       12 /bin/sh -e /usr/share/language-tools/language-validate en_GB:en
       1        1        4        0        3        9 gnome-terminal
       4        4        0        0        0        8 /usr/lib/accountsservice/accounts-daemon
       3        2        2        0        0        7 /bin/sh /usr/bin/lesspipe
       2        1        2        0        2        7 compiz
       4        0        0        0        0        4 init --user --state-fd 29 --restart
       0        0        3        0        0        3 grep -F .utf8
       0        0        3        0        0        3 locale -a
       2        0        0        0        0        2 gnome-session --session=ubuntu
       0        1        1        0        0        2 grep
       0        1        0        0        0        1 locale
       0        0        1        0        0        1 ps -ef
       0        0        1        0        0        1 debian-distro-info --all
       0        0        1        0        0        1 ls /etc/bash_completion.d
       0        0        1        0        0        1 dmesg
       0        0        0        0        1        1 /usr/lib/x86_64-linux-gnu/indicator-session/indicator-session-service
       0        0        1        0        0        1 readlink -f /home/king/.canonistack/novarc
       0        0        1        0        0        1 dircolors -b
       0        0        1        0        0        1 groups
       0        0        1        0        0        1 ubuntu-distro-info --all
       0        0        1        0        0        1 dirname /usr/bin/lesspipe
       0        0        1        0        0        1 basename /usr/bin/lesspipe
```
