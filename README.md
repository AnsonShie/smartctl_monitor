# system_monitor
* Preinstall:
  * nagios packages
  * yum install perl-Time-HiRes

* Configuration(for Nodes):
  * Edit /etc/sudoers
  <pre><code>
    nagios ALL=(ALL) NOPASSWD:/opt/system-monitor/ipmitool_monitor.py
    nagios ALL=(ALL) NOPASSWD:/opt/system-monitor/smartctl_monitor.py
  </pre></code>
  * Edit /etc/nagios/nrpe.cfg
  <pre><code>
    command[check_ipmi]=/usr/bin/python /opt/system-monitor/ipmitool_monitor.py
    command[check_disk]=/usr/bin/python /opt/system-monitor/smartctl_monitor.py
  </pre></code>
  * Edit /etc/udev/rules.d/99-scsi.rules
  <pre><code>
    SUBSYSTEM=="scsi_disk",ACTION=="add",RUN="/usr/bin/python /opt/system-monitor/disk_plug_in_out.py"
    SUBSYSTEM=="scsi_disk",ACTION=="remove",RUN="/usr/bin/python /opt/system-monitor/disk_plug_in_out.py"
  </pre></code>
* Configuration(for Manager):
  * Add nagios_server_config to /etc/nagios/objects/

  
* Reference:
  * https://github.com/thomas-krenn/check_smart_attributes
