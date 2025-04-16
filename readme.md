 # Analyze Apache access logs for bot activity.

## positional arguments:<br>
  log_file    Path to the Apache access log file.<br>
  start_time  Start time (YYYY-MM-DD HH:MM:SS +ZZZZ).<br>
  end_time    End time (YYYY-MM-DD HH:MM:SS +ZZZZ).<br>

## options:<br>
  -h, --help  show this help message and exit<br>
  --suspicious_count SUSPICIOUS_COUNT<br>

## Example:<br>
python3 apache_log_analyzer.py /var/log/apache2/access.log '2025-04-16 06:45:00 +0000' '2025-04-16 07:15:00 +0000'<br>

<hr>

### Apache Log Format;
<p>
LogFormat "%{X-Forwarded-For}i %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined<br>
LogFormat "%h %l %u %t \"%r\" %>s %b" common<br>
ErrorLog ${APACHE_LOG_DIR}/error.log<br>
CustomLog ${APACHE_LOG_DIR}/access.log combined<br>
</p>
<br>
<br>
License: CDDL Version 1.1