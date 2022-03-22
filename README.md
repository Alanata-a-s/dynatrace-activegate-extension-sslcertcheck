# SSL/TLS Certificates Check ActiveGate Extension

This extension checks the SSL/TLS certificate expiration time. It doesn't check certificate validity! The host:port specification for checked certificates is populated in extension's configuration or specified in hosts file specified in GUI.

## Requirements
This plugin requires Dynatrace Active Gate

## Features
* Check TLS connection to specified certificate's address
    * Send error event if destination is not reachable or there is TLS protocol error
* Check certificate's expiration date
    * Send two events before expiration
    * Send error event when certicate is expired

## Extension  deployment
Extension is distributed as file
* custom.remote.python.certcheck.zip

Deployment process
1. Import extension into Dynatrace server. Import file `custom.remote.python.certcheck.zip` by pressing button in Dyntarce GUI: `Settings->Monitoring->Monitoring technologies->Custom extensions->Upload extension`
1. Click on `SSL/TLS Certificates Check ActiveGate Extension (version x.y)` and press button `Add new endpoint`
1. Deploy extension zip file to ActiveGate server. 
    * For Linux server unzip file into /opt/dynatrace/remotepluginmodule/plugin_deployment
    * For MS Windows server unzip file into C:\Program Files\dynatrace\remotepluginmodule\plugin_deployment
1. Check the logfile:
    * For Linux server: /var/lib/dynatrace/remotepluginmodule/log/remoteplugin/custom.remote.python.certcheck/CertCheckPluginRemote.log
    * For Windows server: c:\ProgramData\dynatrace\remotepluginmodule\log\remoteplugin\custom.remote.python.certcheck\CertCheckPluginRemote.log

## Extension  Configuration
* `Endpoint name` - Monitoring instance endpoint name
* `Poll Interval` - How often certificates should be checked in hours
* `First event` - Raise first warning event before expiration in Days
* `First Event Type` - The type of event to be sent for first warning event
* `Second event` - Raise second error event before expiration in Days
* `Second Event Type` - The type of Dynatrace event to be sent for second error event
* `Hosts` - Comma seperated list of the Host certificates to monitor eg. www.google.com,example.com:16311
* `Hosts file` - Path on ActiveGate to hosts file with certificates to check. Addresses are delimited by a newline
* `Send metrics` - Send metrics for each checked certificate:
    * Days to expiration
    * Expired certificate
* `Debug` - Enable debug logging
* `Choose ActiveGate` - Choose ActiveGate where will be extension running
