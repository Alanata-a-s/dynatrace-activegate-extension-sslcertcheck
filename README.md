# SSL/TLS Certificates Check ActiveGate Extension

This extension checks the SSL/TLS certificate expiration time. It doesn't check certificate validity! The host:port specification for checked certificates is populated in extension's configuration or specified in hosts file specified in GUI.

# Requirements
This plugin is deployed on Dynatrace Active Gate

# Features
* Checks TLS connection to specified certificate's address
    * Send error event if destination is not reachable or there is TLS protocol error
* Creates Custom device group for each extension's end point to group certificates
* Creates Custom device for each checked certificate and populates certificate's attributes as Custom device properties
* Checks certificate's expiration date
    * Sends two events before expiration
    * Sends error event when certicate is expired

# Installation

1. Download the release zip file from the [releases](releases) page named custom.remote.python.certcheck.zip.
1. Upload the zip file `custom.remote.python.certcheck.zip` to your Dynatrace tenant by pressing button in Dyntarce GUI: `Settings->Monitoring->Monitoring technologies->Custom extensions->Upload extension`
1. Unzip the extension zip file on ActiveGate server: 
    * For Linux server unzip file into /opt/dynatrace/remotepluginmodule/plugin_deployment
    * For MS Windows server unzip file into C:\Program Files\dynatrace\remotepluginmodule\plugin_deployment
1. Click on `Settings->Monitoring->Monitoring technologies->Custom extensions->SSL/TLS Certificates Check ActiveGate Extension (version x.y)` and press button `Add new endpoint`

# Troubleshooting

Check the logfile:
* For Linux server: /var/lib/dynatrace/remotepluginmodule/log/remoteplugin/custom.remote.python.certcheck/CertCheckPluginRemote.log
* For Windows server: c:\ProgramData\dynatrace\remotepluginmodule\log\remoteplugin\custom.remote.python.certcheck\CertCheckPluginRemote.log

# Configuration
| Setting | Description | Default value | 
| ------- | ----------- | --------------| 
| Endpoint name | Monitoring instance endpoint name | |
| Poll Interval (hours) | How often certificates should be checked in hours | 12 |
| First event (days) | Raise first warning event before expiration in Days | 20 |
| First Event Type | The type of event to be sent for first warning event | Resource |
| Second event (days) | Raise second error event before expiration in Days | 5 |
| Second Event Type | The type of Dynatrace event to be sent for second error event | Error |
| Hosts | Comma seperated list of the Host certificates to monitor eg. www.google.com,example.com:16311 | |
| Hosts file | Path on ActiveGate to hosts file with certificates to check. Addresses are delimited by a newline | |
| Send metrics | Send metrics for each checked certificate: `Days to expiration`, `Expired certificate` | Yes |
| Debug | Enable debug logging | No |
| Choose ActiveGate | Choose ActiveGate where will be extension running | |

# Limitations
* Extension doesn't check certificate validity!