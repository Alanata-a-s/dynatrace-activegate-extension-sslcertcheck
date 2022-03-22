from ruxit.api.base_plugin import RemoteBasePlugin
import logging
from  datetime import datetime, timezone, timedelta
import time
import ssl
import socket
# import asn1crypto
import asn1crypto.x509
import os

logger = logging.getLogger(__name__)
# Dynatrace custom device metadata length
CD_PROPERTIES_VALUE_MAX = 199
CD_PROPERTIES_KEY_MAX = 99
API_EVENTS_MAX_ENTITIES = 200

LOCAL_TIMEZONE = datetime.now(timezone.utc).astimezone().tzinfo

class SSLCheckResult:
    def __init__(self, device, certificate, error:str=None):
        self.device = device
        self.certificate = certificate
        self.error = error
        self.discoverEvent = time.time()     


class CertCheckPluginRemote(RemoteBasePlugin):
    def initialize(self, **kwargs):
        """
        Plugin initialization
        """
        config = kwargs['config']
        logger.info(f"Config: {config}")
        self.path = os.getcwd()
        self.poll_interval = config["poll_interval"]
        self.event_warning = config["event_warning"]
        self.event_warning_type = config["event_warning_type"]
        self.event_error = config["event_error"]
        self.event_error_type = config["event_error_type"]
        self.hosts = config["hosts"].split(",")
        self.hosts_file = config["hosts_file"]
        self.metrics = config["metrics"]
        self.debug = config["debug"]

        self.last_check = 0
        self.first_run = True
        # self.device_group_name = "SSL/TLS Expiration Group"
        # self.device_group_identifier = "CertCheckGroup"
        self.device_group_name = f"{self.activation.endpoint_name}"
        self.device_group_identifier = f"{self.activation.endpoint_name}"
        self.sslinfo = {}
        self.binding_to_device = {}

    def create_custom_devices(self, device_group):
        """
        Creates custom devices from hosts in self.hosts and self.hosts_file
        :param device_group: device group where devices will be created
        :return: dictionary for mapping binding->device
        """
        binding_to_device = {}
        # read input list from config gui
        for host_port in self.hosts:
            logger.debug(f"Reading cert address from config: '{host_port}'")
            host = host_port.split(":")
            c_host = host[0].strip()
            c_port = 443
            if len(host) == 2:
                c_port = int(host[1].strip())
            device = device_group.create_device(identifier=f"{c_host}:{c_port}", display_name=f"{c_host}:{c_port}")
            binding_to_device[(c_host,c_port)] = device
        
        # read input list from file
        if self.hosts_file:
            try:
                with open(self.hosts_file) as file:
                    for line in file:
                        logger.debug(f"Reading cert address from file: '{line.rstrip()}'")
                        host = line.rstrip().split(":")
                        c_host = host[0]
                        c_port = 443
                        if len(host) == 2:
                            c_port = int(host[1])
                        device = device_group.create_device(identifier=f"{c_host}:{c_port}", display_name=f"{c_host}:{c_port}")
                        binding_to_device[(c_host,c_port)] = device
            except Exception as e:
                logger.error(f"Error opening file with cert destinations: {str(e)}")
        return binding_to_device

    def get_remote_certs(self):
        """
        Checks all specified certificate bindings and 
        populates global dictionary "sslinfo" mapping binding->SSLCheckResul()
        """
        for binding in self.binding_to_device:
            logger.debug(f"Checking {binding}")
            try:
                context = ssl.create_default_context()
                # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection(binding, 3) as sock:
                    with context.wrap_socket(sock, server_hostname=binding[0]) as ssl_sock:
                        # ssl_sock.settimeout(4)
                        # print(ssl_sock.version())
                        remote_cert=asn1crypto.x509.Certificate.load(ssl_sock.getpeercert(True))        
                        self.sslinfo[binding] = SSLCheckResult(device=self.binding_to_device[binding], certificate=remote_cert['tbs_certificate'])
            except Exception as e:
                self.sslinfo[binding] = SSLCheckResult(device=self.binding_to_device[binding], certificate=None, error=str(e))
                logger.warn(f"Error event sent: certificate {binding} not reachable, error: {str(e)}")
                self.binding_to_device[binding].report_error_event(
                    description=f"Certificate {binding} error {str(e)}", 
                    title="Certificate not reachable", 
                    properties=dict())    
                self.binding_to_device[binding].report_property("Error", str(e)[:CD_PROPERTIES_VALUE_MAX])        
            logger.debug(f"Finished checking {binding}")            
        


    def device_properties(self, device, certificate:asn1crypto.x509.TbsCertificate, hostPort:str=None):
        """
        Sets properties info from certificate for custom device representing certificate 
        :param device: Dynatrace device object representing certificate
        :param certificate: retreived certificate for hostPort
        :param hostPort: host:port string from certificate was retreived
        :return properties: returns properties dictionary
        """
        properties = {}
        for cert_prop in ["Subject", "Issuer", "Validity"]:
            for k,v in certificate[cert_prop.lower()].native.items():
                if isinstance(v, datetime):
                    key = f"{cert_prop} {k}"[:CD_PROPERTIES_KEY_MAX]
                    # if we want value in localtime not GMT
                    # val = v.astimezone(LOCAL_TIMEZONE).isoformat()[:CD_PROPERTIES_VALUE_MAX]
                    val = v.isoformat()
                    logger.debug(f"Adding cert properties for custom device: {key}:{val}")
                    properties[key]=val
                    device.report_property(key, val)
                elif isinstance(v, list):
                    key = f"{cert_prop} {k}"[:CD_PROPERTIES_KEY_MAX]
                    val = ','.join(v)[:CD_PROPERTIES_VALUE_MAX]
                    logger.debug(f"Adding cert properties for custom device: {key}:{val}")
                    properties[key]=val                    
                    device.report_property(key, val)
                else:
                    key = f"{cert_prop} {k}"[:CD_PROPERTIES_KEY_MAX]
                    val = v[:CD_PROPERTIES_VALUE_MAX]
                    properties[key]=val
                    logger.debug(f"Adding cert properties for custom device: {key}:{val}")
                    device.report_property(key, val)
        if hostPort:
            logger.debug(f"Adding cert properties for custom device: Certificate found at:{hostPort}")
            device.report_property("Certificate found at", hostPort[:CD_PROPERTIES_VALUE_MAX])
        return properties
    
    def send_event(self, device, severity, title, description, properties):
        """
        Sends event for device from parameters
        :param device: custom device object
        :param severity: severity string, one from ["Availability", "Error", "Slowdown", "Resource", "Custom Info", "Suppress"]
        :param title: event's title string
        :param description: event's description string
        :param properties: event's properties dictionary
        """
        if severity == "Suppress":
            return
        elif severity == "Availability":
            device.report_availability_event(title=title, description=description, properties=properties)
        elif severity == "Error":
            device.report_error_event(title=title, description=description, properties=properties)
        elif severity == "Slowdown":
            device.report_performance_event(title=title, description=description, properties=properties)
        elif severity == "Resource":
            device.report_resource_contention_event(title=title, description=description, properties=properties)
        elif severity == "Custom Info":
            device.report_custom_info_event(title=title, description=description, properties=properties)

    def check_certs_and_report(self):
        """
        Checks certs validity and sends event about expiration due on device
        Sends metrics for cert on device
        """
        for binding in self.sslinfo:
            check_result = self.sslinfo[binding]
            cert = check_result.certificate
            device = check_result.device

            if check_result.error:
                device.report_property("Error", check_result.error[:CD_PROPERTIES_VALUE_MAX])
                device.report_error_event(
                    description=f"Certificate {binding} error {check_result.error}", 
                    title="Certificate not reachable", 
                    properties=dict())
                continue

            host = binding[0]
            port = binding[1]
            hps = f"{host}:{port}"
            logger.debug("Certificate result {hps} subject CN {sub} notvalidbefore {nvb} novalidafter {nva}".format(hps=hps,
                sub=cert['subject'].native['common_name'],
                nvb=cert['validity']['not_before'].native,
                nva=cert['validity']['not_after'].native))
            
            # set device properties
            properties = self.device_properties(device, cert, hps)

            if (cert['validity']['not_after'].native < datetime.now(timezone.utc)):
                # cert expired, sending error event
                logger.debug("Error event sent: certificate expired")
                self.send_event(
                    device=device,
                    severity=self.config['event_error_type'],
                    # description="Certificate expired on {expiring}".format(expiring=cert['validity']['not_after'].native), 
                    description="Certificate expired on {expiring}".format(expiring=cert['validity']['not_after'].native.astimezone(LOCAL_TIMEZONE).isoformat()), 
                    title="Certificate expired", 
                    properties=properties)
            elif (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['event_error'])):
                # sending error event
                logger.debug("Error event sent: event_error threshold crossed")
                self.send_event(
                    device=device,
                    severity=self.config['event_error_type'],
                    description=f"Certificate expiring in less than {self.config['event_error']} days", 
                    title="Certificate due to expire", 
                    properties=properties)
            elif (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['event_warning'])):
                # sending warning event
                logger.debug("Warning event sent: event_warning threshold crossed")
                self.send_event(
                    device=device,
                    severity=self.config['event_warning_type'],
                    description=f"Certificate expiring in less than {self.config['event_warning']} days", 
                    title="Certificate due to expire", 
                    properties=properties)

            # send metrics if enabled
            if self.config["metrics"]:
                if cert['validity']['not_after'].native < datetime.now(timezone.utc):
                    expired = 1 
                    days_to_expire = 0
                    device.absolute(key="expired", value=expired)
                    device.absolute(key="days_to_expire", value=days_to_expire)
                    logger.debug(f"Metrics: expired={expired} days_to_expire={days_to_expire}")
                else:
                    expired = 0 
                    # returns timedelta object not int
                    days_to_expire = cert['validity']['not_after'].native - datetime.now(timezone.utc)
                    device.absolute(key="days_to_expire", value=days_to_expire.days)
                    logger.debug(f"Metrics: expired={expired} days_to_expire={days_to_expire.days}")

                 

    def query(self, **kwargs):    
        """    
        Plugin main function
        """
        startTime = time.time()

        # Initializes DEBUG logging in first run or when debug setting is true
        if self.config['debug'] or self.first_run:
            logger.setLevel(logging.DEBUG)
            self.first_run = False
        else:
            logger.info(f"Setting log level to WARNING (Debug is {self.config['debug']})")
            logger.setLevel(logging.WARNING)

        device_group = self.topology_builder.create_group(identifier=self.device_group_identifier,
                                                    group_name=self.device_group_name)

        self.binding_to_device = self.create_custom_devices(device_group)

       # hours *3600
        if (self.last_check + self.config['poll_interval']*3600 < time.time()):            
            # for all keys from self.binding_to_device to self.sslinfo
            self.get_remote_certs()
            self.last_check = time.time()
        else:
            logger.debug("Not downloading certificates, next refresh in %s hours", int((self.last_check + self.config['poll_interval']*3600 - time.time()))/3600)

        self.check_certs_and_report()

        logger.info("Finished query execution in %s seconds for %d certificates", round(time.time() - startTime, 2), len(self.binding_to_device))

    