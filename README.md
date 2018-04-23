# ISEUntangled
Implementing Several ISE API calls to facilitate automation and quick on-boarding with a Cisco Partner focus.

Cisco Systems' Identity Services Engine (ISE) is a Network Policy Server with an amazing set of features.  These features allow customers to make their entire network - not a singular edge device - the enforcement point for Security Policy.

With ISE, a users connectivity and level of access is reliant on the entire context of the connection.  Specifically:
  - Who - Who is the user that is trying to connect - based on Active Directory or Local username or user group.
  - What - What kind of device is the user leveraging to gain access to the network?  Is it an iPhone, Android, Macbook, Windows, PC, IP Phone, Printer, dum terminal, etc.
  - When - What time of day is this access being requested?
  - Where - Where is the user coming from?  This can be based on Geo-location services and/or a "logical" location as assigned to the Network Access Device.  For instance, a country, state, city, building, floor, or other subsection.
  - How - Is the user accessing the network via a wired, wireless, or remote access VPN connection?
  
By having this contextual information, ISE can provide a level of security that is specific to the user accessing the network.  This can help to enforce compliance regulations and implement a least-privilege model.

Also, by having ISE in place, all security policy can be centrally managed.  Every Access Layer port can ultimately have the exact same configuration - an 802.1x policy.  As the connecting endpoint authenticates to the port, the appropriate level of network policy can be deployed to the port - ie a specific VLAN, Scalable Group Tag, ACL, etc.

As many of these features can be perceived as complex by our customers, many of Cisco's partners offer services to assist with the installation of ISE.  In order to automate this process - thereby shortening installation times and/or allowing sharing of common templates across multiple customers - Cisco ISE API's can be leveraged.  This code repository helps those who are just beginning that journey.

Some key features of this repository:
  - UnpluggedDemo.py - This python module is the main module of this code repository.  It provides a command-line driven menu system that can impact policy and databases on ISE.
  - ise_mgmt_config.py - This python module is the central location of the API and global variable definitions.  The ERS APIs can be found via https://<ISE_IP>:9060/ers/sdk.  The other APIs can be found via the ISE Administration guide for your version.
  - base_api_calls.py - This python module includes basic HTTP Create Read Update and Delete (CRUD) function calls/APIs.  These calls help to simplify the requisite 'requests' module calls.

This code repository is a labor of love - with no warranty or guarantee as to the code worthiness, readability, or general functionality being stated nor implied.  Ultimately - use at your own risk!
