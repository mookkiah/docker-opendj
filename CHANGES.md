# Changelog

Here you can see an overview of changes between each release.

## Version 3.1.4_06

Released on April 9th, 2019.

* Fixed inconsistent oxTrustConfigGeneration value.

## Version 3.1.4_05

Released on April 4th, 2019.

* Added license info during container run.

## Version 3.1.4_04

Released on January 23rd, 2019.

* Fixed OpenDJ server installation where it was failed if `/opt/opendj/config` directory is not empty.
* Fixed upgrade process from OpenDJ 3.0.0 to 3.0.1 (if required).

## Version 3.1.4_03

Released on December 11th, 2018.

* Added patches to `java.properties` to disable endpoint identification.

## Version 3.1.4_02

Released on December 2nd, 2018.

* Removed Casa scripts from distribution.

## Version 3.1.4_01

Released on November 12th, 2018.

* Upgraded to Gluu Server 3.1.4.

## Version 3.1.3_07

Released on September 18th, 2018.

* Changed base image to use Alpine 3.8.1.

## Version 3.1.3_06

Released on September 12th, 2018.

* Added feature to connect to secure Consul (HTTPS).

## Version 3.1.3_05

Released on August 31st, 2018.

* Added Tini to handle signal forwarding and reaping zombie processes.

## Version 3.1.3_04

Released on August 3rd, 2018.

* Added feature to re-generate certificate with Subject Alt Name.

## Version 3.1.3_03

Released on July 24th, 2018.

* Added function to migrate `ldap_servers` to `ldap_peers` config automatically.

## Version 3.1.3_02

Released on July 19th, 2018.

* Added wrapper to manage config via Consul KV or Kubernetes configmap.
* Simplified config of LDAP peers discovery. Refer to `README.md` for details.

## Version 3.1.3_01

Released on June 6th, 2018.

* Upgraded to Gluu Server 3.1.3.

## Version 3.1.2_01

Released on June 6th, 2018.

* Upgraded to Gluu Server 3.1.2.
