#!/bin/bash -e

# get next build number
BUILD_NUMBER=$(curl http://repo-depot.f4tech.com/artifactory/rally-maven/com/rallydev/saml-utils-jar/maven-metadata.xml | sed -n 's:.*<latest>\(.*\)</latest>.*:\1:p')
let BUILD_NUMBER+=1

# build and publish jar
gw clean
BUILD_NUMBER=testci gw shadowJar
BUILD_NUMBER=testci gw publishSAMLJarPublicationToMavenRepository
