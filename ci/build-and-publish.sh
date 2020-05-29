#!/bin/bash -e

# get next build number
NEXT_BUILD_NUMBER=$(curl http://repo-depot.f4tech.com/artifactory/rally-maven/com/rallydev/saml-utils-jar/maven-metadata.xml | sed -n 's:.*<release>\(.*\)</release>.*:\1:p')
let NEXT_BUILD_NUMBER+=1
echo "NEXT_BUILD_NUMBER=${NEXT_BUILD_NUMBER}"

# build and publish jar
gw clean
BUILD_NUMBER=${NEXT_BUILD_NUMBER} gw shadowJar
BUILD_NUMBER=${NEXT_BUILD_NUMBER} gw publishSAMLJarPublicationToMavenRepository
