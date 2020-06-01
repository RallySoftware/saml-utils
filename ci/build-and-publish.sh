#!/bin/bash -e

# get next build number
NEXT_BUILD_NUMBER=$(curl http://repo-depot.f4tech.com/artifactory/rally-maven/com/rallydev/saml-utils-jar/maven-metadata.xml | sed -n 's:.*<release>\(.*\)</release>.*:\1:p')
let NEXT_BUILD_NUMBER+=1
echo NEXT_BUILD_NUMBER=${NEXT_BUILD_NUMBER}
echo "version=${NEXT_BUILD_NUMBER}" > saml_utils_version.prop

version=0.1.527

# build and publish jar
echo gw clean
gw clean
echo BUILD_NUMBER=${NEXT_BUILD_NUMBER} gw shadowJar
BUILD_NUMBER=${NEXT_BUILD_NUMBER} gw shadowJar
echo BUILD_NUMBER=${NEXT_BUILD_NUMBER} gw publishSAMLJarPublicationToMavenRepository
BUILD_NUMBER=${NEXT_BUILD_NUMBER} gw publishSAMLJarPublicationToMavenRepository
echo DONE

sleep 900

