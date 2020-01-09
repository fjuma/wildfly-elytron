---
layout: getting-started-for-developers
title: Getting Started For Developers
permalink: /getting-started-for-developers/
---
<div class="grid__item width-12-12 width-12-12-m" markdown="1">
<h2>Getting Started for Developers</h2>

* TOC
{:toc}
### A Quick Introduction to the Projects

#### WildFly Elytron
 
WildFly Elytron is the main project that contains the security APIs, SPIs, and implementations of various
components that are used across the WildFly application server. Although Elytron was developed for WildFly,
it is possible to use Elytron outside of WildFly.

[Git Repository](https://github.com/wildfly-security/wildfly-elytron)
<br/>
[Issue Tracker](https://issues.redhat.com/projects/ELY)
<br/>
[JavaDoc]({{site.baseurl}}/javadoc)
 
#### WildFly Core
 
This is the core of the WildFly application server and the initial place where we integrate Elytron with WildFly.

[Git Repository](https://github.com/wildfly/wildfly-core)
<br/>
[Issue Tracker](https://issues.redhat.com/projects/WFCORE)

#### WildFly
 
This is the main application server project. Integration related to Elytron can also be found here.

[Git Repository](https://github.com/wildfly/wildfly)
<br/>
[Issue Tracker](https://issues.redhat.com/projects/WFLY)

#### WildFly Proposals
 
When starting on a new Elytron feature, we prepare an analysis document and submit a PR against the WildFly
Proposals repository to get feedback on the new feature.

[Git Repository](https://github.com/wildfly/wildfly-proposals)

### Getting Familiar with Elytron

For an introduction to Elytron, take a look at this [presentation](https://sector.ca/sessions/elytron-next-generation-security-for-java-servers/)
which also includes a few demos.

Another great way to learn more about Elytron is to take a look at our [blog
posts]({{site.baseurl}}/blog) on various Elytron features.

If you'd like to get started with some example applications that you can easily deploy to WildFly,
take a look at some of our [quickstart applications](https://github.com/wildfly/quickstart).
Search for the ones that mention "Elytron". You'll also want to check out our [additional examples](https://github.com/wildfly-security-incubator/elytron-examples)
that demonstrate specific Elytron features.

### Getting Help

Questions on Elytron are always welcome in WildFly's [user forums](https://developer.jboss.org/community/wildfly?view=discussions).

### Getting Your Developer Environment Set Up

You will need:

* JDK 11
* Git
* Maven 3.3.9 or later
* An [IDE](https://en.wikipedia.org/wiki/Comparison_of_integrated_development_environments#Java)
(e.g., [IntelliJ IDEA](https://www.jetbrains.com/idea/download/), [Eclipse](https://www.eclipse.org/downloads/), etc.)

Fork [wildfly-elytron](https://github.com/wildfly-security/wildfly-elytron), [wildfly-core](https://github.com/wildfly/wildfly-core),
and [wildfly](https://github.com/wildfly/wildfly) to your GitHub account and clone your newly forked repositories into
your local workspace. Then, for each repository, add a remote ref to upstream, for pulling future updates.
For example:

```
git remote add upstream https://github.com/wildfly-security/wildfly-elytron
```

To build `wildfly-elytron`, `wildfly-core`, or `wildfly`, `cd` to the appropriate directory and then run:

```
mvn clean install
```

To skip the tests, use:

```
mvn clean install -DskipTests=true
```

To run only a specific test, use:

```
mvn clean install -Dtest=TestClassName 
```

If you have made a change in Elytron and need to test out the change in WildFly, the following steps
can be used to build a version of WildFly that incorporates your Elytron changes:

1. Build `wildfly-elytron`
2. Update the `version.org.wildfly.security.elytron` property in the `wildfly-core/pom.xml` file to
reference your locally built `wildfly-elytron` `SNAPSHOT` version
3. Build `wildfly-core`
4. Update the `version.org.wildfly.core` property in the `wildfly/pom.xml` file to reference your locally
built `wildfly-core` `SNAPSHOT` version
5. Build `wildfly` 

### Running the Test Suites

Before submitting a PR, it is important to make sure the appropriate test suites pass with your changes.

For `wildfly-elytron`, all tests will be run when executing `mvn clean install`.

For both `wildfly-core` and `wildfly`, the following command can be used to run the full test suite:

```
mvn clean install -DallTests -fae > alltests.txt
```  