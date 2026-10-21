module com.sshteam.lib {
	requires com.nimbusds.jose.jwt;
	requires java.net.http;
	requires com.fasterxml.jackson.databind;
	requires com.sshtools.synergy.client;
	requires static jdk.httpserver;
	exports com.sshteam.lib;
}
