package com.sshteam.lib;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class InMemoryDeviceStore implements DeviceStore {

    private final Map<String, DeviceCredentials> credentialsByServer = new LinkedHashMap<>();
    private final Map<String, String> dpopPrivateKeyByServer = new LinkedHashMap<>();
    private String defaultServer;

    @Override
    public void initServer(String serverUrl) throws IOException {
        // No-op for in-memory storage.
    }

    @Override
    public void saveCredentials(DeviceCredentials credentials) throws Exception {
        credentialsByServer.put(credentials.serverUrl(), credentials);
    }

    @Override
    public Optional<DeviceCredentials> loadCredentials(String serverUrl) throws Exception {
        return Optional.ofNullable(credentialsByServer.get(serverUrl));
    }

    @Override
    public void saveDpopPrivateKey(String serverUrl, String privateKeyJwk) throws Exception {
        dpopPrivateKeyByServer.put(serverUrl, privateKeyJwk);
    }

    @Override
    public String loadDpopPrivateKey(String serverUrl) throws Exception {
        String key = dpopPrivateKeyByServer.get(serverUrl);
        if (key == null) {
            throw new IllegalStateException("DPoP key not found for " + serverUrl);
        }
        return key;
    }

    @Override
    public void setDefaultServer(String serverUrl) throws IOException {
        defaultServer = serverUrl;
    }

    @Override
    public Optional<String> getDefaultServer() throws IOException {
        return Optional.ofNullable(defaultServer);
    }

    @Override
    public List<String> listServers() throws IOException {
        return new ArrayList<>(credentialsByServer.keySet());
    }
}
