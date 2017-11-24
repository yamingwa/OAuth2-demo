package com.dayang.oauth2.server;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

/**
 * Created by Administrator on 2017/11/24.
 */
@Component
public class TenantManagementService {
    private Map<String, Set<String>> tenantServiceMap;
    private Map<String, Set<String>> userTenantMap;

    public TenantManagementService() {
        init();
    }
    public void init() {
        //Add tenant service map
        this.tenantServiceMap = new Hashtable<String, Set<String>>();
        this.tenantServiceMap.put("tenant1", createSet("serviceID1", "serviceID3"));
        this.tenantServiceMap.put("tenant2", createSet("serviceID2", "serviceID3"));

        //Add user tenant map
        this.userTenantMap = new Hashtable<String, Set<String>>();
        this.userTenantMap.put("user1", createSet("tenant1"));
        this.userTenantMap.put("user2", createSet("tenant2"));
        this.userTenantMap.put("user3", createSet("tenant1", "tenant2"));
    }

    public Map<String, Set<String>> getTenantServiceMap() {
        return this.tenantServiceMap;
    }

    public Map<String, Set<String>> getUserTenantMap() {
        return this.userTenantMap;
    }

    private Set<String> createSet(String... services) {
        Set<String> serviceSet = new HashSet<String>();
        for (String service : services) {
            serviceSet.add(service);
        }
        return serviceSet;
    }
}
