package com.dayang.oauth2.authorizationserver;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;

/**
 * Created by Administrator on 2017/11/17.
 */
public class MyUserApprovalHandler extends ApprovalStoreUserApprovalHandler {

    private boolean useApprovalStore = true;

    private ClientDetailsService clientDetailsService;
    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
        super.setClientDetailsService(clientDetailsService);
    }

    public void setUseApprovalStore(boolean useApprovalStore) {
        this.useApprovalStore = useApprovalStore;
    }

    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
                                                    Authentication userAuthentication) {
        //we always return true for approval
        authorizationRequest.setApproved(true);
        return authorizationRequest;
    }
}
