/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.amazonaws.serverless.proxy.internal.jaxrs;

import com.amazonaws.serverless.proxy.model.*;
import com.amazonaws.services.lambda.runtime.Context;

import javax.ws.rs.core.SecurityContext;

import java.security.Principal;

import static com.amazonaws.serverless.proxy.model.AwsProxyRequest.RequestSource.API_GATEWAY;


/**
 * default implementation of the <code>SecurityContext</code> object. This class supports 3 API Gateway's authorization methods:
 * AWS_IAM, CUSTOM_AUTHORIZER, and COGNITO_USER_POOL (oidc). The Principal returned by the object depends on the authorization
 * model:
 *  * AWS_IAM: User ARN
 *  * CUSTOM_AUTHORIZER: Custom user principal
 *  * COGNITO_USER_POOL: Cognito identity id
 */
public class AwsProxySecurityContext
        implements SecurityContext {

    //-------------------------------------------------------------
    // Constants - Package
    //-------------------------------------------------------------

    static final String AUTH_SCHEME_CUSTOM = "CUSTOM_AUTHORIZER";
    static final String AUTH_SCHEME_COGNITO_POOL = "COGNITO_USER_POOL";
    static final String AUTH_SCHEME_AWS_IAM = "AWS_IAM";

    static final String ALB_ACESS_TOKEN_HEADER = "x-amzn-oidc-accesstoken";
    static final String ALB_IDENTITY_HEADER = "x-amzn-oidc-identity";


    //-------------------------------------------------------------
    // Variables - Private
    //-------------------------------------------------------------

    private Context lambdaContext;
    private AwsProxyRequest event;


    public Context getLambdaContext() {
        return lambdaContext;
    }


    public AwsProxyRequest getEvent() {
        return event;
    }

    //-------------------------------------------------------------
    // Constructors
    //-------------------------------------------------------------

    public AwsProxySecurityContext(final Context lambdaContext, final AwsProxyRequest event) {
        this.lambdaContext = lambdaContext;
        this.event = event;
    }


    //-------------------------------------------------------------
    // Implementation - SecurityContext
    //-------------------------------------------------------------

    @Override
    public Principal getUserPrincipal() {
        final String authenticationScheme = getAuthenticationScheme();
        if (authenticationScheme == null) {
            return () -> null;
        }

        if (authenticationScheme.equals(AUTH_SCHEME_CUSTOM) || authenticationScheme.equals(AUTH_SCHEME_AWS_IAM)) {
            return () -> {
                switch (authenticationScheme) {
                    case AUTH_SCHEME_CUSTOM:
                        switch (event.getRequestSource()) {
                            case API_GATEWAY:
                                return event.getRequestContext().getAuthorizer().getPrincipalId();
                            case ALB:
                                return event.getMultiValueHeaders().getFirst(ALB_IDENTITY_HEADER);
                        }
                    case AUTH_SCHEME_AWS_IAM:
                        final ApiGatewayRequestIdentity identity = event.getRequestContext().getIdentity();
                        // if we received credentials from Cognito Federated Identities then we return the identity id
                        if (identity.getCognitoIdentityId() != null) {
                            return identity.getCognitoIdentityId();
                        } else { // otherwise the user arn from the credentials
                            return identity.getUserArn();
                        }
                }

                // return null if we couldn't find a valid scheme
                return null;
            };
        }

        if (authenticationScheme.equals(AUTH_SCHEME_COGNITO_POOL)) {
            return new CognitoUserPoolPrincipal(event.getRequestContext().getAuthorizer().getClaims());
        }

        throw new RuntimeException("Cannot recognize authorization scheme in event");
    }


    @Override
    public boolean isUserInRole(String role) {
        return role != null && role.equals(event.getRequestContext().getIdentity().getUserArn());
    }


    @Override
    public boolean isSecure() {
        return getAuthenticationScheme() != null;
    }


    @Override
    public String getAuthenticationScheme() {
        switch (event.getRequestSource()) {
        case API_GATEWAY:
            final AwsProxyRequestContext requestContext = event.getRequestContext();
            final ApiGatewayAuthorizerContext authorizer = requestContext.getAuthorizer();
            final ApiGatewayRequestIdentity identity = requestContext.getIdentity();
            if (authorizer != null && authorizer.getClaims() != null && authorizer.getClaims().getSubject() != null) {
                return AUTH_SCHEME_COGNITO_POOL;
            } else if (authorizer != null) {
                return AUTH_SCHEME_CUSTOM;
            } else if (identity != null && identity.getAccessKey() != null) {
                return AUTH_SCHEME_AWS_IAM;
            }
            break;
        case ALB:
            if (event.getMultiValueHeaders().containsKey(ALB_ACESS_TOKEN_HEADER)) {
                return AUTH_SCHEME_CUSTOM;
            }
            break;
        }
        return null;
    }


    /**
     * Custom object for request authorized with a Cognito User Pool authorizer. By casting the Principal
     * object to this you can extract the Claims object included in the token.
     */
    public static class CognitoUserPoolPrincipal implements Principal {

        private CognitoAuthorizerClaims claims;

        CognitoUserPoolPrincipal(CognitoAuthorizerClaims c) {
            claims = c;
        }

        @Override
        public String getName() {
            return claims.getSubject();
        }

        public CognitoAuthorizerClaims getClaims() {
            return claims;
        }
    }
}
